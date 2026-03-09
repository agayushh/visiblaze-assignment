"use strict";

const {
  S3Client,
  ListBucketsCommand,
  GetBucketEncryptionCommand,
  GetPublicAccessBlockCommand,
} = require("@aws-sdk/client-s3");
const {
  IAMClient,
  ListVirtualMFADevicesCommand,
  GetAccountSummaryCommand,
  ListUsersCommand,
  ListAccessKeysCommand,
} = require("@aws-sdk/client-iam");
const {
  CloudTrailClient,
  DescribeTrailsCommand,
  GetTrailStatusCommand,
} = require("@aws-sdk/client-cloudtrail");
const {
  EC2Client,
  DescribeSecurityGroupsCommand,
} = require("@aws-sdk/client-ec2");
const { DynamoDBClient, PutItemCommand } = require("@aws-sdk/client-dynamodb");

const REGION = process.env.AWS_REGION || "us-east-1";
const TABLE_NAME = process.env.DYNAMODB_TABLE || "scan_results";

const s3 = new S3Client({ region: REGION });
const iam = new IAMClient({ region: REGION });
const cloudtrail = new CloudTrailClient({ region: REGION });
const ec2 = new EC2Client({ region: REGION });
const dynamo = new DynamoDBClient({ region: REGION });

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json",
};

function makeResult(checkName, resourceId, status, evidence) {
  return {
    checkName,
    status,
    affectedResource: resourceId,
    evidence,
    timestamp: new Date().toISOString(),
  };
}

async function storeResult(result) {
  const resourceKey = `${result.checkName}#${result.affectedResource}`;
  try {
    await dynamo.send(
      new PutItemCommand({
        TableName: TABLE_NAME,
        Item: {
          resource_id: { S: resourceKey },
          resource_type: { S: result.checkName.split("_")[0] || "UNKNOWN" },
          check_name: { S: result.checkName },
          status: { S: result.status },
          affected_resource: { S: result.affectedResource },
          evidence: { S: result.evidence },
          timestamp: { S: result.timestamp },
        },
      }),
    );
  } catch (e) {
    console.warn(`Failed to store result for ${resourceKey}: ${e.message}`);
  }
}

// CIS Check 1: S3 buckets should not be publicly accessible
async function checkS3PublicAccess(results) {
  try {
    const { Buckets } = await s3.send(new ListBucketsCommand({}));
    for (const bucket of Buckets || []) {
      try {
        const pabResp = await s3.send(
          new GetPublicAccessBlockCommand({ Bucket: bucket.Name }),
        );
        const cfg = pabResp.PublicAccessBlockConfiguration || {};
        const allBlocked =
          cfg.BlockPublicAcls &&
          cfg.BlockPublicPolicy &&
          cfg.IgnorePublicAcls &&
          cfg.RestrictPublicBuckets;

        results.push(
          makeResult(
            "S3_PUBLIC_ACCESS",
            bucket.Name,
            allBlocked ? "PASS" : "FAIL",
            allBlocked
              ? "All public access block settings are enabled."
              : `Public access block not fully enabled: ${JSON.stringify(cfg)}`,
          ),
        );
      } catch (e) {
        // No public access block config = vulnerable
        results.push(
          makeResult(
            "S3_PUBLIC_ACCESS",
            bucket.Name,
            "FAIL",
            `No public access block configuration found: ${e.message}`,
          ),
        );
      }
    }
  } catch (e) {
    console.error("checkS3PublicAccess error:", e.message);
  }
}

// CIS Check 2: S3 buckets must have server-side encryption enabled
async function checkS3Encryption(results) {
  try {
    const { Buckets } = await s3.send(new ListBucketsCommand({}));
    for (const bucket of Buckets || []) {
      try {
        const encResp = await s3.send(
          new GetBucketEncryptionCommand({ Bucket: bucket.Name }),
        );
        const rules = encResp.ServerSideEncryptionConfiguration?.Rules || [];
        const algo =
          rules[0]?.ApplyServerSideEncryptionByDefault?.SSEAlgorithm || null;
        results.push(
          makeResult(
            "S3_ENCRYPTION",
            bucket.Name,
            algo ? "PASS" : "FAIL",
            algo
              ? `Server-side encryption enabled with algorithm: ${algo}`
              : "No server-side encryption configured.",
          ),
        );
      } catch (e) {
        results.push(
          makeResult(
            "S3_ENCRYPTION",
            bucket.Name,
            "FAIL",
            `Encryption not configured: ${e.message}`,
          ),
        );
      }
    }
  } catch (e) {
    console.error("checkS3Encryption error:", e.message);
  }
}

// CIS Check 3: IAM root account must have MFA enabled
async function checkRootMFA(results) {
  try {
    const summaryResp = await iam.send(new GetAccountSummaryCommand({}));
    const summary = summaryResp.SummaryMap || {};
    const mfaEnabled = summary["AccountMFAEnabled"] === 1;
    results.push(
      makeResult(
        "IAM_ROOT_MFA",
        "root-account",
        mfaEnabled ? "PASS" : "FAIL",
        mfaEnabled
          ? "Root account has MFA enabled."
          : "Root account does NOT have MFA enabled. This is a critical security risk.",
      ),
    );
  } catch (e) {
    console.error("checkRootMFA error:", e.message);
    results.push(
      makeResult(
        "IAM_ROOT_MFA",
        "root-account",
        "FAIL",
        `Could not determine MFA status: ${e.message}`,
      ),
    );
  }
}

// CIS Check 4: CloudTrail must be enabled in the account
async function checkCloudTrail(results) {
  try {
    const trailsResp = await cloudtrail.send(
      new DescribeTrailsCommand({ includeShadowTrails: false }),
    );
    const trails = trailsResp.trailList || [];

    if (trails.length === 0) {
      results.push(
        makeResult(
          "CLOUDTRAIL_ENABLED",
          "account",
          "FAIL",
          "No CloudTrail trails configured in this account.",
        ),
      );
      return;
    }

    for (const trail of trails) {
      try {
        const statusResp = await cloudtrail.send(
          new GetTrailStatusCommand({ Name: trail.TrailARN }),
        );
        const isLogging = statusResp.IsLogging || false;
        results.push(
          makeResult(
            "CLOUDTRAIL_ENABLED",
            trail.Name || trail.TrailARN,
            isLogging ? "PASS" : "FAIL",
            isLogging
              ? `CloudTrail '${trail.Name}' is active and logging.`
              : `CloudTrail '${trail.Name}' exists but is NOT currently logging.`,
          ),
        );
      } catch (e) {
        results.push(
          makeResult(
            "CLOUDTRAIL_ENABLED",
            trail.Name || "unknown",
            "FAIL",
            `Could not determine logging status: ${e.message}`,
          ),
        );
      }
    }
  } catch (e) {
    console.error("checkCloudTrail error:", e.message);
    results.push(
      makeResult(
        "CLOUDTRAIL_ENABLED",
        "account",
        "FAIL",
        `Could not check CloudTrail: ${e.message}`,
      ),
    );
  }
}

// CIS Check 5: Security groups should not allow SSH (22) or RDP (3389) from 0.0.0.0/0
async function checkOpenSecurityGroups(results) {
  try {
    const sgResp = await ec2.send(new DescribeSecurityGroupsCommand({}));
    const groups = sgResp.SecurityGroups || [];

    for (const sg of groups) {
      const dangerousRules = [];

      for (const perm of sg.IpPermissions || []) {
        const fromPort = perm.FromPort;
        const toPort = perm.ToPort;
        const isSSH = fromPort <= 22 && toPort >= 22;
        const isRDP = fromPort <= 3389 && toPort >= 3389;
        const isAllPorts = fromPort === -1 && toPort === -1;

        if (isSSH || isRDP || isAllPorts) {
          for (const ipRange of perm.IpRanges || []) {
            if (ipRange.CidrIp === "0.0.0.0/0") {
              const portDesc = isAllPorts
                ? "All ports"
                : `${fromPort}-${toPort}`;
              dangerousRules.push(`Port ${portDesc} open to 0.0.0.0/0`);
            }
          }
          for (const ipv6Range of perm.Ipv6Ranges || []) {
            if (ipv6Range.CidrIpv6 === "::/0") {
              const portDesc = isAllPorts
                ? "All ports"
                : `${fromPort}-${toPort}`;
              dangerousRules.push(`Port ${portDesc} open to ::/0 (IPv6)`);
            }
          }
        }
      }

      const sgId = sg.GroupId;
      const sgName = sg.GroupName || sgId;
      if (dangerousRules.length > 0) {
        results.push(
          makeResult(
            "SG_OPEN_SSH_RDP",
            `${sgId} (${sgName})`,
            "FAIL",
            `Dangerous inbound rules found: ${dangerousRules.join("; ")}`,
          ),
        );
      } else {
        results.push(
          makeResult(
            "SG_OPEN_SSH_RDP",
            `${sgId} (${sgName})`,
            "PASS",
            "No unrestricted SSH or RDP access found.",
          ),
        );
      }
    }
  } catch (e) {
    console.error("checkOpenSecurityGroups error:", e.message);
    results.push(
      makeResult(
        "SG_OPEN_SSH_RDP",
        "security-groups",
        "FAIL",
        `Could not check security groups: ${e.message}`,
      ),
    );
  }
}

// CIS Check 6 (Bonus): IAM users should not have active access keys older than 90 days
async function checkIAMAccessKeyAge(results) {
  try {
    const usersResp = await iam.send(new ListUsersCommand({}));
    const users = usersResp.Users || [];

    for (const user of users) {
      const keysResp = await iam.send(
        new ListAccessKeysCommand({ UserName: user.UserName }),
      );
      for (const key of keysResp.AccessKeyMetadata || []) {
        if (key.Status !== "Active") continue;
        const created = new Date(key.CreateDate);
        const ageInDays = Math.floor(
          (Date.now() - created.getTime()) / (1000 * 60 * 60 * 24),
        );
        const isOld = ageInDays > 90;
        results.push(
          makeResult(
            "IAM_ACCESS_KEY_AGE",
            `${user.UserName} / ${key.AccessKeyId}`,
            isOld ? "FAIL" : "PASS",
            isOld
              ? `Active access key is ${ageInDays} days old (exceeds 90-day limit). Created: ${key.CreateDate}`
              : `Active access key is ${ageInDays} days old (within 90-day limit).`,
          ),
        );
      }
    }
  } catch (e) {
    console.error("checkIAMAccessKeyAge error:", e.message);
  }
}

exports.handler = async (event) => {
  const results = [];

  // Run all checks concurrently
  await Promise.all([
    checkS3PublicAccess(results),
    checkS3Encryption(results),
    checkRootMFA(results),
    checkCloudTrail(results),
    checkOpenSecurityGroups(results),
    checkIAMAccessKeyAge(results),
  ]);

  // Store all results in DynamoDB
  await Promise.all(results.map((r) => storeResult(r)));

  const passed = results.filter((r) => r.status === "PASS").length;
  const failed = results.filter((r) => r.status === "FAIL").length;

  return {
    statusCode: 200,
    headers: CORS_HEADERS,
    body: JSON.stringify({
      summary: { total: results.length, passed, failed },
      results,
    }),
  };
};
