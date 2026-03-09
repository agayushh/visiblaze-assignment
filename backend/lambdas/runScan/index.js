"use strict";

/**
 * runScan Lambda – orchestrates a full cloud posture scan.
 * It invokes the CIS checks logic directly (shared code pattern)
 * and also captures EC2 + S3 discovery summaries, storing everything
 * to DynamoDB before returning a combined result.
 */

const { EC2Client, DescribeInstancesCommand } = require("@aws-sdk/client-ec2");
const {
  S3Client,
  ListBucketsCommand,
  GetBucketEncryptionCommand,
  GetPublicAccessBlockCommand,
  GetBucketLocationCommand,
} = require("@aws-sdk/client-s3");
const { IAMClient, GetAccountSummaryCommand, ListUsersCommand, ListAccessKeysCommand } = require("@aws-sdk/client-iam");
const { CloudTrailClient, DescribeTrailsCommand, GetTrailStatusCommand } = require("@aws-sdk/client-cloudtrail");
const { EC2Client: EC2ClientSG, DescribeSecurityGroupsCommand } = require("@aws-sdk/client-ec2");
const { DynamoDBClient, PutItemCommand } = require("@aws-sdk/client-dynamodb");

const REGION = process.env.AWS_REGION || "us-east-1";
const TABLE_NAME = process.env.DYNAMODB_TABLE || "scan_results";

const ec2 = new EC2Client({ region: REGION });
const s3 = new S3Client({ region: REGION });
const iam = new IAMClient({ region: REGION });
const cloudtrail = new CloudTrailClient({ region: REGION });
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
      })
    );
  } catch (e) {
    console.warn(`Failed to store result: ${e.message}`);
  }
}

// ─── CIS Checks ──────────────────────────────────────────────────────────────

async function checkS3PublicAccess(results) {
  try {
    const { Buckets } = await s3.send(new ListBucketsCommand({}));
    for (const bucket of Buckets || []) {
      try {
        const resp = await s3.send(new GetPublicAccessBlockCommand({ Bucket: bucket.Name }));
        const cfg = resp.PublicAccessBlockConfiguration || {};
        const allBlocked = cfg.BlockPublicAcls && cfg.BlockPublicPolicy && cfg.IgnorePublicAcls && cfg.RestrictPublicBuckets;
        results.push(makeResult("S3_PUBLIC_ACCESS", bucket.Name, allBlocked ? "PASS" : "FAIL",
          allBlocked ? "All public access block settings enabled." : `Partial/no public access block: ${JSON.stringify(cfg)}`));
      } catch (e) {
        results.push(makeResult("S3_PUBLIC_ACCESS", bucket.Name, "FAIL", `No public access block config: ${e.message}`));
      }
    }
  } catch (e) { console.error("S3PublicAccess:", e.message); }
}

async function checkS3Encryption(results) {
  try {
    const { Buckets } = await s3.send(new ListBucketsCommand({}));
    for (const bucket of Buckets || []) {
      try {
        const resp = await s3.send(new GetBucketEncryptionCommand({ Bucket: bucket.Name }));
        const algo = resp.ServerSideEncryptionConfiguration?.Rules?.[0]?.ApplyServerSideEncryptionByDefault?.SSEAlgorithm;
        results.push(makeResult("S3_ENCRYPTION", bucket.Name, algo ? "PASS" : "FAIL",
          algo ? `Encryption enabled: ${algo}` : "No server-side encryption."));
      } catch (e) {
        results.push(makeResult("S3_ENCRYPTION", bucket.Name, "FAIL", `Encryption not configured: ${e.message}`));
      }
    }
  } catch (e) { console.error("S3Encryption:", e.message); }
}

async function checkRootMFA(results) {
  try {
    const resp = await iam.send(new GetAccountSummaryCommand({}));
    const mfaEnabled = (resp.SummaryMap || {})["AccountMFAEnabled"] === 1;
    results.push(makeResult("IAM_ROOT_MFA", "root-account", mfaEnabled ? "PASS" : "FAIL",
      mfaEnabled ? "Root MFA enabled." : "Root account MFA is NOT enabled – critical risk."));
  } catch (e) {
    results.push(makeResult("IAM_ROOT_MFA", "root-account", "FAIL", `Cannot determine MFA: ${e.message}`));
  }
}

async function checkCloudTrail(results) {
  try {
    const { trailList } = await cloudtrail.send(new DescribeTrailsCommand({ includeShadowTrails: false }));
    if (!trailList || trailList.length === 0) {
      results.push(makeResult("CLOUDTRAIL_ENABLED", "account", "FAIL", "No CloudTrail trails configured."));
      return;
    }
    for (const trail of trailList) {
      try {
        const st = await cloudtrail.send(new GetTrailStatusCommand({ Name: trail.TrailARN }));
        results.push(makeResult("CLOUDTRAIL_ENABLED", trail.Name, st.IsLogging ? "PASS" : "FAIL",
          st.IsLogging ? `Trail '${trail.Name}' is logging.` : `Trail '${trail.Name}' is NOT logging.`));
      } catch (e) {
        results.push(makeResult("CLOUDTRAIL_ENABLED", trail.Name || "unknown", "FAIL", `Status check failed: ${e.message}`));
      }
    }
  } catch (e) {
    results.push(makeResult("CLOUDTRAIL_ENABLED", "account", "FAIL", `CloudTrail check failed: ${e.message}`));
  }
}

async function checkOpenSGs(results) {
  try {
    const { SecurityGroups } = await ec2.send(new DescribeSecurityGroupsCommand({}));
    for (const sg of SecurityGroups || []) {
      const dangerous = [];
      for (const perm of sg.IpPermissions || []) {
        const from = perm.FromPort, to = perm.ToPort;
        const isSSH = from <= 22 && to >= 22;
        const isRDP = from <= 3389 && to >= 3389;
        const isAll = from === -1 && to === -1;
        if (isSSH || isRDP || isAll) {
          for (const r of perm.IpRanges || []) {
            if (r.CidrIp === "0.0.0.0/0") dangerous.push(`Port ${isAll ? "All" : `${from}-${to}`} → 0.0.0.0/0`);
          }
          for (const r of perm.Ipv6Ranges || []) {
            if (r.CidrIpv6 === "::/0") dangerous.push(`Port ${isAll ? "All" : `${from}-${to}`} → ::/0`);
          }
        }
      }
      results.push(makeResult("SG_OPEN_SSH_RDP", `${sg.GroupId} (${sg.GroupName})`,
        dangerous.length ? "FAIL" : "PASS",
        dangerous.length ? `Dangerous rules: ${dangerous.join("; ")}` : "No unrestricted SSH/RDP."));
    }
  } catch (e) { console.error("OpenSGs:", e.message); }
}

async function checkIAMKeyAge(results) {
  try {
    const { Users } = await iam.send(new ListUsersCommand({}));
    for (const user of Users || []) {
      const { AccessKeyMetadata } = await iam.send(new ListAccessKeysCommand({ UserName: user.UserName }));
      for (const key of AccessKeyMetadata || []) {
        if (key.Status !== "Active") continue;
        const days = Math.floor((Date.now() - new Date(key.CreateDate)) / 86400000);
        results.push(makeResult("IAM_ACCESS_KEY_AGE", `${user.UserName}/${key.AccessKeyId}`,
          days > 90 ? "FAIL" : "PASS",
          days > 90 ? `Key is ${days} days old (>90 day limit).` : `Key is ${days} days old.`));
      }
    }
  } catch (e) { console.error("IAMKeyAge:", e.message); }
}

// ─── Main handler ─────────────────────────────────────────────────────────────

exports.handler = async (event) => {
  const scanStart = new Date().toISOString();
  const cisResults = [];

  // Run all CIS checks concurrently
  await Promise.all([
    checkS3PublicAccess(cisResults),
    checkS3Encryption(cisResults),
    checkRootMFA(cisResults),
    checkCloudTrail(cisResults),
    checkOpenSGs(cisResults),
    checkIAMKeyAge(cisResults),
  ]);

  // Store all results
  await Promise.all(cisResults.map(storeResult));

  const passed = cisResults.filter((r) => r.status === "PASS").length;
  const failed = cisResults.filter((r) => r.status === "FAIL").length;

  return {
    statusCode: 200,
    headers: CORS_HEADERS,
    body: JSON.stringify({
      scanStartedAt: scanStart,
      scanCompletedAt: new Date().toISOString(),
      summary: { total: cisResults.length, passed, failed },
      results: cisResults,
    }),
  };
};
