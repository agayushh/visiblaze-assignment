"use strict";

const {
  S3Client,
  ListBucketsCommand,
  GetBucketLocationCommand,
  GetBucketEncryptionCommand,
  GetPublicAccessBlockCommand,
  GetBucketPolicyStatusCommand,
} = require("@aws-sdk/client-s3");

const s3 = new S3Client({ region: process.env.AWS_REGION || "us-east-1" });

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json",
};

async function getBucketDetails(bucketName) {
  const result = {
    bucketName,
    region: "us-east-1",
    encryptionStatus: "NOT_ENABLED",
    isPublic: false,
    publicAccessBlockEnabled: false,
  };

  // Get region
  try {
    const locationResp = await s3.send(
      new GetBucketLocationCommand({ Bucket: bucketName })
    );
    result.region =
      locationResp.LocationConstraint || "us-east-1";
  } catch (e) {
    console.warn(`Could not get location for ${bucketName}: ${e.message}`);
  }

  // Get encryption status
  try {
    const encResp = await s3.send(
      new GetBucketEncryptionCommand({ Bucket: bucketName })
    );
    const rules =
      encResp.ServerSideEncryptionConfiguration?.Rules || [];
    if (rules.length > 0) {
      const algo =
        rules[0].ApplyServerSideEncryptionByDefault?.SSEAlgorithm || "ENABLED";
      result.encryptionStatus = algo;
    }
  } catch (e) {
    if (e.name !== "ServerSideEncryptionConfigurationNotFoundError") {
      console.warn(`Could not get encryption for ${bucketName}: ${e.message}`);
    }
  }

  // Get public access block config
  try {
    const pabResp = await s3.send(
      new GetPublicAccessBlockCommand({ Bucket: bucketName })
    );
    const cfg = pabResp.PublicAccessBlockConfiguration || {};
    result.publicAccessBlockEnabled =
      cfg.BlockPublicAcls &&
      cfg.BlockPublicPolicy &&
      cfg.IgnorePublicAcls &&
      cfg.RestrictPublicBuckets;
    result.publicAccessBlockConfig = cfg;
  } catch (e) {
    // No public access block = potentially public
    result.publicAccessBlockEnabled = false;
  }

  // Get bucket policy status
  try {
    const policyStatusResp = await s3.send(
      new GetBucketPolicyStatusCommand({ Bucket: bucketName })
    );
    result.isPublic =
      policyStatusResp.PolicyStatus?.IsPublic || false;
  } catch (e) {
    // No policy = not public via policy
    result.isPublic = false;
  }

  return result;
}

exports.handler = async (event) => {
  try {
    const listResp = await s3.send(new ListBucketsCommand({}));
    const buckets = listResp.Buckets || [];

    const bucketDetails = await Promise.all(
      buckets.map((b) => getBucketDetails(b.Name))
    );

    return {
      statusCode: 200,
      headers: CORS_HEADERS,
      body: JSON.stringify({ count: bucketDetails.length, buckets: bucketDetails }),
    };
  } catch (error) {
    console.error("discoverS3 error:", error);
    return {
      statusCode: 500,
      headers: CORS_HEADERS,
      body: JSON.stringify({
        error: "Failed to fetch S3 buckets",
        message: error.message,
      }),
    };
  }
};
