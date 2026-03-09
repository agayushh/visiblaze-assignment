"use strict";

const { EC2Client, DescribeInstancesCommand } = require("@aws-sdk/client-ec2");

const REGION = process.env.AWS_REGION || "us-east-1";
const ec2 = new EC2Client({ region: REGION });

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json",
};

exports.handler = async (event) => {
  try {
    const command = new DescribeInstancesCommand({});
    const response = await ec2.send(command);

    const instances = [];

    (response.Reservations || []).forEach((reservation) => {
      (reservation.Instances || []).forEach((instance) => {
        instances.push({
          instanceId: instance.InstanceId,
          instanceType: instance.InstanceType,
          region: REGION,
          state: instance.State ? instance.State.Name : "unknown",
          publicIp: instance.PublicIpAddress || null,
          privateIp: instance.PrivateIpAddress || null,
          securityGroups: (instance.SecurityGroups || []).map((g) => ({
            groupId: g.GroupId,
            groupName: g.GroupName,
          })),
          launchTime: instance.LaunchTime || null,
          tags: (instance.Tags || []).reduce((acc, tag) => {
            acc[tag.Key] = tag.Value;
            return acc;
          }, {}),
        });
      });
    });

    return {
      statusCode: 200,
      headers: CORS_HEADERS,
      body: JSON.stringify({ count: instances.length, instances }),
    };
  } catch (error) {
    console.error("discoverEC2 error:", error);
    return {
      statusCode: 500,
      headers: CORS_HEADERS,
      body: JSON.stringify({
        error: "Failed to fetch EC2 instances",
        message: error.message,
      }),
    };
  }
};

