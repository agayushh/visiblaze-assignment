"use strict";

const { DynamoDBClient, ScanCommand } = require("@aws-sdk/client-dynamodb");

const REGION = process.env.AWS_REGION || "us-east-1";
const TABLE_NAME = process.env.DYNAMODB_TABLE || "scan_results";
const dynamo = new DynamoDBClient({ region: REGION });

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json",
};

function unmarshallItem(item) {
  return {
    resourceId: item.resource_id?.S || "",
    resourceType: item.resource_type?.S || "",
    checkName: item.check_name?.S || "",
    status: item.status?.S || "",
    affectedResource: item.affected_resource?.S || "",
    evidence: item.evidence?.S || "",
    timestamp: item.timestamp?.S || "",
  };
}

exports.handler = async (event) => {
  try {
    const queryParams = event.queryStringParameters || {};
    const checkName = queryParams.checkName;
    const status = queryParams.status;

    let filterExpression = undefined;
    let expressionAttributeValues = {};

    if (checkName && status) {
      filterExpression = "check_name = :cn AND #st = :st";
      expressionAttributeValues = {
        ":cn": { S: checkName },
        ":st": { S: status },
      };
    } else if (checkName) {
      filterExpression = "check_name = :cn";
      expressionAttributeValues = { ":cn": { S: checkName } };
    } else if (status) {
      filterExpression = "#st = :st";
      expressionAttributeValues = { ":st": { S: status } };
    }

    const scanParams = {
      TableName: TABLE_NAME,
    };

    if (filterExpression) {
      scanParams.FilterExpression = filterExpression;
      scanParams.ExpressionAttributeValues = expressionAttributeValues;
      // "status" is a reserved word in DynamoDB
      if (status) {
        scanParams.ExpressionAttributeNames = { "#st": "status" };
      }
    }

    const response = await dynamo.send(new ScanCommand(scanParams));
    const items = (response.Items || []).map(unmarshallItem);

    // Sort by timestamp descending
    items.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    const passed = items.filter((i) => i.status === "PASS").length;
    const failed = items.filter((i) => i.status === "FAIL").length;

    return {
      statusCode: 200,
      headers: CORS_HEADERS,
      body: JSON.stringify({
        summary: { total: items.length, passed, failed },
        results: items,
      }),
    };
  } catch (error) {
    console.error("getResults error:", error);
    return {
      statusCode: 500,
      headers: CORS_HEADERS,
      body: JSON.stringify({
        error: "Failed to retrieve scan results",
        message: error.message,
      }),
    };
  }
};
