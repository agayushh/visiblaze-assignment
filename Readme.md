# Cloud Posture Scanner

A **Cloud Posture Scanner** that analyzes AWS accounts for security misconfigurations based on **CIS Benchmark rules**.  
The system scans AWS services such as **EC2, S3, IAM, and CloudTrail** and reports security findings in a web dashboard.

The scanner identifies insecure configurations like:

- Publicly accessible S3 buckets
- Open SSH ports in security groups
- Missing encryption
- Disabled CloudTrail logging
- Missing root MFA

Results are displayed as **PASS / FAIL findings with evidence and timestamps**.

---

# Architecture Overview

The system follows a **client–server architecture**.

## Components

### Frontend
- React dashboard
- Displays scan results
- Allows users to trigger security scans

### Backend
- Node.js / Express API
- Security scanning engine
- CIS benchmark rule evaluation

### AWS Integration
- AWS SDK used to query AWS resources

### AWS Services Scanned
- EC2
- S3
- IAM
- CloudTrail

---

# System Workflow

1. User clicks **Run Scan** in the dashboard.
2. Frontend sends a request to the backend API.
3. Backend scanner retrieves AWS resource configurations using AWS SDK.
4. CIS security rules are evaluated.
5. Results are returned to the frontend.
6. Dashboard displays findings.

---

# Security Checks Implemented

| Check | Description |
|------|-------------|
| S3_PUBLIC_ACCESS | Ensures S3 buckets block public access |
| S3_ENCRYPTION | Verifies S3 bucket encryption is enabled |
| SG_OPEN_SSH_RDP | Detects security groups allowing SSH/RDP from the internet |
| IAM_ROOT_MFA | Ensures root account has MFA enabled |
| IAM_ACCESS_KEY_AGE | Detects outdated IAM access keys |
| CLOUDTRAIL_ENABLED | Ensures CloudTrail logging is enabled |

---

# Deployment Instructions

## 1. Clone the Repository

```bash
git clone https://github.com/agayushh/visiblaze-assignment
cd visiblaze-assignment
```

---

## 2. Install Dependencies



```bash
cd backend
npm install

cd ../frontend
npm install
```

---

## 3. Configure AWS Credentials

The scanner requires AWS credentials to access your AWS account.

You can configure them using:

```bash
aws configure
```

Or create a `.env` file.

Example:

```
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_REGION=us-east-1
```

---

## 4. Run Backend Server

```bash
npm run dev
```

or

```bash
node server.js
```

Backend server runs at:

```
http://localhost:5000
```

---

## 5. Run Frontend

```bash
npm run dev
```

Frontend dashboard runs at:

```
http://localhost:3000
```

---

# API Documentation

## Run Security Scan

Runs all CIS security checks on AWS resources.

**Endpoint**

```
POST /scan
```

### Example Request

```
POST /scan
```

### Example Response

```json
{
  "checks": [
    {
      "check": "S3_PUBLIC_ACCESS",
      "status": "PASS",
      "resource": "example-bucket"
    },
    {
      "check": "SG_OPEN_SSH_RDP",
      "status": "FAIL",
      "resource": "sg-123456"
    }
  ]
}
```

---

## Get Scan Results

Returns the latest scan results.

**Endpoint**

```
GET /results
```

### Example Response

```json
{
  "totalChecks": 9,
  "passed": 3,
  "failed": 6,
  "results": [
    {
      "check": "IAM_ROOT_MFA",
      "status": "PASS"
    },
    {
      "check": "CLOUDTRAIL_ENABLED",
      "status": "FAIL"
    }
  ]
}
```

---

# Demo

Live Demo:

```
https://visiblaze-assignment.vercel.app
```

---

# System Architecture 

[system architecture](system_architecture.png)
---

# Tech Stack

### Frontend
- React 
- Tailwind CSS

### Backend
- Node.js
- Express

### Cloud Integration
- AWS SDK

---




# Author

**Ayush Goyal**