# IAM Access Analyzer Workshop - Complete Use Cases Guide

## Overview

AWS IAM Access Analyzer helps you identify resources in your organization and accounts that are shared with external entities. This workshop provides comprehensive use cases and examples to test different scenarios and understand how Access Analyzer works in practice.

## What is IAM Access Analyzer?

IAM Access Analyzer uses provable security (mathematical logic) to analyze resource policies and identify resources that can be accessed from outside your zone of trust. It generates findings for resources that allow access to external principals.

### Key Features:
- **External Access Detection** - Identifies resources accessible outside your zone of trust
- **Policy Validation** - Validates IAM policies against AWS best practices
- **Archive Rules** - Reduces noise by archiving expected findings
- **Continuous Monitoring** - Monitors for new external access grants
- **Integration** - Works with EventBridge, CloudTrail, and other AWS services

## Zone of Trust

- **Account Zone** - Your AWS account is the zone of trust
- **Organization Zone** - Your AWS Organization is the zone of trust

## Use Cases and Examples

### 1. S3 Bucket External Access

#### Use Case: Public S3 Bucket Detection
**Scenario**: Detect S3 buckets that allow public read access

**Example Policy** (Bucket Policy):
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-public-bucket/*"
    }
  ]
}
```

**Expected Finding**: Public access to S3 bucket
**Archive Rule**: Archive if this is an intentional public website bucket

#### Use Case: Cross-Account S3 Access
**Scenario**: S3 bucket shared with specific external AWS account

**Example Policy**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:root"
      },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::shared-bucket/*"
    }
  ]
}
```

**Expected Finding**: External account access
**Archive Rule**: Archive if 123456789012 is a trusted partner account

### 2. IAM Role External Access

#### Use Case: Cross-Account Role Assumption
**Scenario**: IAM role that can be assumed by external account

**Example Trust Policy**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::987654321098:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "unique-external-id"
        }
      }
    }
  ]
}
```

**Expected Finding**: External account can assume role
**Archive Rule**: Archive if this is for a trusted third-party service

#### Use Case: SAML Federation Access
**Scenario**: Role accessible via SAML identity provider

**Example Trust Policy**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:saml-provider/CompanySAML"
      },
      "Action": "sts:AssumeRoleWithSAML",
      "Condition": {
        "StringEquals": {
          "SAML:aud": "https://signin.aws.amazon.com/saml"
        }
      }
    }
  ]
}
```

**Expected Finding**: Federated access via SAML
**Archive Rule**: Archive for known corporate SAML providers

### 3. Lambda Function External Access

#### Use Case: Lambda Function with Resource Policy
**Scenario**: Lambda function invokable by external service

**Example Resource Policy**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "s3.amazonaws.com"
      },
      "Action": "lambda:InvokeFunction",
      "Resource": "arn:aws:lambda:us-east-1:123456789012:function:MyFunction",
      "SourceArn": "arn:aws:s3:::my-bucket"
    }
  ]
}
```

**Expected Finding**: External service access (if S3 bucket is external)
**Archive Rule**: Archive for AWS service principals

### 4. KMS Key External Access

#### Use Case: KMS Key Shared Externally
**Scenario**: KMS key accessible by external account

**Example Key Policy**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111122223333:root"
      },
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "*"
    }
  ]
}
```

**Expected Finding**: External account KMS access
**Archive Rule**: Archive for trusted encryption partners

### 5. SQS Queue External Access

#### Use Case: SQS Queue Cross-Account Access
**Scenario**: SQS queue accessible by external account

**Example Queue Policy**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::444455556666:root"
      },
      "Action": "sqs:SendMessage",
      "Resource": "arn:aws:sqs:us-east-1:123456789012:MyQueue"
    }
  ]
}
```

**Expected Finding**: External account SQS access
**Archive Rule**: Archive for integration partner accounts

### 6. Secrets Manager External Access

#### Use Case: Secret Shared with External Account
**Scenario**: Secrets Manager secret accessible externally

**Example Resource Policy**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::777788889999:role/ExternalServiceRole"
      },
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "*"
    }
  ]
}
```

**Expected Finding**: External access to secrets
**Archive Rule**: Archive for trusted service integrations

## Archive Rules Examples

### 1. Archive Public Website Buckets
```yaml
- RuleName: 'public-website-buckets'
  Filter:
    - Property: 'resource'
      Contains:
        - 'arn:aws:s3:::website-'
        - 'arn:aws:s3:::public-'
    - Property: 'isPublic'
      Eq:
        - 'true'
```

### 2. Archive Trusted Partner Accounts
```yaml
- RuleName: 'trusted-partners'
  Filter:
    - Property: 'principal.AWS'
      Eq:
        - 'arn:aws:iam::123456789012:root'
        - 'arn:aws:iam::987654321098:root'
    - Property: 'isPublic'
      Eq:
        - 'false'
```

### 3. Archive AWS Service Access
```yaml
- RuleName: 'aws-services'
  Filter:
    - Property: 'principal.Service'
      Contains:
        - 'lambda.amazonaws.com'
        - 's3.amazonaws.com'
        - 'events.amazonaws.com'
```

### 4. Archive SAML Federation
```yaml
- RuleName: 'corporate-saml'
  Filter:
    - Property: 'principal.Federated'
      Contains:
        - ':saml-provider/CompanySAML'
        - ':saml-provider/OktaSAML'
```

## Testing Scenarios

### Scenario 1: AI/ML Workload Security
**Setup**: Deploy AI agent with S3 data bucket, Lambda functions, and cross-account model access
**Test**: Verify external access detection for model sharing
**Expected**: Findings for external model account access
**Archive**: Rules for trusted AI service accounts

### Scenario 2: Multi-Account Organization
**Setup**: Organization with dev/staging/prod accounts
**Test**: Cross-account resource sharing
**Expected**: Findings for cross-account access outside organization
**Archive**: Rules for internal organization accounts

### Scenario 3: Third-Party Integration
**Setup**: SQS queues and Lambda functions for external API integration
**Test**: External service access permissions
**Expected**: Findings for third-party service access
**Archive**: Rules for known integration partners

### Scenario 4: Data Analytics Pipeline
**Setup**: S3 buckets shared with analytics account, KMS keys for encryption
**Test**: Cross-account data access patterns
**Expected**: Findings for analytics account access
**Archive**: Rules for trusted analytics partners

## Workshop Labs

### Lab 1: Basic Setup - Step by Step Console Instructions

#### Step 1: Create Access Analyzer with Account Zone of Trust

1. **Navigate to IAM Access Analyzer**
   - Open AWS Console
   - Go to **IAM** service
   - In left navigation, click **Access analyzer**
   - Click **Create analyzer**

2. **Configure Analyzer Settings**
   - **Analyzer name**: Enter `workshop-analyzer`
   - **Zone of trust**: Select **Current account**
   - **Region**: Ensure you're in your preferred region (e.g., us-east-1)
   - Click **Create analyzer**

3. **Verify Creation**
   - Wait for analyzer status to show **Active**
   - Note the analyzer ARN for reference

#### Step 2: Deploy Sample S3 Bucket with Public Access

1. **Create S3 Bucket**
   - Navigate to **S3** service
   - Click **Create bucket**
   - **Bucket name**: `workshop-public-bucket-[your-account-id]` (must be globally unique)
   - **Region**: Same as your Access Analyzer
   - **Block Public Access settings**: Uncheck **Block all public access**
   - Check the acknowledgment box
   - Click **Create bucket**

2. **Add Public Bucket Policy**
   - Click on your newly created bucket
   - Go to **Permissions** tab
   - Scroll to **Bucket policy** section
   - Click **Edit**
   - Paste the following policy (replace `YOUR-BUCKET-NAME`):
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Principal": "*",
         "Action": "s3:GetObject",
         "Resource": "arn:aws:s3:::YOUR-BUCKET-NAME/*"
       }
     ]
   }
   ```
   - Click **Save changes**

3. **Upload Test File**
   - Go to **Objects** tab
   - Click **Upload**
   - Add a test file (e.g., `test.txt`)
   - Click **Upload**

#### Step 3: Review Generated Findings

1. **Wait for Analysis** (5-10 minutes)
   - Access Analyzer runs continuously but may take time for initial findings

2. **View Findings**
   - Return to **IAM** > **Access analyzer**
   - Click on your `workshop-analyzer`
   - Click **Findings** tab
   - You should see a finding for your S3 bucket

3. **Examine Finding Details**
   - Click on the S3 bucket finding
   - Review the following information:
     - **Resource**: Your bucket ARN
     - **Resource type**: AWS::S3::Bucket
     - **External principal**: * (public access)
     - **Access level**: Read
     - **Condition**: None
     - **Action**: s3:GetObject

4. **Understanding the Finding**
   - **Status**: Active (needs attention)
   - **Public**: Yes (accessible from internet)
   - **Principal**: * (anyone can access)

#### Step 4: Create Archive Rule for Public Buckets

1. **Navigate to Archive Rules**
   - In your Access Analyzer dashboard
   - Click **Archive rules** tab
   - Click **Create archive rule**

2. **Configure Archive Rule**
   - **Rule name**: `public-website-buckets`
   - **Description**: `Archive findings for intentional public website buckets`

3. **Set Filter Criteria**
   - Click **Add filter**
   - **Property**: Select `resource`
   - **Operator**: Select `contains`
   - **Value**: Enter `website-` (this will match buckets with 'website-' in the name)
   
   - Click **Add filter** again
   - **Property**: Select `isPublic`
   - **Operator**: Select `equals`
   - **Value**: Select `true`

4. **Review and Create**
   - Review your filter criteria
   - Click **Create archive rule**

5. **Test Archive Rule**
   - Create another S3 bucket named `website-test-bucket-[account-id]`
   - Apply the same public policy
   - Wait 5-10 minutes
   - Check that this finding is automatically archived

#### Verification Steps

1. **Check Active Findings**
   - Go to **Findings** tab
   - Verify your original bucket finding is still **Active**
   - Verify the website bucket finding is **Archived** (if created)

2. **View Archived Findings**
   - Click **Archived** tab
   - See findings that match your archive rule

3. **Test Public Access**
   - Try accessing your bucket object via public URL:
   - `https://YOUR-BUCKET-NAME.s3.amazonaws.com/test.txt`
   - Should be accessible without authentication

#### Expected Results

✅ **Access Analyzer Created**: Status shows Active
✅ **S3 Bucket Finding**: Shows public access to bucket
✅ **Archive Rule Working**: Website buckets automatically archived
✅ **Public Access Confirmed**: Files accessible via public URL

#### Cleanup (Optional)

1. **Delete S3 Buckets**
   - Empty bucket contents first
   - Delete the buckets

2. **Keep Access Analyzer**
   - Leave analyzer running for subsequent labs

#### Troubleshooting

- **No findings appear**: Wait 10-15 minutes, Access Analyzer needs time to analyze
- **Archive rule not working**: Check filter syntax and property names
- **Can't create public bucket**: Verify Block Public Access settings are disabled
- **Policy error**: Ensure bucket name in policy matches actual bucket name

### Lab 2: Cross-Account IAM Role - Key Components

#### Overview
This lab creates an IAM role that can be assumed by an external AWS account, which will trigger Access Analyzer findings. We'll create a role with cross-account trust policy and attach permissions that Access Analyzer will flag as external access.

#### Trust Policy JSON
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "workshop-external-id"
        }
      }
    }
  ]
}
```

#### Permissions Policy JSON
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::workshop-*",
        "arn:aws:s3:::workshop-*/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:Query",
        "dynamodb:Scan"
      ],
      "Resource": "arn:aws:dynamodb:*:*:table/workshop-*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*"
    }
  ]
}
```

#### Step-by-Step Console Instructions

**Step 1: Create IAM Role**
1. Navigate to **IAM** > **Roles** > **Create role**
2. Select **AWS account** > **Another AWS account**
3. Account ID: `123456789012`
4. Check **Require external ID**: `workshop-external-id`
5. Role name: `WorkshopCrossAccountRole`

**Step 2: Attach Permissions**
1. Go to role **Permissions** tab
2. **Add permissions** > **Create inline policy**
3. Use **JSON** tab and paste permissions policy above
4. Policy name: `WorkshopCrossAccountPermissions`

**Step 3: Monitor Access Analyzer**
1. Wait 10-15 minutes for analysis
2. Check **IAM** > **Access analyzer** > **Findings**
3. Look for **AWS::IAM::Role** finding
4. Review external principal: `123456789012`

**Step 4: Create Archive Rule**
1. **Archive rules** tab > **Create archive rule**
2. Rule name: `trusted-partner-accounts`
3. Filter: `principal.AWS` equals `arn:aws:iam::123456789012:root`
4. Filter: `isPublic` equals `false`

#### Expected Access Analyzer Findings

**What Gets Flagged:**
- External AWS account can assume IAM role
- Role has permissions to access S3, DynamoDB, CloudWatch
- Potential unauthorized access to resources
- Cross-account trust relationship detected

**Finding Details:**
- **Resource**: `arn:aws:iam::YOUR-ACCOUNT:role/WorkshopCrossAccountRole`
- **Principal**: `arn:aws:iam::123456789012:root`
- **Action**: `sts:AssumeRole`
- **Access Level**: Various (based on permissions)
- **Condition**: External ID requirement

#### Security Best Practices

**Enhanced Security Measures:**
- ✅ **External ID**: Additional authentication factor
- ✅ **Least Privilege**: Minimal required permissions
- ✅ **Resource Restrictions**: Limit to specific resources
- ✅ **Condition Blocks**: Time-based or IP restrictions
- ✅ **Regular Reviews**: Monitor actual role usage

**Archive Rule Strategy:**
- Archive trusted partner accounts
- Keep unknown external accounts as active findings
- Document business justification for external access
- Regular review of archived vs active findings

#### Troubleshooting

- **No IAM findings**: Wait 15-20 minutes, IAM analysis takes longer
- **Archive rule not working**: Check principal.AWS format matches exactly
- **Can't create role**: Verify you have IAM permissions
- **External ID issues**: Ensure condition syntax is correct in trust policy


### Lab 3: Policy Validation
1. Create IAM policy with potential issues
2. Use Access Analyzer policy validation
3. Review and fix policy recommendations
4. Test policy changes

### Lab 4: Automated Monitoring
1. Set up EventBridge rules for Access Analyzer findings
2. Create Lambda function for automated responses
3. Test finding notifications and remediation
4. Monitor security posture over time

### Lab 5: AI/ML Security
1. Deploy AI agent infrastructure
2. Configure cross-account model access
3. Set up data sharing policies
4. Create AI-specific archive rules

## Best Practices

### 1. Archive Rule Strategy
- Start with broad rules and refine over time
- Archive known safe patterns to reduce noise
- Regular review of archived vs active findings
- Document business justification for archive rules

### 2. Monitoring and Alerting
- Set up EventBridge integration for real-time alerts
- Create dashboards for security posture visibility
- Implement automated remediation for critical findings
- Regular security reviews and audits

### 3. Policy Management
- Use Access Analyzer policy validation before deployment
- Implement least privilege access principles
- Regular policy reviews and updates
- Version control for policy changes

### 4. Organization-Wide Deployment
- Deploy at organization level for comprehensive coverage
- Consistent archive rules across accounts
- Centralized monitoring and reporting
- Cross-account finding correlation

## Common Findings and Resolutions

| Finding Type | Common Cause | Resolution |
|--------------|--------------|------------|
| Public S3 Bucket | Bucket policy allows public access | Review if public access is needed, add archive rule if intentional |
| Cross-Account Role | Role trust policy includes external account | Verify external account is trusted, add conditions if needed |
| Lambda External Access | Resource policy allows external invocation | Review if external access is required, restrict to specific sources |
| KMS Key Sharing | Key policy grants external access | Verify encryption sharing requirements, use grants for temporary access |
| SQS Queue Access | Queue policy allows external send/receive | Review integration requirements, use conditions to restrict access |

## Troubleshooting

### Common Issues:
1. **No Findings Generated** - Check zone of trust configuration and resource policies
2. **Too Many Findings** - Implement archive rules for known safe patterns
3. **Archive Rules Not Working** - Verify filter syntax and property names
4. **Missing Expected Findings** - Ensure resources have policies that grant external access

### Debugging Steps:
1. Verify Access Analyzer is enabled in correct region
2. Check resource policies for external principals
3. Review archive rule filters for accuracy
4. Test with known external access scenarios
5. Monitor CloudTrail for Access Analyzer API calls

## Integration Examples

### EventBridge Integration
```json
{
  "source": ["aws.access-analyzer"],
  "detail-type": ["Access Analyzer Finding"],
  "detail": {
    "status": ["ACTIVE"],
    "resourceType": ["AWS::S3::Bucket", "AWS::IAM::Role"]
  }
}
```

### Lambda Remediation Function
```python
def lambda_handler(event, context):
    finding = event['detail']
    resource_arn = finding['resource']
    
    if finding['resourceType'] == 'AWS::S3::Bucket':
        # Handle S3 bucket finding
        handle_s3_finding(resource_arn, finding)
    elif finding['resourceType'] == 'AWS::IAM::Role':
        # Handle IAM role finding
        handle_iam_finding(resource_arn, finding)
```

## Conclusion

IAM Access Analyzer is a powerful tool for maintaining security posture by identifying unintended external access to your AWS resources. This workshop provides comprehensive examples and use cases to help you understand and implement Access Analyzer effectively in your environment.

Regular use of Access Analyzer, combined with proper archive rules and automated monitoring, helps ensure your AWS resources maintain appropriate access controls and security boundaries.
