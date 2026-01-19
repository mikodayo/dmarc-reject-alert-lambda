# DMARC REJECT Alert (CloudWatch Logs → Lambda → SES)

This repository provides an AWS Lambda function that detects `dmarcPolicy = "REJECT"` events in structured JSON logs delivered via **CloudWatch Logs subscription filters**, then sends an email alert via **Amazon SES**.  
The email includes both a human-readable summary and the original raw log line.

## Architecture

CloudWatch Logs (Log Group)
→ Subscription Filter (`{ $.event.dmarcPolicy = "REJECT" }`)
→ Lambda
→ Amazon SES (SendEmail)

## Prerequisites

- Amazon SES is available and configured in your target region.
- Your **FROM** identity is verified in SES:
  - Email identity (e.g., `alert@example.com`), or
  - Domain identity (recommended).
- If SES is still in **sandbox**, the **TO** addresses must also be verified.

## Environment Variables

Set these in Lambda configuration:

- `SES_REGION` (default: `us-east-1`)
- `FROM_EMAIL` (e.g., `alert@example.com`)
- `TO_EMAILS` (comma-separated, e.g., `sec-team@example.com,ops@example.com`)

See `.env.example`.

## CloudWatch Logs Subscription Filter

Create a subscription filter for your target log group:

Filter pattern:
{ $.event.dmarcPolicy = "REJECT" }

Destination:
- This Lambda function

> Note: A log group can have only **one** subscription filter. If you already use one, you must consolidate the pipeline (e.g., via Kinesis / Firehose).

## IAM Policy (Lambda Execution Role)

Attach at least the following permission to the Lambda execution role:

- `ses:SendEmail` (and optionally `ses:SendRawEmail`)

Example policy is in `iam-policy-example.json`.

## Testing

### Common pitfall
Manual Lambda test events often fail because they do not include `event.awslogs.data`.  
This function expects the **CloudWatch Logs subscription** payload format:
```json
{ "awslogs": { "data": "..." } }

To test locally, you can create a sample payload by:

Building the decoded JSON (CloudWatch Logs event)

Gzip compressing it

Base64 encoding it

(You can also test by triggering a real log event in the subscribed log group.)

Security Notes

The function includes the raw log line in the email body.
Avoid logging or emailing sensitive content unless approved by your security policy.

Consider adding deduplication (e.g., by messageId) or batching to avoid email floods.

### License

MIT



