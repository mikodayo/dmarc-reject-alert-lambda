import os
import json
import gzip
import base64
import boto3
from datetime import datetime, timezone

# ---
# Environment variables
# ---
SES_REGION = os.environ.get("SES_REGION", "us-east-1")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "alert@example.com")
TO_EMAILS = [s.strip() for s in os.environ.get("TO_EMAILS", "").split(",") if s.strip()]

ses = boto3.client("ses", region_name=SES_REGION)


def _to_utc_iso(ts_ms: int | float | None, fallback: str) -> str:
    if isinstance(ts_ms, (int, float)):
        dt = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
        return dt.isoformat()
    return fallback


def lambda_handler(event, context):
    """
    Trigger: CloudWatch Logs subscription filter
    Filter example: { $.event.dmarcPolicy = "REJECT" }

    Expected event format:
    {
      "awslogs": { "data": "<base64(gzip(json))>" }
    }
    """
    if "awslogs" not in event or "data" not in event["awslogs"]:
        # This often happens when you run a manual Lambda test with the wrong event payload.
        raise ValueError("Invalid event format: expected event['awslogs']['data']")

    payload = gzip.decompress(base64.b64decode(event["awslogs"]["data"]))
    data = json.loads(payload)

    for le in data.get("logEvents", []):
        raw_message = le.get("message", "")
        try:
            msg = json.loads(raw_message)  # App structured JSON (your original log)
        except Exception:
            msg = {}

        ev = msg.get("event") or {}
        if ev.get("dmarcPolicy") != "REJECT":
            continue

        # Timestamp
        ts_ms = msg.get("eventTime") or ev.get("messageTimestamp")
        dt_str = _to_utc_iso(ts_ms, fallback=str(le.get("timestamp")))

        # Subject
        from_addr = ev.get("from", "(unknown)")
        subj = ev.get("subject", "(no subject)")
        subject = f"[DMARC REJECT] from={from_addr} subj={subj[:60]}"

        # Body (includes raw log line)
        body = (
            "DMARC REJECT detected\n\n"
            f"Time (UTC): {dt_str}\n"
            f"AccountId: {msg.get('accountId')}\n"
            f"OrgId: {msg.get('organizationId')}\n"
            f"TraceId: {msg.get('traceId')}\n\n"
            f"From: {from_addr}\n"
            f"Subject: {subj}\n"
            f"MessageId: {ev.get('messageId')}\n"
            f"DMARC Verdict: {ev.get('dmarcVerdict')}\n"
            f"SPF Verdict: {ev.get('spfVerdict')}\n"
            f"DKIM Verdict: {ev.get('dkimVerdict')}\n"
            f"Spam Verdict: {ev.get('spamVerdict')}\n\n"
            "---- RAW LOG ----\n"
            f"{raw_message}\n"
        )

        if not TO_EMAILS:
            raise ValueError("TO_EMAILS is empty. Set env var TO_EMAILS (comma-separated).")

        # Send via SES
        ses.send_email(
            Source=FROM_EMAIL,
            Destination={"ToAddresses": TO_EMAILS},
            Message={
                "Subject": {"Data": subject, "Charset": "UTF-8"},
                "Body": {"Text": {"Data": body, "Charset": "UTF-8"}},
            },
        )
