# Demo secrets for GoSecretScanv2
# These are fake credentials for testing the scanner. DO NOT use in production.

# 1) Simple password assignments (should trigger password detectors)
password = "P@ssw0rd123!"
db_password = "password123"

# 2) AWS credentials (classic patterns)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# 3) GitHub token (ghp_ + 36 chars)
GITHUB_TOKEN = "ghp_1234567890abcdef1234567890abcdef1234"

# 4) GCP API key (AIza + 35 chars)
GCP_API_KEY = "AIzaSyA1234567890abcdefGHIJKLMNOPQRSTUV123"

# 5) Stripe live secret key
stripe_secret_key = "sk_live_51M8c7uExampleExampleExample0000"

# 6) Slack Bot token
slack_bot_token = "xoxb-123456789012-1234567890123-ABCDEFGHIJKLMNOPQRSTUV"

# 7) Private key header/footer (header line alone should trigger)
PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCx...truncated...
-----END PRIVATE KEY-----"""

# 8) Bearer/JWT-like token
AUTH_HEADER = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.XYZXYZXYZ.abcdEFGHijklMNOPqrstUVWX0123456789"

# 9) Hardcoded connection string with password
conn_str = "postgres://appuser:Sup3rS3cr3t!@localhost:5432/appdb"

