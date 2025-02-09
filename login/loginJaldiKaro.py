import boto3
import jwt
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

JWT_SECRET = "hackathon_secret_key"  # For demo purposes only; use a secure secret in production!
JWT_ALGORITHM = "HS256"
JWT_EXP_DELTA_SECONDS = 3600  # 1 hour token validity

def login_to_aws_api(access_key: str, secret_key: str, region: str = "us-east-1"):
    session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region
    )
    try:
        sts_client = session.client("sts")
        identity = sts_client.get_caller_identity()
    except ClientError as e:
        raise Exception("Invalid AWS credentials") from e

    payload = {
        "access_key": access_key,
        "secret_key": secret_key,
        "region": region,
        "exp": datetime.utcnow() + timedelta(seconds=JWT_EXP_DELTA_SECONDS)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {
        "token": token,
        "account": identity.get("Account"),
        "user_id": identity.get("UserId"),
        "arn": identity.get("Arn")
    }
