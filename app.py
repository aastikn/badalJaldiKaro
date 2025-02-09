from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
from typing import Optional
import jwt
import boto3
import uvicorn

from login.loginJaldiKaro import login_to_aws_api, JWT_SECRET, JWT_ALGORITHM
from badal.badal import run_scan

app = FastAPI()

class LoginRequest(BaseModel):
    access_key: str
    secret_key: str
    region: Optional[str] = "us-east-1"

@app.post("/login")
def login(request: LoginRequest):
    try:
        result = login_to_aws_api(request.access_key, request.secret_key, request.region)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

def get_current_credentials(authorization: str = Header(...)):
    # Expect header format: "Bearer <token>"
    try:
        parts = authorization.split()
        if parts[0].lower() != "bearer" or len(parts) != 2:
            raise HTTPException(status_code=401, detail="Invalid authorization header")
        token = parts[1]
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/badal")
def badal_report(credentials: dict = Depends(get_current_credentials)):
    try:
        session = boto3.Session(
            aws_access_key_id=credentials["access_key"],
            aws_secret_access_key=credentials["secret_key"],
            region_name=credentials["region"]
        )
        report = run_scan(session=session)
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    # Run API on localhost:8000 with auto-reload.
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
