from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional
import jwt
import boto3
import uvicorn
import os
import json
from dotenv import load_dotenv

from login.loginJaldiKaro import login_to_aws_api, JWT_SECRET, JWT_ALGORITHM
from badal.badal import run_scan
from badal.solution_provider import analyze_vulnerabilities_with_mistral

load_dotenv()

app = FastAPI(title="Badal — Cloud Vulnerability Analyser")

# Add CORS middleware — allow frontend origins.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",   # Next.js dev
        "http://127.0.0.1:3000",
        "*",                       # Adjust for production
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class LoginRequest(BaseModel):
    access_key: str
    secret_key: str
    region: Optional[str] = "us-east-1"

class AnalyzeRequest(BaseModel):
    report: dict

@app.post("/login")
def login(request: LoginRequest):
    try:
        print(f"[LOGIN] access_key length={len(request.access_key)}, region={request.region}")
        result = login_to_aws_api(request.access_key, request.secret_key, request.region)
        return result
    except Exception as e:
        print(f"[LOGIN ERROR] {type(e).__name__}: {e}")
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

@app.post("/scan")
def scan_report(credentials: dict = Depends(get_current_credentials)):
    """Run full cloud vulnerability scan and return structured report with dependency graph."""
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

@app.post("/analyze")
def analyze_report(request: AnalyzeRequest, credentials: dict = Depends(get_current_credentials)):
    """Send scan report to Mistral AI for vulnerability analysis and remediation suggestions."""
    try:
        mistral_key = os.getenv("MISTRAL_API_KEY")
        if not mistral_key:
            raise HTTPException(status_code=500, detail="MISTRAL_API_KEY not configured on server")
        analysis = analyze_vulnerabilities_with_mistral(request.report, mistral_key)
        return analysis
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Keep the old endpoint for backward compatibility
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
    # Run API on 0.0.0.0:8000 with auto-reload.
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
