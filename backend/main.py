import os
import time
import json
import boto3
from datetime import datetime
from decimal import Decimal
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt

from pydantic import BaseModel
from engine.attack_logic import generate_attack_vectors

# Import the individual intelligence cells directly
from engine.dns_cell import run_dns_recon
from engine.network_cell import run_network_recon
from engine.web_cell import run_web_recon

load_dotenv()
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def verify_token(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Token")
    try:
        token = authorization.split(" ")[1]
        return jwt.get_unverified_claims(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid Token")

# --- AWS DYNAMODB ARCHIVING ---
def archive_to_dynamo(target: str, module_name: str, intel_data: dict):
    table_name = os.getenv("DYNAMODB_TABLE_NAME")
    if not table_name or "your_" in table_name:
        print("[-] DynamoDB archiving skipped: Table name not configured.")
        return

    try:
        # DynamoDB strictly requires floats to be Decimals. This safely converts the payload.
        clean_intel = json.loads(json.dumps(intel_data), parse_float=Decimal)

        dynamodb = boto3.resource(
            'dynamodb',
            region_name=os.getenv("AWS_REGION"),
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY")
        )
        table = dynamodb.Table(table_name)
        
        # Composite Partition Key (target) and Sort Key (timestamp)
        item = {
            'target': target,
            'timestamp': datetime.utcnow().isoformat(),
            'module': module_name,
            'intel': clean_intel
        }
        
        table.put_item(Item=item)
        print(f"[+] ARCHIVED: {module_name.upper()} intelligence for {target} saved to DynamoDB.")
    except Exception as e:
        print(f"[-] DYNAMODB ERROR: Failed to archive {module_name} for {target}. Reason: {str(e)}")

# --- TACTICAL ENDPOINTS ---

@app.post("/scan/dns")
async def scan_dns(target: str, user=Depends(verify_token)):
    print(f"--- RUNNING DNS RECON: {target} ---")
    results = run_dns_recon(target)
    archive_to_dynamo(target, "dns_recon", results)
    return {"results": results}

@app.post("/scan/network")
async def scan_network(target: str, user=Depends(verify_token)):
    print(f"--- RUNNING NETWORK RECON: {target} ---")
    results = run_network_recon(target)
    archive_to_dynamo(target, "network_recon", results)
    return {"results": results}

@app.post("/scan/web")
async def scan_web(target: str, user=Depends(verify_token)):
    print(f"--- RUNNING WEB RECON: {target} ---")
    results = run_web_recon(target)
    archive_to_dynamo(target, "web_recon", results)
    return {"results": results}

# Model to accept the intel from the frontend
class IntelPayload(BaseModel):
    dns: dict | None = None
    network: dict | None = None
    web: dict | None = None

@app.post("/scan/analyze")
async def scan_analyze(payload: IntelPayload, user=Depends(verify_token)):
    print(f"--- RUNNING THREAT ANALYSIS ---")
    # Feed the frontend data into the tactician engine
    vectors = generate_attack_vectors(payload.network or {}, payload.web or {}, payload.dns or {})
    
    # Extract a target name from the DNS payload if available, otherwise default to "Aggregate_Analysis"
    target_name = payload.dns.get('base_ip', 'Aggregate_Analysis') if payload.dns else 'Aggregate_Analysis'
    archive_to_dynamo(target_name, "tactician_analysis", {"vectors": vectors})
    
    return {"results": vectors}