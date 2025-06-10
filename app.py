from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv
import os
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response as StarletteResponse, StreamingResponse
from typing import Awaitable, Callable
from datetime import datetime, timezone
from cachetools import TTLCache
import json

from aws_data_fetcher import (
    get_live_eks_data,
    get_single_cluster_details,
    upgrade_nodegroup_version,
    stream_cloudwatch_logs
)

load_dotenv()

app = FastAPI(title="EKS Operational Dashboard")

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

cache = TTLCache(maxsize=20, ttl=300) 

class CurrentTimeMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: StarletteRequest, call_next: Callable[[StarletteRequest], Awaitable[StarletteResponse]]
    ) -> StarletteResponse:
        request.state.now = datetime.now(timezone.utc)
        response = await call_next(request)
        return response

app.add_middleware(CurrentTimeMiddleware)

def get_role_arn_for_account(account_id: str) -> str | None:
    target_roles_str = os.getenv("AWS_TARGET_ACCOUNTS_ROLES", "")
    if target_roles_str and account_id != 'Primary Account':
        for r_arn in target_roles_str.split(','):
            if account_id in r_arn:
                return r_arn.strip()
    return None

@app.get("/", response_class=HTMLResponse)
async def read_dashboard(request: Request):
    if 'dashboard_data' in cache:
        print("Fetching dashboard data (from cache)...")
        dashboard_data = cache['dashboard_data']
    else:
        print("Fetching dashboard data (cache miss, calling AWS)...")
        dashboard_data = get_live_eks_data()
        cache['dashboard_data'] = dashboard_data
    
    context = {"request": request, **dashboard_data}
    return templates.TemplateResponse("dashboard.html", context)

@app.get("/cluster/{account_id}/{region}/{cluster_name}", response_class=HTMLResponse)
async def read_cluster_detail(request: Request, account_id: str, region: str, cluster_name: str):
    role_arn = get_role_arn_for_account(account_id)
    cache_key = f"cluster_{account_id}_{region}_{cluster_name}"

    if cache_key in cache:
        print(f"Fetching details for {cluster_name} (from cache)...")
        cluster_detail_data = cache[cache_key]
    else:
        print(f"Fetching details for {cluster_name} (cache miss, calling AWS)...")
        cluster_detail_data = get_single_cluster_details(account_id, region, cluster_name, role_arn)
        cache[cache_key] = cluster_detail_data
    
    context = {
        "request": request,
        "cluster": cluster_detail_data,
        "errors": cluster_detail_data.get("errors", [])
    }
    return templates.TemplateResponse("cluster_detail.html", context)

@app.post("/api/upgrade-nodegroup")
async def api_upgrade_nodegroup(request: Request):
    try:
        body = await request.json()
        account_id = body.get("accountId")
        region = body.get("region")
        cluster_name = body.get("clusterName")
        nodegroup_name = body.get("nodegroupName")
    except json.JSONDecodeError:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body."})

    if not all([account_id, region, cluster_name, nodegroup_name]):
        return JSONResponse(status_code=400, content={"error": "Missing required parameters in request body."})

    role_arn = get_role_arn_for_account(account_id)
    result = upgrade_nodegroup_version(account_id, region, cluster_name, nodegroup_name, role_arn)

    if "error" in result:
        return JSONResponse(status_code=500, content=result)
    
    cache_key = f"cluster_{account_id}_{region}_{cluster_name}"
    if cache_key in cache:
        del cache[cache_key]
        print(f"Cache invalidated for {cache_key}")
        
    return JSONResponse(content=result)

@app.get("/api/logs/{account_id}/{region}/{cluster_name}/{log_type}")
async def api_stream_logs(account_id: str, region: str, cluster_name: str, log_type: str):
    role_arn = get_role_arn_for_account(account_id)
    log_group_name = f"/aws/eks/{cluster_name}/cluster"
    
    return StreamingResponse(
        stream_cloudwatch_logs(account_id, region, log_group_name, log_type, role_arn),
        media_type="text/event-stream"
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
