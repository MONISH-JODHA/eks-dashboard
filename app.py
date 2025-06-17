# --- START OF FILE app.py ---

from fastapi import FastAPI, Request, Form, Depends, Query
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv
import os
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response as StarletteResponse
from urllib.parse import urlparse, quote
from cachetools import TTLCache
import json
import logging
import uvicorn
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
import copy
import uuid

# SAML specific imports
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils

# Your existing data fetcher functions
from aws_data_fetcher import (
    get_live_eks_data,
    get_single_cluster_details,
    upgrade_nodegroup_version,
    stream_cloudwatch_logs,
    get_cluster_metrics,
    get_cost_breakdown,
    calculate_what_if_cost
)

# Load environment variables from your .env file
load_dotenv()

# --- App Initialization ---
app = FastAPI(title="EKS Operational Dashboard")

# --- Middleware Setup ---
class UserStateMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request.state.user = request.session.get("user")
        response = await call_next(request)
        return response

app.add_middleware(UserStateMiddleware)
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SECRET_KEY", "a_very_secret_key_for_dev")
)

# --- Static files, Templates, and Global State ---
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
# Cache with 1-hour TTL
cache = TTLCache(maxsize=200, ttl=3600)
# In-memory store for Time Machine snapshots (cleared on restart)
SNAPSHOT_STORE = {}

# --- SAML Helper Function ---
async def prepare_saml_request(request: Request):
    form_data = await request.form() if request.method == 'POST' else {}
    base_url = os.getenv("APP_BASE_URL")
    if not base_url:
        base_url = str(request.base_url).rstrip('/')
    parsed_url = urlparse(base_url)
    return {
        "http_host": parsed_url.netloc, "script_name": request.url.path,
        "server_port": str(parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)),
        "get_data": dict(request.query_params), "post_data": dict(form_data),
        "https_": "on" if parsed_url.scheme == "https" else "off",
    }

# --- Auth Dependency (Route Protector) ---
async def get_current_user(request: Request):
    if not request.state.user:
        if "/api/" in request.url.path:
            return JSONResponse(status_code=401, content={"detail": "Not authenticated"})
        
        redirect_url = f"/login?next={quote(request.url.path)}"
        return RedirectResponse(url=redirect_url)
    
    return request.state.user

# --- Authentication Routes (SAML) ---
@app.get('/login', tags=['Authentication'], name='saml_login')
async def saml_login(request: Request, next: str = "/"):
    req = await prepare_saml_request(request)
    auth = OneLogin_Saml2_Auth(req, custom_base_path=os.path.join(os.path.dirname(__file__), 'saml_config'))
    return RedirectResponse(auth.login(return_to=next))

@app.post('/saml/acs', tags=['Authentication'], include_in_schema=False)
async def saml_assertion_consumer_service(request: Request):
    req = await prepare_saml_request(request)
    auth = OneLogin_Saml2_Auth(req, custom_base_path=os.path.join(os.path.dirname(__file__), 'saml_config'))
    auth.process_response()
    errors = auth.get_errors()
    if errors:
        logging.error(f"SAML ACS Error: {errors} | Reason: {auth.get_last_error_reason()}")
        return templates.TemplateResponse("error.html", {"request": request, "errors": errors, "reason": auth.get_last_error_reason()}, status_code=401)
    if not auth.is_authenticated():
        return RedirectResponse(url="/login?error=auth_failed", status_code=307)
    request.session["user"] = {
        'email': auth.get_nameid(), 'attributes': auth.get_attributes(), 'session_index': auth.get_session_index()
    }
    relay_state = req['post_data'].get('RelayState', '/')
    if not relay_state.startswith('/'):
        relay_state = '/'
    return RedirectResponse(url=relay_state, status_code=303)

@app.get('/logout', tags=['Authentication'], name='saml_logout')
async def saml_logout(request: Request):
    req = await prepare_saml_request(request)
    auth = OneLogin_Saml2_Auth(req, custom_base_path=os.path.join(os.path.dirname(__file__), 'saml_config'))
    user_session = request.session.get("user", {})
    logout_url = auth.logout(
        name_id=user_session.get("email"), 
        session_index=user_session.get("session_index"), 
        return_to="/"
    )
    request.session.clear()
    return RedirectResponse(logout_url if logout_url else "/")

@app.get("/logged-out", response_class=HTMLResponse, tags=['Authentication'])
async def logged_out_page(request: Request):
    return templates.TemplateResponse("logged_out.html", {"request": request})

@app.get("/saml/metadata", tags=['Authentication'])
async def saml_metadata(request: Request):
    req = await prepare_saml_request(request)
    auth = OneLogin_Saml2_Auth(req, custom_base_path=os.path.join(os.path.dirname(__file__), 'saml_config'))
    settings = auth.get_settings()
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)
    return StarletteResponse(content=metadata, media_type="application/xml") if not errors else JSONResponse(content={'errors': errors}, status_code=500)

# --- Helper Function for AWS Roles ---
def get_role_arn_for_account(account_id: str) -> str | None:
    target_roles_str = os.getenv("AWS_TARGET_ACCOUNTS_ROLES", "")
    if target_roles_str:
        for r_arn in target_roles_str.split(','):
            if f":{account_id}:" in r_arn:
                return r_arn.strip()
    return None

# --- Main Application Routes ---
@app.get("/", response_class=HTMLResponse, name="read_dashboard")
async def read_dashboard(request: Request, user: dict = Depends(get_current_user)):
    if isinstance(user, RedirectResponse): return user
    request.state.now = datetime.now(timezone.utc)
    saml_attributes = user.get("attributes", {})
    group_map_str = os.getenv("GROUP_TO_ACCOUNT_MAP", "")
    group_key = next((k for k in saml_attributes if 'Group' in k), None)
    saml_groups = saml_attributes.get(group_key, [])
    user_groups = saml_groups if isinstance(saml_groups, list) else [saml_groups]
    cache_key = f"dashboard_data_{'_'.join(sorted(user_groups))}"
    
    if cache_key in cache:
        logging.info(f"Cache HIT for dashboard: user='{user.get('email')}'")
        dashboard_data = cache[cache_key]
    else:
        logging.info(f"Cache MISS for dashboard: user='{user.get('email')}'")
        dashboard_data = get_live_eks_data(user_groups, group_map_str)
        if not dashboard_data.get("errors"):
            cache[cache_key] = dashboard_data

    context = {"request": request, "user": user, **dashboard_data}
    return templates.TemplateResponse("dashboard.html", context)

@app.get("/clusters/{account_id}/{region}/{cluster_name}", response_class=HTMLResponse, name="read_cluster_detail")
async def read_cluster_detail(request: Request, account_id: str, region: str, cluster_name: str, user: dict = Depends(get_current_user)):
    if isinstance(user, RedirectResponse): return user
    
    cache_key = f"cluster_{account_id}_{region}_{cluster_name}"
    if cache_key in cache:
        logging.info(f"Cache HIT for cluster detail: {cluster_name}")
        cluster_details = cache[cache_key]
    else:
        logging.info(f"Cache MISS for cluster detail: {cluster_name}")
        try:
            self_account_id = boto3.client('sts').get_caller_identity().get('Account')
        except (ClientError, NoCredentialsError, PartialCredentialsError) as e:
            logging.error(f"Could not determine self account ID from instance metadata: {e}")
            return templates.TemplateResponse("error.html", {"request": request, "errors": ["Could not determine the application's own account ID."]}, status_code=500)
        
        role_arn = None
        if account_id != self_account_id:
            role_arn = get_role_arn_for_account(account_id)
            if not role_arn:
                return templates.TemplateResponse("error.html", {"request": request, "errors": [f"No role ARN for account {account_id} is configured in AWS_TARGET_ACCOUNTS_ROLES."], "reason": "Please check your .env file."}, status_code=404)
        
        cluster_details = get_single_cluster_details(account_id=account_id, region=region, cluster_name=cluster_name, role_arn=role_arn)
        if not cluster_details.get("errors"):
             cache[cache_key] = cluster_details

    context = {"request": request, "user": user, "cluster": cluster_details, "account_id": account_id, "region": region}
    return templates.TemplateResponse("cluster_detail.html", context)

# --- API Routes for Frontend ---
@app.post("/api/refresh-data", tags=["API"])
async def refresh_data(user: dict = Depends(get_current_user)):
    if isinstance(user, JSONResponse): return user
    cache.clear()
    SNAPSHOT_STORE.clear()
    logging.info(f"Cache and Snapshots cleared by user: {user.get('email')}")
    return JSONResponse(content={"status": "success", "message": "Cache and Snapshots cleared."})

@app.post("/api/refresh-cluster/{account_id}/{region}/{cluster_name}", tags=["API"])
async def refresh_cluster_data(account_id: str, region: str, cluster_name: str, user: dict = Depends(get_current_user)):
    if isinstance(user, JSONResponse): return user
    cache_key = f"cluster_{account_id}_{region}_{cluster_name}"
    if cache_key in cache:
        try:
            del cache[cache_key]
            logging.info(f"Cache for cluster {cluster_name} cleared by user: {user.get('email')}")
            return JSONResponse(content={"status": "success", "message": f"Cache for {cluster_name} cleared."})
        except KeyError:
             logging.warning(f"Cache key {cache_key} disappeared before deletion.")
    return JSONResponse(content={"status": "success", "message": "Cluster was not in cache or already removed."})

@app.post("/api/upgrade-nodegroup", tags=["API"])
async def api_upgrade_nodegroup(request: Request, user: dict = Depends(get_current_user)):
    if isinstance(user, JSONResponse): return user
    data = await request.json()
    account_id = data.get("accountId")
    
    role_arn = None
    try:
        self_account_id = boto3.client('sts').get_caller_identity().get('Account')
        if account_id != self_account_id:
            role_arn = get_role_arn_for_account(account_id)
            if not role_arn:
                return JSONResponse(status_code=404, content={"error": f"Role ARN not found for account {account_id}."})
    except (ClientError, NoCredentialsError, PartialCredentialsError) as e:
        return JSONResponse(status_code=500, content={"error": f"Could not determine self-account ID: {e}"})

    result = upgrade_nodegroup_version(account_id, data.get("region"), data.get("clusterName"), data.get("nodegroupName"), role_arn)
    if "error" in result: return JSONResponse(status_code=400, content=result)
    return JSONResponse(content=result)

@app.get("/api/logs/{account_id}/{region}/{cluster_name}/{log_type}", tags=["API"])
async def get_logs(account_id: str, region: str, cluster_name: str, log_type: str, user: dict = Depends(get_current_user)):
    if isinstance(user, JSONResponse): return user
    
    role_arn = None
    try:
        self_account_id = boto3.client('sts').get_caller_identity().get('Account')
        if account_id != self_account_id:
            role_arn = get_role_arn_for_account(account_id)
            if not role_arn:
                return JSONResponse(status_code=404, content={"error": f"Role ARN not found for account {account_id}."})
    except (ClientError, NoCredentialsError, PartialCredentialsError) as e:
        return JSONResponse(status_code=500, content={"error": f"Could not determine application's account ID: {e}"})
            
    log_group_name = f"/aws/eks/{cluster_name}/cluster"
    return StreamingResponse(
        stream_cloudwatch_logs(account_id, region, log_group_name, log_type, role_arn),
        media_type="text/event-stream"
    )

@app.get("/api/metrics/{account_id}/{region}/{cluster_name}", tags=["API"])
async def api_get_cluster_metrics(account_id: str, region: str, cluster_name: str, user: dict = Depends(get_current_user)):
    if isinstance(user, JSONResponse): return user
    role_arn = get_role_arn_for_account(account_id)
    metrics = get_cluster_metrics(account_id, region, cluster_name, role_arn)
    if 'error' in metrics:
        return JSONResponse(content=metrics, status_code=500)
    return JSONResponse(content=metrics)

# --- New API Routes for Added Features ---

@app.get("/api/cost-breakdown/{account_id}/{region}/{cluster_name}", tags=["API"])
async def api_get_cost_breakdown(account_id: str, region: str, cluster_name: str, user: dict = Depends(get_current_user)):
    if isinstance(user, JSONResponse): return user
    role_arn = get_role_arn_for_account(account_id)
    costs = get_cost_breakdown(account_id, region, cluster_name, role_arn)
    if 'error' in costs:
        return JSONResponse(content=costs, status_code=500)
    return JSONResponse(content=costs)

@app.post("/api/cost-what-if/{account_id}/{region}/{cluster_name}", tags=["API"])
async def api_cost_what_if(request: Request, account_id: str, region: str, user: dict = Depends(get_current_user)):
    if isinstance(user, JSONResponse): return user
    data = await request.json()
    result = calculate_what_if_cost(
        region=region,
        current_instance_type=data.get('current_instance_type'),
        target_instance_type=data.get('target_instance_type'),
        instance_count=data.get('instance_count')
    )
    if 'error' in result:
        return JSONResponse(content=result, status_code=400)
    return JSONResponse(content=result)

@app.post("/api/snapshot/{account_id}/{region}/{cluster_name}", tags=["API"])
async def create_snapshot(account_id: str, region: str, cluster_name: str, user: dict = Depends(get_current_user)):
    if isinstance(user, JSONResponse): return user
    role_arn = get_role_arn_for_account(account_id)
    # Fetch fresh, non-cached data for the snapshot
    cluster_details = get_single_cluster_details(account_id, region, cluster_name, role_arn, use_cache=False)
    if cluster_details.get("errors"):
        return JSONResponse(content={"error": f"Failed to fetch cluster data for snapshot: {cluster_details['errors']}"}, status_code=500)

    snapshot_id = f"{cluster_name}_{uuid.uuid4().hex[:8]}"
    SNAPSHOT_STORE[snapshot_id] = {
        "id": snapshot_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cluster_name": cluster_name,
        "data": cluster_details
    }
    logging.info(f"Created snapshot {snapshot_id} for user {user.get('email')}")
    return JSONResponse(content={"status": "success", "id": snapshot_id, "timestamp": SNAPSHOT_STORE[snapshot_id]['timestamp']})

@app.get("/api/snapshots/{account_id}/{region}/{cluster_name}", tags=["API"])
async def list_snapshots(cluster_name: str, user: dict = Depends(get_current_user)):
    if isinstance(user, JSONResponse): return user
    cluster_snapshots = [
        {"id": s["id"], "timestamp": s["timestamp"]}
        for s in SNAPSHOT_STORE.values() if s["cluster_name"] == cluster_name
    ]
    return JSONResponse(content=cluster_snapshots)

def diff_snapshots(base_data, compare_data):
    """Computes the difference between two cluster data snapshots using dictionary access."""
    diffs = {
        "Deployments": {"added": [], "removed": [], "changed": []},
        "Services": {"added": [], "removed": [], "changed": []},
    }

    def create_resource_map(snapshot_data, workload_key, resource_key):
        workloads = snapshot_data.get(workload_key, {})
        if not isinstance(workloads, dict): return {}
        items = workloads.get(resource_key, [])
        if not items: return {}
        return {f"{item['metadata']['namespace']}/{item['metadata']['name']}": item for item in items}

    # Diff Deployments
    base_deps = create_resource_map(base_data, 'workloads', 'deployments')
    compare_deps = create_resource_map(compare_data, 'workloads', 'deployments')

    for name, dep in compare_deps.items():
        if name not in base_deps:
            diffs["Deployments"]["added"].append({"name": dep['metadata']['name'], "namespace": dep['metadata']['namespace']})
        else:
            base_dep = base_deps[name]
            changes = []
            if base_dep['spec']['replicas'] != dep['spec']['replicas']:
                changes.append(f"Replicas: {base_dep['spec']['replicas']} -> {dep['spec']['replicas']}")
            
            base_image = base_dep['spec']['template']['spec']['containers'][0]['image']
            compare_image = dep['spec']['template']['spec']['containers'][0]['image']
            if base_image != compare_image:
                 changes.append(f"Image changed: ...{base_image[-40:]} -> ...{compare_image[-40:]}")
            
            if changes:
                diffs["Deployments"]["changed"].append({"name": dep['metadata']['name'], "namespace": dep['metadata']['namespace'], "diff": changes})
    
    for name, dep in base_deps.items():
        if name not in compare_deps:
            diffs["Deployments"]["removed"].append({"name": dep['metadata']['name'], "namespace": dep['metadata']['namespace']})
    
    # Diff Services
    base_svcs = create_resource_map(base_data, 'workloads', 'services')
    compare_svcs = create_resource_map(compare_data, 'workloads', 'services')
    for name, svc in compare_svcs.items():
        if name not in base_svcs:
            diffs["Services"]["added"].append({"name": svc['metadata']['name'], "namespace": svc['metadata']['namespace']})
    for name, svc in base_svcs.items():
        if name not in compare_svcs:
            diffs["Services"]["removed"].append({"name": svc['metadata']['name'], "namespace": svc['metadata']['namespace']})

    return diffs

@app.get("/api/snapshot-diff", tags=["API"])
async def get_snapshot_diff(base_id: str, compare_id: str, user: dict = Depends(get_current_user)):
    if isinstance(user, JSONResponse): return user
    
    try:
        base_snapshot = SNAPSHOT_STORE.get(base_id)
        compare_snapshot = SNAPSHOT_STORE.get(compare_id)

        if not base_snapshot or not compare_snapshot:
            return JSONResponse(content={"error": "One or both snapshot IDs are invalid."}, status_code=404)
            
        diff_result = diff_snapshots(base_snapshot['data'], compare_snapshot['data'])
        
        return JSONResponse(content=diff_result)
    except Exception as e:
        logging.error(f"Snapshot diff failed for {base_id} vs {compare_id}: {e}", exc_info=True)
        return JSONResponse(status_code=500, content={"error": f"An internal error occurred while comparing snapshots: {str(e)}"})


# --- Main Execution Block ---
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
