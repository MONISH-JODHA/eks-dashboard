from fastapi import FastAPI, Request, Form, Depends, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
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
import asyncio

# SAML specific imports
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils

# Kubernetes imports for streaming
from kubernetes import client, config, watch, stream
from kubernetes.client.rest import ApiException

# Your existing data fetcher functions
from aws_data_fetcher import (
    get_live_eks_data,
    get_single_cluster_details,
    upgrade_nodegroup_version,
    get_cluster_metrics,
    get_k8s_api_client
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
        if "/api/" in request.url.path or "/ws/" in request.url.path:
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

# --- Common Data Fetching Logic ---
def get_dashboard_data(user: dict):
    saml_attributes = user.get("attributes", {})
    group_map_str = os.getenv("GROUP_TO_ACCOUNT_MAP", "")
    group_key = next((k for k in saml_attributes if 'Group' in k), None)
    saml_groups = saml_attributes.get(group_key, [])
    user_groups = saml_groups if isinstance(saml_groups, list) else [saml_groups]
    cache_key = f"dashboard_data_{'_'.join(sorted(user_groups))}"
    
    if cache_key in cache:
        logging.info(f"Cache HIT for dashboard data: user='{user.get('email')}'")
        dashboard_data = cache[cache_key]
    else:
        logging.info(f"Cache MISS for dashboard data: user='{user.get('email')}'")
        dashboard_data = get_live_eks_data(user_groups, group_map_str)
        if not dashboard_data.get("errors"):
            cache[cache_key] = dashboard_data
    return dashboard_data

# --- Main Application Routes ---
@app.get("/", response_class=HTMLResponse, name="read_dashboard")
async def read_dashboard(request: Request, user: dict = Depends(get_current_user)):
    if isinstance(user, RedirectResponse): return user
    request.state.now = datetime.now(timezone.utc)
    dashboard_data = get_dashboard_data(user)
    context = {"request": request, "user": user, **dashboard_data}
    return templates.TemplateResponse("dashboard.html", context)

@app.get("/clusters", response_class=HTMLResponse, name="list_clusters")
async def list_clusters(request: Request, user: dict = Depends(get_current_user)):
    if isinstance(user, RedirectResponse): return user
    request.state.now = datetime.now(timezone.utc)
    dashboard_data = get_dashboard_data(user)
    context = {"request": request, "user": user, **dashboard_data}
    return templates.TemplateResponse("clusters.html", context)

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
            self_account_id_sts = boto3.client('sts').get_caller_identity().get('Account')
        except (ClientError, NoCredentialsError, PartialCredentialsError) as e:
            logging.warning(f"Could not determine self account ID from instance metadata: {e}")
            self_account_id_sts = None

        role_arn = None
        if account_id != self_account_id_sts:
            role_arn = get_role_arn_for_account(account_id)
            if not role_arn:
                err_msg = f"No role ARN for account {account_id} is configured in AWS_TARGET_ACCOUNTS_ROLES."
                logging.error(err_msg)
                return templates.TemplateResponse("error.html", {"request": request, "errors": [err_msg], "reason": "Please check your .env file."}, status_code=404)
        
        cluster_details = get_single_cluster_details(account_id=account_id, region=region, cluster_name=cluster_name, role_arn=role_arn)
        if not cluster_details.get("errors"):
             cache[cache_key] = cluster_details

    context = {"request": request, "user": user, "cluster": cluster_details, "account_id": account_id, "region": region}
    return templates.TemplateResponse("cluster_detail.html", context)


# --- API & WebSocket Routes ---

@app.post("/api/refresh-data", tags=["API"])
async def refresh_data(user: dict = Depends(get_current_user)):
    if isinstance(user, JSONResponse): return user
    cache.clear()
    logging.info(f"Cache cleared by user: {user.get('email')}")
    return JSONResponse(content={"status": "success", "message": "Cache cleared."})

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
    
    role_arn = get_role_arn_for_account(account_id)
    result = upgrade_nodegroup_version(account_id, data.get("region"), data.get("clusterName"), data.get("nodegroupName"), role_arn)
    if "error" in result: return JSONResponse(status_code=400, content=result)
    return JSONResponse(content=result)

@app.get("/api/metrics/{account_id}/{region}/{cluster_name}", tags=["API"])
async def api_get_cluster_metrics(account_id: str, region: str, cluster_name: str, user: dict = Depends(get_current_user)):
    if isinstance(user, JSONResponse): return user
    role_arn = get_role_arn_for_account(account_id)
    metrics = get_cluster_metrics(account_id, region, cluster_name, role_arn)
    if 'error' in metrics:
        return JSONResponse(content=metrics, status_code=500)
    return JSONResponse(content=metrics)

@app.websocket("/ws/logs/{account_id}/{region}/{cluster_name}/{namespace}/{pod_name}")
async def websocket_log_stream(websocket: WebSocket, account_id: str, region: str, cluster_name: str, namespace: str, pod_name: str):
    await websocket.accept()
    role_arn = get_role_arn_for_account(account_id)
    
    try:
        # Get cluster info from cache or fresh fetch to get endpoint details
        cluster_details = get_single_cluster_details(account_id, region, cluster_name, role_arn)
        if cluster_details.get("errors"):
            await websocket.send_text(f"ERROR: Could not get cluster details: {cluster_details['errors']}")
            return

        cluster_endpoint = cluster_details.get('endpoint')
        if not cluster_endpoint:
            raise KeyError("Cluster endpoint URL not found in cluster details.")

        api_client = get_k8s_api_client(cluster_name, cluster_endpoint, cluster_details['certificateAuthority']['data'], region, role_arn)
        core_v1 = client.CoreV1Api(api_client)

        container_to_log = None
        try:
            pod_details = core_v1.read_namespaced_pod(name=pod_name, namespace=namespace)
            if pod_details.spec.containers:
                container_to_log = pod_details.spec.containers[0].name
                # Check for multiple containers and inform the user
                if len(pod_details.spec.containers) > 1:
                    await websocket.send_text(f"\x1b[33mPod has multiple containers. Tailing logs for the first container: '{container_to_log}'...\x1b[0m\r\n")
        except ApiException as e:
            await websocket.send_text(f"\n--- ERROR: Could not get pod details to determine container name. Reason: {e.reason} ---")
            return

        log_stream = stream.stream(core_v1.read_namespaced_pod_log, name=pod_name, namespace=namespace, container=container_to_log, follow=True, _preload_content=False)

        while log_stream.is_open():
            try:
                line = log_stream.readline()
                if line:
                    await websocket.send_text(line)
                else: # No new data, brief pause
                    await asyncio.sleep(0.1)
            except Exception:
                break # Stream closed or error
    except Exception as e:
        logging.error(f"Log stream error for {pod_name}: {e}")
        await websocket.send_text(f"\n--- ERROR: Could not start log stream. Reason: {e} ---")
    finally:
        await websocket.close()
        logging.info(f"Log stream for {pod_name} closed.")

@app.websocket("/ws/events/{account_id}/{region}/{cluster_name}")
async def websocket_event_stream(websocket: WebSocket, account_id: str, region: str, cluster_name: str):
    await websocket.accept()
    role_arn = get_role_arn_for_account(account_id)
    w = None
    api_client = None

    try:
        cluster_details = get_single_cluster_details(account_id, region, cluster_name, role_arn)
        if cluster_details.get("errors"):
            await websocket.send_text(json.dumps({"type": "ERROR", "message": f"Could not get cluster details: {cluster_details['errors']}"}))
            return

        cluster_endpoint = cluster_details.get('endpoint')
        if not cluster_endpoint:
            raise KeyError("Cluster endpoint URL not found in cluster details.")

        api_client = get_k8s_api_client(cluster_name, cluster_endpoint, cluster_details['certificateAuthority']['data'], region, role_arn)
        core_v1 = client.CoreV1Api(api_client)
        w = watch.Watch()
        
        # --- FIX: Sanitize the event object before sending it ---
        for event in w.stream(core_v1.list_event_for_all_namespaces, timeout_seconds=3600):
            # The 'raw_object' contains the full event data as a dictionary
            # The 'object' is a kubernetes model object (e.g., V1Event)
            # We need to serialize the model object to a dict before sending as JSON
            sanitized_event = api_client.sanitize_for_serialization(event['object'])
            
            # We wrap it in the same structure that the watch stream provides
            payload = {'type': event['type'], 'object': sanitized_event}
            await websocket.send_text(json.dumps(payload))

    except WebSocketDisconnect:
        logging.info(f"Event stream for {cluster_name} disconnected.")
    except Exception as e:
        logging.error(f"Event stream error for {cluster_name}: {e}")
        try:
            # Ensure the error message is a string for JSON serialization
            await websocket.send_text(json.dumps({"type": "ERROR", "message": f"Stream failed: {str(e)}"}))
        except:
            pass # Websocket might be already closed
    finally:
        if w:
            w.stop()
        # No need to close the api_client explicitly
        await websocket.close()
        logging.info(f"Event stream for {cluster_name} closed.")

# --- Main Execution Block ---
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True, ws="wsproto")
