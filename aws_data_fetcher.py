# --- START OF FILE aws_data_fetcher.py ---

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from datetime import datetime, timezone, timedelta
from dateutil.relativedelta import relativedelta
import os
import json
from collections import Counter
import time
import base64
import requests
import subprocess
from functools import lru_cache

# --- New Kubernetes & Analysis Imports ---
from kubernetes import client, config
from kubernetes.config.kube_config import KubeConfigLoader
from kubernetes.client.rest import ApiException
import numpy as np
from scipy import stats

# --- EKS Data ---
EKS_EOL_DATES = {
    "1.23": datetime(2024, 6, 4, tzinfo=timezone.utc), "1.24": datetime(2024, 8, 1, tzinfo=timezone.utc),
    "1.25": datetime(2024, 10, 22, tzinfo=timezone.utc), "1.26": datetime(2025, 1, 22, tzinfo=timezone.utc),
    "1.27": datetime(2025, 6, 22, tzinfo=timezone.utc), "1.28": datetime(2025, 7, 22, tzinfo=timezone.utc),
    "1.29": datetime(2025, 11, 1, tzinfo=timezone.utc), "1.30": datetime(2026, 6, 1, tzinfo=timezone.utc),
}
# A conventional tag for associating costs with a cluster. Ensure your resources are tagged.
COST_TAG_KEY = os.getenv("COST_TAG_KEY", "eks:cluster-name")


# --- Utility & Session Management ---

def pp_debug(label, data):
    """Pretty prints data for debugging purposes."""
    try:
        print(f"DEBUG: {label}:\n{json.dumps(data, indent=2, default=str)}")
    except TypeError:
        print(f"DEBUG: {label}: {data} (Could not JSON serialize fully)")

def get_session(role_arn=None):
    """
    Gets a boto3 session, assuming a role if one is provided.
    """
    if not role_arn:
        try:
            boto3.client('sts').get_caller_identity()
            return boto3.Session()
        except (NoCredentialsError, PartialCredentialsError, ClientError) as e:
            print(f"ERROR_GET_SESSION: Default credentials are not configured or invalid. Error: {e}")
            return None

    try:
        sts_client = boto3.client('sts')
        assumed_role_object = sts_client.assume_role(
            RoleArn=role_arn, RoleSessionName=f"eks-dashboard-session-{int(time.time())}"
        )
        creds = assumed_role_object['Credentials']
        return boto3.Session(
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken'],
        )
    except ClientError as e:
        print(f"ERROR_GARS: Could not assume role {role_arn}. Error: {e}")
        return None

# --- NEW Kubernetes Client & Helper Functions ---
def get_k8s_api_client(cluster_name, cluster_endpoint, cluster_ca_data, role_arn=None):
    """Configures and returns a Kubernetes API client for a specific EKS cluster."""
    kube_config_dict = {
        'apiVersion': 'v1',
        'clusters': [{'name': cluster_name, 'cluster': {'server': cluster_endpoint, 'certificate-authority-data': cluster_ca_data}}],
        'contexts': [{'name': cluster_name, 'context': {'cluster': cluster_name, 'user': cluster_name}}],
        'current-context': cluster_name,
        'users': [{'name': cluster_name, 'user': {
            'exec': {
                'apiVersion': 'client.authentication.k8s.io/v1beta1',
                'command': 'aws',
                'args': ['eks', 'get-token', '--cluster-name', cluster_name]
            }
        }}]
    }
    if role_arn:
        kube_config_dict['users'][0]['user']['exec']['args'].extend(['--role-arn', role_arn])

    loader = KubeConfigLoader(config_dict=kube_config_dict)
    cfg = client.Configuration()
    loader.load_and_set(cfg)
    return client.ApiClient(configuration=cfg)

def parse_quantity(s: str):
    """Parses Kubernetes quantities (e.g., '500m', '1024Ki') into a common base unit."""
    if not s: return 0
    s = s.lower()
    if s.endswith('m'): return int(s[:-1]) # CPU millicores
    if s.endswith('ki'): return int(s[:-2]) * 1024 # Memory kibibytes
    if s.endswith('mi'): return int(s[:-2]) * 1024**2
    if s.endswith('gi'): return int(s[:-2]) * 1024**3
    if s.endswith('ti'): return int(s[:-2]) * 1024**4
    if s.isdigit(): return int(s) # Plain CPU cores
    return 0

def get_eks_token(cluster_name: str, role_arn: str = None) -> str:
    """
    Generates an EKS authentication token using the AWS CLI.
    This is used by the requests-based fetchers.
    """
    command = ["aws", "eks", "get-token", "--cluster-name", cluster_name]
    if role_arn: command.extend(["--role-arn", role_arn])
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=30)
        return json.loads(result.stdout)["status"]["token"]
    except Exception as e:
        print(f"ERROR getting EKS token for cluster {cluster_name}: {e}")
        raise

# --- Vulnerability Scanning ---
@lru_cache(maxsize=128)
def scan_image_with_trivy(image_name: str):
    """Scans a container image with Trivy and returns a summary. Requires Trivy to be installed."""
    print(f"Scanning image: {image_name} with Trivy...")
    command = [
        "trivy", "image", "--format", "json",
        "--severity", "CRITICAL,HIGH", "--quiet", "--timeout", "3m", image_name
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=180)

        if result.returncode > 1:
             print(f"Trivy scan failed for {image_name}. Exit code: {result.returncode}. Stderr: {result.stderr}")
             return {"error": f"Trivy scan failed. Is the image public or are you authenticated? Stderr: {result.stderr[:500]}"}

        if not result.stdout.strip() or result.stdout.strip() == "null":
            return {"CRITICAL": 0, "HIGH": 0}

        scan_data = json.loads(result.stdout)
        summary = {"CRITICAL": 0, "HIGH": 0}

        results_list = scan_data if isinstance(scan_data, list) else [scan_data]
        if results_list and results_list[0] and results_list[0].get("Results"):
             for res in results_list[0]["Results"]:
                if res.get("Vulnerabilities"):
                    for vuln in res["Vulnerabilities"]:
                        sev = vuln.get("Severity")
                        if sev in summary:
                            summary[sev] += 1
        return summary
    except FileNotFoundError:
        print("ERROR: 'trivy' command not found. Please install Trivy on the host machine.")
        return {"error": "Trivy not found on server."}
    except json.JSONDecodeError:
        print(f"ERROR decoding Trivy JSON for {image_name}. Stderr: {result.stderr}")
        return {"error": "Failed to decode Trivy output. Image may not exist."}
    except subprocess.TimeoutExpired:
        print(f"ERROR: Trivy scan timed out for image {image_name}")
        return {"error": "Scan timed out."}

# --- Agentless Feature Logic ---
def get_pod_metrics(custom_objects_api):
    """Fetches pod metrics from the Kubernetes Metrics Server."""
    try:
        metrics = custom_objects_api.list_cluster_custom_object("metrics.k8s.io", "v1beta1", "pods")
        # Sum usage across all containers in a pod
        return {f"{m['metadata']['namespace']}/{m['metadata']['name']}": {
            'cpu': sum(parse_quantity(c['usage'].get('cpu', '0m')) for c in m['containers']),
            'memory': sum(parse_quantity(c['usage'].get('memory', '0Ki')) for c in m['containers'])
        } for m in metrics['items']}
    except ApiException as e:
        if e.status == 404:
            print("ERROR: Metrics API (metrics.k8s.io) not found. Is the Metrics Server installed?")
            return {"error": "Metrics Server not found in cluster."}
        print(f"Error fetching pod metrics: {e}")
        return {"error": f"API Error fetching metrics: {e.reason}"}
    except Exception as e:
        print(f"Unexpected error fetching pod metrics: {e}")
        return {"error": f"An unexpected error occurred while fetching metrics: {str(e)}"}


def analyze_workloads(core_v1, apps_v1, pod_metrics):
    """Performs anomaly detection and rightsizing analysis."""
    anomalies, rightsizing = [], []
    try:
        all_pods = core_v1.list_pod_for_all_namespaces(timeout_seconds=60).items
        deployments = apps_v1.list_deployment_for_all_namespaces(timeout_seconds=60).items
    except ApiException as e:
        return {"error": f"Failed to list workloads: {e.reason}", "anomalies": [], "rightsizing": []}

    for dep in deployments:
        dep_name, ns = dep.metadata.name, dep.metadata.namespace
        selector = dep.spec.selector.match_labels
        if not selector: continue

        dep_pods = [p for p in all_pods if p.metadata.namespace == ns and p.metadata.labels and selector.items() <= p.metadata.labels.items()]
        if len(dep_pods) < 3: continue

        restart_counts = [sum(cs.restart_count for cs in (p.status.container_statuses or [])) for p in dep_pods]

        if np.std(restart_counts) > 0 and len(restart_counts) > 1:
            zscores = np.abs(stats.zscore(restart_counts))
            for i, pod in enumerate(dep_pods):
                if zscores[i] > 2.5: # Z-score > 2.5 is a strong outlier
                    anomalies.append({
                        "type": "Excessive Restarts", "severity": "High",
                        "pod": pod.metadata.name, "namespace": ns,
                        "details": f"Pod has {restart_counts[i]} restarts, while the average for this deployment is {np.mean(restart_counts):.1f}."
                    })

        if pod_metrics and "error" not in pod_metrics:
            cpu_usages = [pod_metrics.get(f"{p.metadata.namespace}/{p.metadata.name}", {}).get('cpu', 0) for p in dep_pods]
            
            main_container = dep.spec.template.spec.containers[0] if dep.spec.template.spec.containers else None
            if not main_container or not main_container.resources or not main_container.resources.requests:
                continue

            req_cpu_str = main_container.resources.requests.get('cpu', '0m')
            pod_requests_cpu = parse_quantity(req_cpu_str)

            if pod_requests_cpu > 100: # Only analyze if CPU request is significant (e.g., > 100m)
                p95_cpu = np.percentile([c for c in cpu_usages if c > 0], 95) if any(c > 0 for c in cpu_usages) else 0
                if p95_cpu < pod_requests_cpu * 0.4: # If usage is less than 40% of request
                     rightsizing.append({
                         "workload": dep_name, "namespace": ns, "kind": "Deployment", "metric": "CPU",
                         "current_request": f"{req_cpu_str}",
                         "recommended_request": f"{int(p95_cpu * 1.2)}m", # Recommend P95 + 20% buffer
                     })

    return {"anomalies": anomalies, "rightsizing": rightsizing, "error": None}

# --- Cost Optimization Insights ---
def get_cost_optimization_insights(session, region, cluster_name):
    """Finds potential cost savings for a given cluster."""
    print(f"Searching for cost optimizations for {cluster_name}...")
    insights = []
    ec2 = session.client('ec2', region_name=region)
    elbv2 = session.client('elbv2', region_name=region)
    cluster_tag_filter = {'Name': f'tag:kubernetes.io/cluster/{cluster_name}', 'Values': ['owned']}

    # Check for unattached EBS volumes
    try:
        volumes = ec2.describe_volumes(Filters=[{'Name': 'status', 'Values': ['available']}, cluster_tag_filter])
        for vol in volumes.get('Volumes', []):
            insights.append({
                "title": "Unattached EBS Volume", "severity": "Medium",
                "description": f"Volume {vol['VolumeId']} ({vol['Size']} GiB, Type: {vol['VolumeType']}) is 'available' and not attached to any instance, but is still incurring costs.",
                "recommendation": "Verify the volume is no longer needed and delete it. If needed, consider snapshotting before deletion.", "resource_id": vol['VolumeId']
            })
    except ClientError as e:
        print(f"Warning: Could not check for unattached EBS volumes. Permission might be missing. {e}")

    # Check for idle Load Balancers
    try:
        paginator = elbv2.get_paginator('describe_load_balancers')
        for page in paginator.paginate():
            lb_arns = [lb['LoadBalancerArn'] for lb in page.get('LoadBalancers', [])]
            if not lb_arns: continue
            tags_response = elbv2.describe_tags(ResourceArns=lb_arns)
            for tag_desc in tags_response.get('TagDescriptions', []):
                if any(t['Key'] == f'kubernetes.io/cluster/{cluster_name}' and t['Value'] == 'owned' for t in tag_desc.get('Tags', [])):
                    lb_arn = tag_desc['ResourceArn']
                    lb_name = lb_arn.split('/')[-2]
                    tg_paginator = elbv2.get_paginator('describe_target_groups')
                    is_idle = True
                    for tg_page in tg_paginator.paginate(LoadBalancerArn=lb_arn):
                        for tg in tg_page.get('TargetGroups', []):
                            health = elbv2.describe_target_health(TargetGroupArn=tg['TargetGroupArn'])
                            if any(t.get('TargetHealth', {}).get('State') == 'healthy' for t in health.get('TargetHealthDescriptions',[])):
                                is_idle = False; break
                        if not is_idle: break
                    if is_idle:
                        insights.append({
                            "title": "Idle Load Balancer", "severity": "High",
                            "description": f"Load Balancer {lb_name} appears to have no healthy targets across all its target groups.",
                            "recommendation": "This LB was likely provisioned by a Kubernetes Service. Verify if the Service is still needed. If not, deleting it will deprovision this LB.", "resource_id": lb_name
                        })
    except ClientError as e:
        print(f"Warning: Could not check for idle LBs. Permission might be missing. {e}")
    return insights

# --- Cost Fetcher Function ---
def get_cost_for_clusters(session, cluster_names: list):
    """Fetches cost data from AWS Cost Explorer for a list of clusters, grouped by a specific tag."""
    if not cluster_names: return {}
    cost_client = session.client('ce', region_name='us-east-1')
    start_date = (datetime.now(timezone.utc) - relativedelta(months=1)).strftime('%Y-%m-%d')
    end_date = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    try:
        response = cost_client.get_cost_and_usage(
            TimePeriod={'Start': start_date, 'End': end_date}, Granularity='MONTHLY',
            Filter={"Tags": {"Key": COST_TAG_KEY, "Values": cluster_names, "MatchOptions": ["EQUALS"]}},
            Metrics=['UnblendedCost'], GroupBy=[{'Type': 'TAG', 'Key': COST_TAG_KEY}]
        )
        return {
            group['Keys'][0].split('$')[-1]: f"${float(group['Metrics']['UnblendedCost']['Amount']):,.2f}"
            for group in response.get('ResultsByTime', [])[0].get('Groups', [])
        }
    except ClientError as e:
        if 'is not opted in' in e.response['Error'].get('Message', ''):
            print("ERROR: AWS Cost Explorer is not enabled for this account.")
        else: print(f"ERROR fetching cost data: {e}")
        return {}
    except Exception as e:
        print(f"UNEXPECTED ERROR fetching cost data: {e}")
        return {}


# --- Detailed AWS Fetcher Functions ---
def fetch_managed_nodegroups(eks_client, cluster_name):
    nodegroups_details = []
    try:
        paginator = eks_client.get_paginator('list_nodegroups')
        for page in paginator.paginate(clusterName=cluster_name):
            for ng_name in page.get('nodegroups', []):
                try:
                    ng_desc = eks_client.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng_name).get('nodegroup', {})
                    if ng_desc: nodegroups_details.append(ng_desc)
                except ClientError as e:
                    nodegroups_details.append({"nodegroupName": ng_name, "status": "ERROR_DESCRIBING", "error": str(e)})
    except ClientError as e:
        print(f"ERROR_FNFC_LIST: listing nodegroups for {cluster_name}: {e}")
    return nodegroups_details

def fetch_karpenter_nodes_for_cluster(cluster_name, cluster_endpoint, cluster_ca, role_arn=None):
    print(f"Fetching Karpenter/Auto-Mode nodes for {cluster_name}...")
    karpenter_nodes = []
    ca_path = f"/tmp/{cluster_name}_ca.crt"
    try:
        token = get_eks_token(cluster_name, role_arn)
        headers = {'Authorization': f'Bearer {token}'}
        with open(ca_path, "wb") as f: f.write(base64.b64decode(cluster_ca))
        response = requests.get(f"{cluster_endpoint}/api/v1/nodes", headers=headers, verify=ca_path, timeout=30)
        response.raise_for_status()
        nodes = response.json().get('items', [])
        for node in nodes:
            labels = node['metadata'].get('labels', {})
            if 'karpenter.sh/provisioner-name' in labels or labels.get('eks.amazonaws.com/compute-type') == 'ec2':
                karpenter_nodes.append({
                    "name": node['metadata']['name'], "status": "Ready" if any(c['status'] == 'True' for c in node.get('status',{}).get('conditions',[]) if c['type'] == 'Ready') else "NotReady",
                    "desiredSize": 1, "instanceTypes": [labels.get('node.kubernetes.io/instance-type', 'unknown')], "amiType": "AUTO-MODE",
                    "version": node.get('status',{}).get('nodeInfo',{}).get('kubeletVersion'), "releaseVersion": "N/A",
                    "createdAt": datetime.fromisoformat(node['metadata']['creationTimestamp'].replace("Z", "+00:00")), "is_karpenter_node": True
                })
        print(f"Found {len(karpenter_nodes)} Karpenter/Auto-Mode nodes for {cluster_name}.")
    except Exception as e:
        print(f"ERROR fetching Kubernetes API nodes for {cluster_name}: {e}")
    finally:
        if os.path.exists(ca_path): os.remove(ca_path)
    return karpenter_nodes

def get_kubernetes_workloads_and_map(cluster_name, cluster_endpoint, cluster_ca, role_arn=None):
    """Fetches detailed workload info and builds a relationship map for visualization."""
    print(f"Fetching full Kubernetes object map for {cluster_name}...")
    k8s_data = {"pods": [], "services": [], "ingresses": [], "nodes": [], "map_nodes": [], "map_edges": [], "vulnerable_images": {}, "error": None}
    ca_path = f"/tmp/{cluster_name}_ca.crt"
    try:
        token = get_eks_token(cluster_name, role_arn)
        headers = {'Authorization': f'Bearer {token}'}
        with open(ca_path, "wb") as f: f.write(base64.b64decode(cluster_ca))

        endpoints = {"pods": "/api/v1/pods", "services": "/api/v1/services", "ingresses": "/apis/networking.k8s.io/v1/ingresses", "nodes": "/api/v1/nodes"}
        for key, endpoint in endpoints.items():
            res = requests.get(f"{cluster_endpoint}{endpoint}", headers=headers, verify=ca_path, timeout=45); res.raise_for_status()
            k8s_data[key] = res.json().get('items', [])

        map_nodes, map_edges = [], []
        now = datetime.now(timezone.utc)

        for ing in k8s_data["ingresses"]:
            map_nodes.append({"id": ing["metadata"]["uid"], "label": ing["metadata"]["name"], "group": "ingress", "title": f"<b>Ingress</b><br>Namespace: {ing['metadata']['namespace']}"})
            for rule in ing.get("spec", {}).get("rules", []):
                for path in rule.get("http", {}).get("paths", []):
                    svc_name = path["backend"]["service"]["name"]
                    for svc in k8s_data["services"]:
                        if svc["metadata"]["name"] == svc_name and svc["metadata"]["namespace"] == ing["metadata"]["namespace"]:
                            map_edges.append({"from": ing["metadata"]["uid"], "to": svc["metadata"]["uid"]}); break
        for svc in k8s_data["services"]:
            map_nodes.append({"id": svc["metadata"]["uid"], "label": svc["metadata"]["name"], "group": "svc", "title": f"<b>Service</b><br>Namespace: {svc['metadata']['namespace']}<br>Type: {svc['spec']['type']}"})
        for pod in k8s_data["pods"]:
            pod['age'] = str(now - datetime.fromisoformat(pod['metadata']['creationTimestamp'].replace("Z", "+00:00"))).split('.')[0]
            pod['restarts'] = sum(cs.get('restartCount', 0) for cs in pod.get('status', {}).get('containerStatuses', []))
            map_nodes.append({"id": pod["metadata"]["uid"], "label": pod["metadata"]["name"], "group": "pod", "title": f"<b>Pod</b><br>Status: {pod['status']['phase']}<br>Node: {pod['spec'].get('nodeName', 'N/A')}"})
            if pod["spec"].get("nodeName"):
                for n in k8s_data["nodes"]:
                    if n["metadata"]["name"] == pod["spec"]["nodeName"]:
                        map_edges.append({"from": pod["metadata"]["uid"], "to": n["metadata"]["uid"]}); break
            pod_labels = pod["metadata"].get("labels", {})
            if pod_labels:
                for svc in k8s_data["services"]:
                    selector = svc["spec"].get("selector", {})
                    if selector and svc["metadata"]["namespace"] == pod["metadata"]["namespace"] and all(pod_labels.get(k) == v for k, v in selector.items()):
                        map_edges.append({"from": svc["metadata"]["uid"], "to": pod["metadata"]["uid"]})
            pod['vulnerability_summary'] = {"CRITICAL": 0, "HIGH": 0, "error": None}
            for container in pod["spec"].get("containers", []) + pod["spec"].get("initContainers", []):
                image_name = container["image"]
                scan_result = scan_image_with_trivy(image_name)
                if scan_result.get("error"): pod['vulnerability_summary']["error"] = scan_result["error"]
                else:
                    pod['vulnerability_summary']["CRITICAL"] += scan_result["CRITICAL"]
                    pod['vulnerability_summary']["HIGH"] += scan_result["HIGH"]
                    if scan_result["CRITICAL"] > 0 or scan_result["HIGH"] > 0:
                        k8s_data["vulnerable_images"].setdefault(image_name, {"CRITICAL": 0, "HIGH": 0})["CRITICAL"] += scan_result["CRITICAL"]
                        k8s_data["vulnerable_images"].setdefault(image_name, {"CRITICAL": 0, "HIGH": 0})["HIGH"] += scan_result["HIGH"]
        for n in k8s_data["nodes"]:
            map_nodes.append({"id": n["metadata"]["uid"], "label": n["metadata"]["name"], "group": "node", "title": f"<b>Node</b><br>Instance Type: {n['metadata']['labels'].get('node.kubernetes.io/instance-type', 'N/A')}"})
        k8s_data["map_nodes"], k8s_data["map_edges"] = map_nodes, map_edges
    except Exception as e:
        k8s_data['error'] = str(e)
    finally:
        if os.path.exists(ca_path): os.remove(ca_path)
    return k8s_data

def fetch_addons_for_cluster(eks_client, cluster_name):
    addons_details = []
    try:
        for page in eks_client.get_paginator('list_addons').paginate(clusterName=cluster_name):
            for addon_name in page.get('addons', []):
                try:
                    addon_desc = eks_client.describe_addon(clusterName=cluster_name, addonName=addon_name).get('addon', {})
                    if addon_desc:
                        addon_desc['health_status'] = "HEALTHY" if not addon_desc.get('health', {}).get('issues') else "HAS_ISSUES"
                        addons_details.append(addon_desc)
                except ClientError as e: print(f"ERROR_FAFC_DESC: addon {addon_name}: {e}")
    except ClientError as e: print(f"ERROR_FAFC_LIST: for {cluster_name}: {e}")
    return addons_details

def fetch_fargate_profiles_for_cluster(eks_client, cluster_name):
    profiles = []
    try:
        for page in eks_client.get_paginator('list_fargate_profiles').paginate(clusterName=cluster_name):
            profiles.extend(page.get('fargateProfileNames', []))
    except ClientError as e: print(f"ERROR_FFPFC: for {cluster_name}: {e}")
    return [{"name": p} for p in profiles]

def fetch_oidc_provider_for_cluster(cluster_raw):
    return cluster_raw.get('identity', {}).get('oidc', {}).get('issuer')


# --- Action and Streaming Functions ---
def manage_workload(account_id, region, cluster_name, role_arn, action_details):
    """Performs management actions (scale, restart, delete) on Kubernetes workloads."""
    print(f"Performing action {action_details['action']} on {action_details['kind']} {action_details['name']}...")
    try:
        session = get_session(role_arn)
        if not session: return {"error": "Failed to get AWS session."}
        
        eks_client = session.client('eks', region_name=region)
        cluster_raw = eks_client.describe_cluster(name=cluster_name).get('cluster', {})
        if not cluster_raw.get("endpoint") or not cluster_raw.get("certificateAuthority", {}).get("data"):
            return {"error": "Cannot get K8s client, missing endpoint or CA data."}

        api_client = get_k8s_api_client(cluster_name, cluster_raw["endpoint"], cluster_raw["certificateAuthority"]["data"], role_arn)
        apps_v1 = client.AppsV1Api(api_client)
        core_v1 = client.CoreV1Api(api_client)
        
        ns, kind, name, action = action_details['namespace'], action_details['kind'], action_details['name'], action_details['action']

        if kind == 'Deployment':
            if action == 'scale':
                replicas = action_details['replicas']
                apps_v1.patch_namespaced_deployment_scale(name=name, namespace=ns, body={"spec": {"replicas": replicas}})
                return {"success": f"Deployment {name} scaled to {replicas} replicas."}
            elif action == 'restart':
                patch_body = {"spec": {"template": {"metadata": {"annotations": {"kubectl.kubernetes.io/restartedAt": datetime.now(timezone.utc).isoformat()}}}}}
                apps_v1.patch_namespaced_deployment(name=name, namespace=ns, body=patch_body)
                return {"success": f"Deployment {name} rollout restarted."}

        elif kind == 'Pod' and action == 'delete_pod':
            core_v1.delete_namespaced_pod(name=name, namespace=ns)
            return {"success": f"Pod {name} deleted."}

        return {"error": f"Unsupported action '{action}' for kind '{kind}'."}

    except ApiException as e:
        error_body = json.loads(e.body) if e.body and e.body.startswith('{') else {}
        return {"error": f"K8s API Error: {error_body.get('message', e.reason)} (Status: {e.status})"}
    except Exception as e:
        return {"error": f"An unexpected error occurred: {str(e)}"}

def upgrade_nodegroup_version(account_id, region, cluster_name, nodegroup_name, role_arn=None):
    """Initiates an upgrade for a managed nodegroup."""
    session = get_session(role_arn)
    if not session: return {"error": f"Failed to get session for account {account_id}."}
    try:
        eks_client = session.client('eks', region_name=region)
        response = eks_client.update_nodegroup_version(clusterName=cluster_name, nodegroupName=nodegroup_name)
        return {"success": True, "updateId": response.get('update', {}).get('id'), "message": "Nodegroup upgrade initiated."}
    except ClientError as e:
        return {"error": e.response['Error']['Message']}

def stream_cloudwatch_logs(account_id, region, log_group_name, log_type_from_ui, role_arn=None):
    log_stream_prefix_map = {'api': 'kube-apiserver-', 'audit': 'kube-apiserver-audit-', 'authenticator': 'authenticator-', 'controllerManager': 'kube-controller-manager-', 'scheduler': 'kube-scheduler-'}
    log_type_prefix = log_stream_prefix_map.get(log_type_from_ui)
    if not log_type_prefix: yield f"data: {json.dumps({'error': f'Invalid log type: {log_type_from_ui}'})}\n\n"; return

    session = get_session(role_arn)
    if not session: yield f"data: {json.dumps({'error': 'Failed to get session.'})}\n\n"; return
    logs_client = session.client('logs', region_name=region)
    try:
        paginator = logs_client.get_paginator('describe_log_streams')
        all_streams = [s for p in paginator.paginate(logGroupName=log_group_name, logStreamNamePrefix=log_type_prefix) for s in p.get('logStreams', [])]
        if not all_streams: yield f"data: {json.dumps({'message': f'No log streams for \"{log_type_from_ui}\".'})}\n\n"; return
        
        latest_stream = max(all_streams, key=lambda s: s.get('lastEventTimestamp', 0))
        start_time = int((datetime.now(timezone.utc) - timedelta(minutes=10)).timestamp() * 1000)
        event_count = 0
        for page in logs_client.get_paginator('filter_log_events').paginate(logGroupName=log_group_name, logStreamNames=[latest_stream['logStreamName']], startTime=start_time, interleaved=True):
            for event in page['events']:
                event_count += 1
                yield f"data: {json.dumps(event)}\n\n"
            time.sleep(1)
        if event_count == 0: yield f"data: {json.dumps({'message': 'No new log events in last 10 minutes.'})}\n\n"
    except ClientError as e: yield f"data: {json.dumps({'error': e.response['Error']['Message']})}\n\n"
    except Exception as e: yield f"data: {json.dumps({'error': f'Unexpected error: {e}'})}\n\n"

def get_cluster_metrics(account_id, region, cluster_name, role_arn=None):
    session = get_session(role_arn)
    if not session: return {"error": f"Failed to get session for account {account_id}."}
    cw_client = session.client('cloudwatch', region_name=region)
    metric_defs = {'requests': ('apiserver_request_total','Sum'), 'requests_4xx': ('apiserver_request_total_4XX','Sum'), 'requests_5xx': ('apiserver_request_total_5XX','Sum'), 'requests_429': ('apiserver_request_total_429','Sum'), 'storage_size': ('apiserver_storage_size_bytes','Average'), 'scheduler_attempts_scheduled': ('scheduler_schedule_attempts_SCHEDULED','Sum'), 'scheduler_attempts_unschedulable': ('scheduler_schedule_attempts_UNSCHEDULABLE','Sum'), 'scheduler_attempts_error': ('scheduler_schedule_attempts_ERROR','Sum'), 'pending_pods_gated': ('scheduler_pending_pods_GATED','Average'), 'pending_pods_unschedulable': ('scheduler_pending_pods_UNSCHEDULABLE','Average'), 'pending_pods_activeq': ('scheduler_pending_pods_ACTIVEQ','Average'), 'pending_pods_backoff': ('scheduler_pending_pods_BACKOFF','Average'), 'latency_get': ('apiserver_request_duration_seconds_GET_P99','Average'), 'latency_post': ('apiserver_request_duration_seconds_POST_P99','Average'), 'latency_put': ('apiserver_request_duration_seconds_PUT_P99','Average'), 'latency_delete': ('apiserver_request_duration_seconds_DELETE_P99','Average'), 'inflight_mutating': ('apiserver_current_inflight_requests_MUTATING','Average'), 'inflight_readonly': ('apiserver_current_inflight_requests_READONLY','Average')}
    queries = [{'Id': f'm{i}', 'Label': k, 'MetricStat': {'Metric': {'Namespace': 'ContainerInsights', 'MetricName': v[0], 'Dimensions': [{'Name': 'ClusterName', 'Value': cluster_name}]}, 'Period': 300, 'Stat': v[1]}, 'ReturnData': True} for i, (k, v) in enumerate(metric_defs.items())]
    try:
        resp = cw_client.get_metric_data(MetricDataQueries=queries, StartTime=datetime.now(timezone.utc) - timedelta(hours=3), EndTime=datetime.now(timezone.utc), ScanBy='TimestampDescending')
        return {res['Label']: {'timestamps': [ts.isoformat() for ts in res['Timestamps']], 'values': res['Values']} for res in resp['MetricDataResults']}
    except ClientError as e: return {'error': f"Could not fetch metrics. Ensure Container Insights is enabled. Error: {e.response['Error']['Message']}"}
    except Exception as e: return {'error': f'Unexpected error fetching metrics: {e}'}

# --- Security Insights ---
def get_security_insights(cluster_raw, eks_client):
    insights = {}
    insights['secrets_encrypted'] = {"status": any(cfg.get('provider', {}).get('keyArn') for cfg in cluster_raw.get('encryptionConfig', [])), "description": "Checks if envelope encryption for Kubernetes secrets is enabled with a KMS key."}
    insights['public_endpoint'] = {"status": not cluster_raw.get('resourcesVpcConfig', {}).get('endpointPublicAccess', False), "description": "Checks if the cluster's API server endpoint is private (best practice)."}
    all_logs, enabled_logs = ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler'], cluster_raw.get('logging', {}).get('clusterLogging', [{}])[0].get('types', [])
    insights['logging_enabled'] = {"status": all(lt in enabled_logs for lt in all_logs), "missing_logs": [lt for lt in all_logs if lt not in enabled_logs], "description": "Checks if all control plane log types are enabled."}
    insights['latest_platform_version'] = {"status": False, "current": "N/A", "latest": "N/A", "description": "Checks if the cluster is running the latest EKS platform version."}
    try: eks_client.describe_update(name=cluster_raw['name'], updateId='dummy-id-for-platform-version')
    except ClientError as e:
        if "Latest platform version for" in (msg := e.response['Error'].get('Message', '')):
            latest_pv, current_pv = msg.split(" is ")[-1].strip(), cluster_raw.get('platformVersion')
            insights['latest_platform_version'].update({"status": latest_pv == current_pv, "current": current_pv, "latest": latest_pv})
    return insights

# --- Main Data Aggregation Functions ---
def _process_cluster_data(c_raw, with_details=False, eks_client=None, role_arn=None, session=None):
    now, ninety_days_from_now = datetime.now(timezone.utc), datetime.now(timezone.utc) + timedelta(days=90)
    version = c_raw.get("version", "Unknown")
    eol_date = EKS_EOL_DATES.get(version)
    cluster_data = {
        "name": c_raw.get("name"), "arn": c_raw.get("arn"), "account_id": c_raw.get("arn", "::::").split(':')[4],
        "version": version, "platformVersion": c_raw.get("platformVersion"), "status": c_raw.get("status", "Unknown"),
        "region": c_raw.get("region"), "createdAt": c_raw.get("createdAt", now), "tags": c_raw.get("tags", {}),
        "health_issues": c_raw.get("health", {}).get("issues", []),
        "health_status_summary": "HEALTHY" if not c_raw.get("health", {}).get("issues", []) else "HAS_ISSUES",
        "upgrade_insight_status": "NEEDS_ATTENTION" if version != "Unknown" and version < "1.29" else "PASSING",
        "is_nearing_eol_90_days": bool(eol_date and eol_date <= ninety_days_from_now and eol_date > now),
        "cost_30d": "N/A",
    }
    if with_details and eks_client and session:
        cluster_name = c_raw["name"]
        cluster_data['cost_30d'] = get_cost_for_clusters(session, [cluster_name]).get(cluster_name, "N/A")
        managed_nodegroups_raw = fetch_managed_nodegroups(eks_client, cluster_name)
        karpenter_nodes_raw, cluster_data["workloads"], cluster_data['deployments'], cluster_data['pods'], cluster_data['analysis'] = [], {"error": "Missing endpoint or CA data."}, [], [], {"error": "Missing endpoint or CA data."}
        
        # All Kubernetes API calls happen here
        if c_raw.get("endpoint") and c_raw.get("certificateAuthority", {}).get("data"):
            endpoint, ca_data = c_raw["endpoint"], c_raw["certificateAuthority"]["data"]
            karpenter_nodes_raw = fetch_karpenter_nodes_for_cluster(cluster_name, endpoint, ca_data, role_arn)
            cluster_data["workloads"] = get_kubernetes_workloads_and_map(cluster_name, endpoint, ca_data, role_arn)

            # Integrate agentless analysis
            try:
                api_client = get_k8s_api_client(cluster_name, endpoint, ca_data, role_arn)
                core_v1, apps_v1, custom_objects_api = client.CoreV1Api(api_client), client.AppsV1Api(api_client), client.CustomObjectsApi(api_client)
                cluster_data['deployments'] = apps_v1.list_deployment_for_all_namespaces().items
                cluster_data['pods'] = core_v1.list_pod_for_all_namespaces().items
                pod_metrics = get_pod_metrics(custom_objects_api)
                cluster_data['analysis'] = {"error": pod_metrics["error"]} if "error" in pod_metrics else analyze_workloads(core_v1, apps_v1, pod_metrics)
            except Exception as e:
                print(f"Failed to perform agentless analysis for {cluster_name}: {e}")
                cluster_data['analysis'] = {"error": f"Failed during K8s client interaction: {e}"}
        
        processed_nodegroups = [{"name": ng.get("nodegroupName"), "status": ng.get("status"), "amiType": ng.get("amiType"), "instanceTypes": ng.get("instanceTypes", []), "releaseVersion": ng.get("releaseVersion"), "version": ng.get("version"), "createdAt": ng.get("createdAt"), "desiredSize": ng.get("scalingConfig", {}).get("desiredSize"), "is_karpenter_node": False} for ng in managed_nodegroups_raw]
        processed_nodegroups.extend(karpenter_nodes_raw)

        cluster_data.update({
            "nodegroups_data": processed_nodegroups, "addons": fetch_addons_for_cluster(eks_client, cluster_name),
            "fargate_profiles": fetch_fargate_profiles_for_cluster(eks_client, cluster_name), "oidc_provider_url": fetch_oidc_provider_for_cluster(c_raw),
            "networking": c_raw.get("resourcesVpcConfig", {}), "security_insights": get_security_insights(c_raw, eks_client),
            "cost_insights": get_cost_optimization_insights(session, c_raw['region'], cluster_name)
        })
    return cluster_data

def get_live_eks_data(user_groups: list[str] | None, group_map_str: str):
    group_to_account_list = {}
    if group_map_str:
        for mapping in group_map_str.split(','):
            try:
                group, account_id = [x.strip() for x in mapping.strip().split(':')]
                group_to_account_list.setdefault(group, []).append(account_id)
            except ValueError: print(f"WARNING: Invalid mapping: '{mapping}'")
    accessible_accounts = {acc for grp in user_groups for acc in group_to_account_list.get(grp, [])} if user_groups is not None else {acc for acc_list in group_to_account_list.values() for acc in acc_list}
    all_possible_accounts = [{'role_arn': r.strip(), 'id': r.strip().split(':')[4]} for r in os.getenv("AWS_TARGET_ACCOUNTS_ROLES", "").split(',') if r.strip()]
    try:
        primary_account_id = boto3.client('sts').get_caller_identity().get('Account')
        if primary_account_id not in [acc['id'] for acc in all_possible_accounts]: all_possible_accounts.append({'role_arn': None, 'id': primary_account_id})
    except Exception as e: print(f"WARNING: Could not determine primary account ID: {e}")
    accounts_to_scan = [acc for acc in all_possible_accounts if acc['id'] in accessible_accounts]
    if not accounts_to_scan and group_to_account_list: return {"clusters": [], "quick_info": {}, "errors": ["User has no access to any configured AWS accounts."]}
    
    all_clusters_raw, errors, clusters_to_describe = [], [], []
    for account in accounts_to_scan:
        session = get_session(account.get('role_arn'))
        if not session: errors.append(f"Failed session for account {account['id']}."); continue
        for region in [r.strip() for r in os.getenv("AWS_REGIONS", os.getenv("AWS_DEFAULT_REGION", "us-east-1")).split(',') if r.strip()]:
            try:
                for name in [n for p in session.client('eks', region_name=region).get_paginator('list_clusters').paginate() for n in p.get('clusters', [])]:
                    clusters_to_describe.append({'name': name, 'region': region, 'account': account, 'session': session})
            except Exception as e: errors.append(f"Error listing clusters in {account['id']}/{region}: {e}")
    for cluster_info in clusters_to_describe:
        try:
            desc = cluster_info['session'].client('eks', region_name=cluster_info['region']).describe_cluster(name=cluster_info['name']).get('cluster', {}); desc['region'] = cluster_info['region']
            all_clusters_raw.append(desc)
        except Exception as e: errors.append(f"Error describing {cluster_info['name']}: {e}")
    
    processed_clusters = [_process_cluster_data(c) for c in all_clusters_raw]
    clusters_by_account = {}
    for c in processed_clusters: clusters_by_account.setdefault(c['account_id'], []).append(c['name'])
    total_cost = 0.0
    for account in accounts_to_scan:
        session = get_session(account.get('role_arn'))
        if session and (names := clusters_by_account.get(account['id'])):
            cost_map = get_cost_for_clusters(session, names)
            for c in processed_clusters:
                if c['account_id'] == account['id'] and (cost_str := cost_map.get(c['name'])):
                    c['cost_30d'] = cost_str; total_cost += float(cost_str.replace('$', '').replace(',', ''))
    for c in processed_clusters: c['createdAt'] = c['createdAt'].isoformat() if isinstance(c.get('createdAt'), datetime) else c.get('createdAt')
    return {"clusters": processed_clusters, "errors": errors, "quick_info": {"total_clusters": len(processed_clusters), "total_cost_30d": f"${total_cost:,.2f}", "clusters_with_health_issues": sum(1 for c in processed_clusters if c["health_issues"]), "clusters_with_upgrade_insights_attention": sum(1 for c in processed_clusters if c["upgrade_insight_status"] == "NEEDS_ATTENTION"), "clusters_nearing_eol_90_days": sum(1 for c in processed_clusters if c["is_nearing_eol_90_days"]), "accounts_running_kubernetes_clusters": len({c["account_id"] for c in processed_clusters}), "regions_running_kubernetes_clusters": len({c["region"] for c in processed_clusters})}}

def get_single_cluster_details(account_id, region, cluster_name, role_arn=None):
    """Fetches comprehensive details for a single EKS cluster."""
    session = get_session(role_arn)
    if not session: return {"errors": [f"Failed to get session for account {account_id}."]}
    try:
        eks_client = session.client('eks', region_name=region)
        cluster_raw = eks_client.describe_cluster(name=cluster_name).get('cluster', {})
        if not cluster_raw: return {"errors": [f"Cluster {cluster_name} not found."]}
        cluster_raw['region'] = region
        return _process_cluster_data(cluster_raw, with_details=True, eks_client=eks_client, role_arn=role_arn, session=session)
    except Exception as e: return {"name": cluster_name, "errors": [f"Error fetching details for cluster {cluster_name}: {e}"]}
