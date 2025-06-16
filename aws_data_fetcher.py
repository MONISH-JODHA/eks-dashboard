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

def get_eks_token(cluster_name: str, role_arn: str = None) -> str:
    """
    Generates an EKS authentication token using the AWS CLI.
    """
    command = ["aws", "eks", "get-token", "--cluster-name", cluster_name]
    if role_arn: command.extend(["--role-arn", role_arn])
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=30)
        return json.loads(result.stdout)["status"]["token"]
    except Exception as e:
        print(f"ERROR getting EKS token for cluster {cluster_name}: {e}")
        raise

# --- NEW: Vulnerability Scanning ---
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

# --- NEW: Cost Optimization Insights ---
def get_cost_optimization_insights(session, region, cluster_name):
    """Finds potential cost savings for a given cluster."""
    print(f"Searching for cost optimizations for {cluster_name}...")
    insights = []
    ec2 = session.client('ec2', region_name=region)
    elbv2 = session.client('elbv2', region_name=region)
    # This tag is standard for resources created by the AWS Load Balancer Controller
    cluster_tag_filter = {'Name': f'tag:kubernetes.io/cluster/{cluster_name}', 'Values': ['owned']}

    # Check for unattached EBS volumes
    try:
        volumes = ec2.describe_volumes(Filters=[{'Name': 'status', 'Values': ['available']}, cluster_tag_filter])
        for vol in volumes.get('Volumes', []):
            insights.append({
                "title": "Unattached EBS Volume", "severity": "Medium",
                "description": f"Volume {vol['VolumeId']} ({vol['Size']} GiB, Type: {vol['VolumeType']}) is 'available' and not attached to any instance, but is still incurring costs.",
                "recommendation": "Verify the volume is no longer needed and delete it. If needed, consider snapshotting before deletion.",
                "resource_id": vol['VolumeId']
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
                                is_idle = False
                                break
                        if not is_idle: break
                    if is_idle:
                        insights.append({
                            "title": "Idle Load Balancer", "severity": "High",
                            "description": f"Load Balancer {lb_name} appears to have no healthy targets registered across all its target groups.",
                            "recommendation": "This LB was likely provisioned by a Kubernetes Service. Verify if the Service is still needed. If not, deleting it will deprovision this LB.",
                            "resource_id": lb_name
                        })
    except ClientError as e:
        print(f"Warning: Could not check for idle LBs. Permission might be missing. {e}")
    return insights

# --- Cost Fetcher Function ---

def get_cost_for_clusters(session, cluster_names: list):
    """
    Fetches cost data from AWS Cost Explorer for a list of clusters, grouped by a specific tag.
    Note: This requires resources (EC2, EBS, ELB, etc.) to be tagged with the COST_TAG_KEY.
    """
    if not cluster_names:
        return {}

    # Cost Explorer is a global service, but for billing data it's best to use us-east-1
    cost_client = session.client('ce', region_name='us-east-1')
    now = datetime.now(timezone.utc)
    start_date = (now - relativedelta(months=1)).strftime('%Y-%m-%d')
    end_date = now.strftime('%Y-%m-%d')

    try:
        response = cost_client.get_cost_and_usage(
            TimePeriod={'Start': start_date, 'End': end_date},
            Granularity='MONTHLY',
            Filter={
                "Tags": {
                    "Key": COST_TAG_KEY,
                    "Values": cluster_names,
                    "MatchOptions": ["EQUALS"]
                }
            },
            Metrics=['UnblendedCost'],
            GroupBy=[{'Type': 'TAG', 'Key': COST_TAG_KEY}]
        )

        cost_map = {}
        for group in response.get('ResultsByTime', [])[0].get('Groups', []):
            tag_value = group['Keys'][0].split('$')[-1]
            amount = float(group['Metrics']['UnblendedCost']['Amount'])
            cost_map[tag_value] = f"${amount:,.2f}"

        return cost_map

    except ClientError as e:
        # Check if the error is due to an opt-in requirement
        if e.response['Error']['Code'] == 'AccessDeniedException' and 'is not opted in' in e.response['Error']['Message']:
            print("ERROR: AWS Cost Explorer is not enabled for this account. Please enable it in the billing console.")
        else:
            print(f"ERROR fetching cost data: {e}")
        return {}
    except Exception as e:
        print(f"UNEXPECTED ERROR fetching cost data: {e}")
        return {}


# --- Detailed Fetcher Functions ---

def fetch_managed_nodegroups(eks_client, cluster_name):
    """Fetches details for all managed nodegroups in a cluster."""
    nodegroups_details = []
    try:
        paginator = eks_client.get_paginator('list_nodegroups')
        for page in paginator.paginate(clusterName=cluster_name):
            for ng_name in page.get('nodegroups', []):
                try:
                    ng_desc = eks_client.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng_name).get('nodegroup', {})
                    if ng_desc:
                        nodegroups_details.append(ng_desc)
                except ClientError as e:
                    print(f"ERROR_FNFC_DESC: describing nodegroup {ng_name} for {cluster_name}: {e}")
                    nodegroups_details.append({"nodegroupName": ng_name, "status": "ERROR_DESCRIBING", "error": str(e)})
    except ClientError as e:
        print(f"ERROR_FNFC_LIST: listing nodegroups for {cluster_name}: {e}")
    return nodegroups_details

def fetch_karpenter_nodes_for_cluster(cluster_name, cluster_endpoint, cluster_ca, role_arn=None):
    """
    Fetches nodes managed by Karpenter or in EKS auto-mode by querying the Kubernetes API.
    """
    print(f"Fetching Karpenter/Auto-Mode nodes for {cluster_name}...")
    karpenter_nodes = []
    ca_path = f"/tmp/{cluster_name}_ca.crt"
    try:
        token = get_eks_token(cluster_name, role_arn)
        headers = {'Authorization': f'Bearer {token}'}

        with open(ca_path, "wb") as f:
            f.write(base64.b64decode(cluster_ca))

        response = requests.get(f"{cluster_endpoint}/api/v1/nodes", headers=headers, verify=ca_path, timeout=30)
        response.raise_for_status()

        nodes = response.json().get('items', [])

        for node in nodes:
            if 'karpenter.sh/provisioner-name' in node['metadata']['labels'] or node['metadata']['labels'].get('eks.amazonaws.com/compute-type') == 'ec2':
                node_info = {
                    "name": node['metadata']['name'],
                    "status": "Ready" if any(c['status'] == 'True' for c in node['status']['conditions'] if c['type'] == 'Ready') else "NotReady",
                    "desiredSize": 1,
                    "instanceTypes": [node['metadata']['labels'].get('node.kubernetes.io/instance-type', 'unknown')],
                    "amiType": "AUTO-MODE",
                    "version": node['status']['nodeInfo']['kubeletVersion'],
                    "releaseVersion": "N/A",
                    "createdAt": datetime.fromisoformat(node['metadata']['creationTimestamp'].replace("Z", "+00:00")),
                    "is_karpenter_node": True
                }
                karpenter_nodes.append(node_info)
        print(f"Found {len(karpenter_nodes)} Karpenter/Auto-Mode nodes for {cluster_name}.")

    except Exception as e:
        print(f"ERROR fetching Kubernetes API nodes for {cluster_name}: {e}")
    finally:
        if os.path.exists(ca_path):
            os.remove(ca_path)
    return karpenter_nodes


# --- Granular Kubernetes Object Fetcher ---

def get_kubernetes_workloads_and_map(cluster_name, cluster_endpoint, cluster_ca, role_arn=None):
    """Fetches detailed workload info and builds a relationship map for visualization."""
    print(f"Fetching full Kubernetes object map for {cluster_name}...")
    k8s_data = {
        "pods": [], "services": [], "ingresses": [], "nodes": [],
        "map_nodes": [], "map_edges": [], "vulnerable_images": {}, "error": None
    }
    ca_path = f"/tmp/{cluster_name}_ca.crt"
    try:
        token = get_eks_token(cluster_name, role_arn)
        headers = {'Authorization': f'Bearer {token}'}
        with open(ca_path, "wb") as f: f.write(base64.b64decode(cluster_ca))

        endpoints = {
            "pods": "/api/v1/pods", "services": "/api/v1/services",
            "ingresses": "/apis/networking.k8s.io/v1/ingresses", "nodes": "/api/v1/nodes"
        }
        for key, endpoint in endpoints.items():
            res = requests.get(f"{cluster_endpoint}{endpoint}", headers=headers, verify=ca_path, timeout=45)
            res.raise_for_status()
            k8s_data[key] = res.json().get('items', [])

        map_nodes, map_edges = [], []

        for ing in k8s_data["ingresses"]:
            uid = ing["metadata"]["uid"]
            map_nodes.append({"id": uid, "label": ing["metadata"]["name"], "group": "ingress", "title": f"<b>Ingress</b><br>Namespace: {ing['metadata']['namespace']}"})
            for rule in ing.get("spec", {}).get("rules", []):
                for path in rule.get("http", {}).get("paths", []):
                    svc_name = path["backend"]["service"]["name"]
                    for svc in k8s_data["services"]:
                        if svc["metadata"]["name"] == svc_name and svc["metadata"]["namespace"] == ing["metadata"]["namespace"]:
                            map_edges.append({"from": uid, "to": svc["metadata"]["uid"]})
                            break

        for svc in k8s_data["services"]:
            map_nodes.append({"id": svc["metadata"]["uid"], "label": svc["metadata"]["name"], "group": "svc", "title": f"<b>Service</b><br>Namespace: {svc['metadata']['namespace']}<br>Type: {svc['spec']['type']}"})

        now = datetime.now(timezone.utc)
        for pod in k8s_data["pods"]:
            pod_uid = pod["metadata"]["uid"]
            created_at = datetime.fromisoformat(pod['metadata']['creationTimestamp'].replace("Z", "+00:00"))
            pod['age'] = str(now - created_at).split('.')[0]
            pod['restarts'] = sum(cs.get('restartCount', 0) for cs in pod.get('status', {}).get('containerStatuses', []))

            map_nodes.append({"id": pod_uid, "label": pod["metadata"]["name"], "group": "pod", "title": f"<b>Pod</b><br>Status: {pod['status']['phase']}<br>Node: {pod['spec'].get('nodeName', 'N/A')}"})

            if pod["spec"].get("nodeName"):
                for n in k8s_data["nodes"]:
                    if n["metadata"]["name"] == pod["spec"]["nodeName"]:
                        map_edges.append({"from": pod_uid, "to": n["metadata"]["uid"]})
                        break

            pod_labels = pod["metadata"].get("labels", {})
            if pod_labels:
                for svc in k8s_data["services"]:
                    selector = svc["spec"].get("selector", {})
                    if selector and svc["metadata"]["namespace"] == pod["metadata"]["namespace"]:
                        if all(pod_labels.get(k) == v for k, v in selector.items()):
                            map_edges.append({"from": svc["metadata"]["uid"], "to": pod_uid})

            pod['vulnerability_summary'] = {"CRITICAL": 0, "HIGH": 0, "error": None}
            for container in pod["spec"].get("containers", []) + pod["spec"].get("initContainers", []):
                image_name = container["image"]
                scan_result = scan_image_with_trivy(image_name)
                if scan_result:
                    if scan_result.get("error"):
                         pod['vulnerability_summary']["error"] = scan_result["error"]
                    else:
                        pod['vulnerability_summary']["CRITICAL"] += scan_result["CRITICAL"]
                        pod['vulnerability_summary']["HIGH"] += scan_result["HIGH"]
                        if scan_result["CRITICAL"] > 0 or scan_result["HIGH"] > 0:
                            if image_name not in k8s_data["vulnerable_images"]:
                                k8s_data["vulnerable_images"][image_name] = {"CRITICAL": 0, "HIGH": 0}
                            k8s_data["vulnerable_images"][image_name]["CRITICAL"] += scan_result["CRITICAL"]
                            k8s_data["vulnerable_images"][image_name]["HIGH"] += scan_result["HIGH"]

        for n in k8s_data["nodes"]:
            instance_type = n['metadata']['labels'].get('node.kubernetes.io/instance-type', 'N/A')
            map_nodes.append({"id": n["metadata"]["uid"], "label": n["metadata"]["name"], "group": "node", "title": f"<b>Node</b><br>Instance Type: {instance_type}"})

        k8s_data["map_nodes"] = map_nodes
        k8s_data["map_edges"] = map_edges

    except Exception as e:
        print(f"ERROR fetching Kubernetes workloads for {cluster_name}: {e}")
        k8s_data['error'] = str(e)
    finally:
        if os.path.exists(ca_path):
            os.remove(ca_path)
    return k8s_data


def fetch_addons_for_cluster(eks_client, cluster_name):
    """Fetches details for all EKS addons in a cluster."""
    addons_details = []
    try:
        paginator = eks_client.get_paginator('list_addons')
        for page in paginator.paginate(clusterName=cluster_name):
            for addon_name in page.get('addons', []):
                try:
                    addon_desc = eks_client.describe_addon(clusterName=cluster_name, addonName=addon_name).get('addon', {})
                    if addon_desc:
                        addon_desc['health_status'] = "HEALTHY" if not addon_desc.get('health', {}).get('issues') else "HAS_ISSUES"
                        addons_details.append(addon_desc)
                except ClientError as e:
                    print(f"ERROR_FAFC_DESC: describing addon {addon_name} for {cluster_name}: {e}")
    except ClientError as e:
        print(f"ERROR_FAFC_LIST: listing addons for {cluster_name}: {e}")
    return addons_details

def fetch_fargate_profiles_for_cluster(eks_client, cluster_name):
    """Fetches all Fargate profiles for a cluster."""
    profiles = []
    try:
        paginator = eks_client.get_paginator('list_fargate_profiles')
        for page in paginator.paginate(clusterName=cluster_name):
            profiles.extend(page.get('fargateProfileNames', []))
    except ClientError as e:
        print(f"ERROR_FFPFC: listing fargate profiles for {cluster_name}: {e}")
    return [{"name": p} for p in profiles]

def fetch_oidc_provider_for_cluster(cluster_raw):
    """Extracts the OIDC provider URL from the raw cluster data."""
    return cluster_raw.get('identity', {}).get('oidc', {}).get('issuer')


# --- Action and Streaming Functions ---

def upgrade_nodegroup_version(account_id, region, cluster_name, nodegroup_name, role_arn=None):
    """Initiates an upgrade for a managed nodegroup."""
    print(f"Attempting to upgrade nodegroup '{nodegroup_name}' in cluster '{cluster_name}'...")
    session = get_session(role_arn)
    if not session:
        return {"error": f"Failed to get session for account {account_id}."}

    try:
        eks_client = session.client('eks', region_name=region)
        response = eks_client.update_nodegroup_version(
            clusterName=cluster_name,
            nodegroupName=nodegroup_name
        )
        update_id = response.get('update', {}).get('id')
        print(f"Successfully initiated nodegroup upgrade. Update ID: {update_id}")
        return {"success": True, "updateId": update_id, "message": "Nodegroup upgrade initiated."}
    except ClientError as e:
        error_message = e.response['Error']['Message']
        print(f"ERROR: Failed to upgrade nodegroup: {error_message}")
        return {"error": error_message}

def stream_cloudwatch_logs(account_id, region, log_group_name, log_type_from_ui, role_arn=None):
    """Streams control plane logs from CloudWatch for a given log type."""
    log_stream_prefix_map = {
        'api': 'kube-apiserver-', 'audit': 'kube-apiserver-audit-', 'authenticator': 'authenticator-',
        'controllerManager': 'kube-controller-manager-', 'scheduler': 'kube-scheduler-'
    }
    log_type_prefix = log_stream_prefix_map.get(log_type_from_ui)

    if not log_type_prefix:
        yield f"data: {json.dumps({'error': f'Invalid log type specified: {log_type_from_ui}'})}\n\n"
        return

    print(f"Starting log stream for {log_group_name} with prefix '{log_type_prefix}'...")
    session = get_session(role_arn)
    if not session:
        yield f"data: {json.dumps({'error': 'Failed to get session for log streaming.'})}\n\n"
        return

    logs_client = session.client('logs', region_name=region)
    try:
        paginator = logs_client.get_paginator('describe_log_streams')
        all_streams = [s for p in paginator.paginate(logGroupName=log_group_name, logStreamNamePrefix=log_type_prefix) for s in p.get('logStreams', [])]

        if not all_streams:
            yield f"data: {json.dumps({'message': f'No log streams found for log type \"{log_type_from_ui}\". Make sure this log type is enabled.'})}\n\n"
            return

        latest_stream = max(all_streams, key=lambda s: s.get('lastEventTimestamp', 0))
        log_stream_name = latest_stream['logStreamName']
        print(f"Found latest log stream: {log_stream_name}")

        start_time = int((datetime.now(timezone.utc) - timedelta(minutes=10)).timestamp() * 1000)

        paginator = logs_client.get_paginator('filter_log_events')
        pages = paginator.paginate(
            logGroupName=log_group_name, logStreamNames=[log_stream_name],
            startTime=start_time, interleaved=True
        )
        event_count = 0
        for page in pages:
            for event in page['events']:
                event_count += 1
                yield f"data: {json.dumps(event)}\n\n"
            time.sleep(1)

        if event_count == 0:
            yield f"data: {json.dumps({'message': 'No new log events in the last 10 minutes.'})}\n\n"

    except ClientError as e:
        error_msg = e.response['Error']['Message']
        print(f"ERROR streaming logs: {error_msg}")
        yield f"data: {json.dumps({'error': error_msg})}\n\n"
    except Exception as e:
        print(f"UNEXPECTED ERROR streaming logs: {e}")
        yield f"data: {json.dumps({'error': 'An unexpected error occurred during log streaming.'})}\n\n"

def get_cluster_metrics(account_id, region, cluster_name, role_arn=None):
    """Fetches key Container Insights metrics for a cluster from CloudWatch."""
    print(f"Fetching metrics for {cluster_name} in {region}...")
    session = get_session(role_arn)
    if not session:
        return {"error": f"Failed to get session for account {account_id}."}

    cw_client = session.client('cloudwatch', region_name=region)
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=3)

    metric_definitions = {
        'requests': {'MetricName': 'apiserver_request_total', 'Stat': 'Sum'}, 'requests_4xx': {'MetricName': 'apiserver_request_total_4XX', 'Stat': 'Sum'},
        'requests_5xx': {'MetricName': 'apiserver_request_total_5XX', 'Stat': 'Sum'}, 'requests_429': {'MetricName': 'apiserver_request_total_429', 'Stat': 'Sum'},
        'storage_size': {'MetricName': 'apiserver_storage_size_bytes', 'Stat': 'Average'}, 'scheduler_attempts_scheduled': {'MetricName': 'scheduler_schedule_attempts_SCHEDULED', 'Stat': 'Sum'},
        'scheduler_attempts_unschedulable': {'MetricName': 'scheduler_schedule_attempts_UNSCHEDULABLE', 'Stat': 'Sum'}, 'scheduler_attempts_error': {'MetricName': 'scheduler_schedule_attempts_ERROR', 'Stat': 'Sum'},
        'pending_pods_gated': {'MetricName': 'scheduler_pending_pods_GATED', 'Stat': 'Average'}, 'pending_pods_unschedulable': {'MetricName': 'scheduler_pending_pods_UNSCHEDULABLE', 'Stat': 'Average'},
        'pending_pods_activeq': {'MetricName': 'scheduler_pending_pods_ACTIVEQ', 'Stat': 'Average'}, 'pending_pods_backoff': {'MetricName': 'scheduler_pending_pods_BACKOFF', 'Stat': 'Average'},
        'latency_get': {'MetricName': 'apiserver_request_duration_seconds_GET_P99', 'Stat': 'Average'}, 'latency_post': {'MetricName': 'apiserver_request_duration_seconds_POST_P99', 'Stat': 'Average'},
        'latency_put': {'MetricName': 'apiserver_request_duration_seconds_PUT_P99', 'Stat': 'Average'}, 'latency_delete': {'MetricName': 'apiserver_request_duration_seconds_DELETE_P99', 'Stat': 'Average'},
        'inflight_mutating': {'MetricName': 'apiserver_current_inflight_requests_MUTATING', 'Stat': 'Average'}, 'inflight_readonly': {'MetricName': 'apiserver_current_inflight_requests_READONLY', 'Stat': 'Average'},
    }
    metric_queries = [
        {'Id': f'm{i}', 'Label': key, 'MetricStat': {'Metric': {'Namespace': 'ContainerInsights', 'MetricName': definition['MetricName'], 'Dimensions': [{'Name': 'ClusterName', 'Value': cluster_name}]}, 'Period': 300, 'Stat': definition['Stat']}, 'ReturnData': True}
        for i, (key, definition) in enumerate(metric_definitions.items())
    ]

    try:
        response = cw_client.get_metric_data(MetricDataQueries=metric_queries, StartTime=start_time, EndTime=end_time, ScanBy='TimestampDescending')
        results = {metric_result['Label']: {'timestamps': [ts.isoformat() for ts in metric_result['Timestamps']], 'values': metric_result['Values']} for metric_result in response['MetricDataResults']}
        return results
    except ClientError as e:
        error_msg = e.response['Error']['Message']
        print(f"ERROR fetching CloudWatch metrics: {error_msg}")
        return {'error': f"Could not fetch metrics. Ensure Container Insights is enabled. Error: {error_msg}"}
    except Exception as e:
        print(f"UNEXPECTED ERROR fetching metrics: {e}")
        return {'error': 'An unexpected error occurred while fetching metrics.'}

# --- Security Insights ---

def get_security_insights(cluster_raw, eks_client):
    """Analyzes raw cluster data to generate security-related insights."""
    insights = {}

    insights['secrets_encrypted'] = {"status": any(cfg.get('provider', {}).get('keyArn') for cfg in cluster_raw.get('encryptionConfig', [])), "description": "Checks if envelope encryption for Kubernetes secrets is enabled with a KMS key."}
    insights['public_endpoint'] = {"status": not cluster_raw.get('resourcesVpcConfig', {}).get('endpointPublicAccess', False), "description": "Checks if the cluster's API server endpoint is private (best practice)."}

    all_log_types = ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler']
    enabled_logs = cluster_raw.get('logging', {}).get('clusterLogging', [{}])[0].get('types', [])
    insights['logging_enabled'] = {"status": all(lt in enabled_logs for lt in all_log_types), "missing_logs": [lt for lt in all_log_types if lt not in enabled_logs], "description": "Checks if all control plane log types are enabled and sent to CloudWatch."}

    insights['latest_platform_version'] = {"status": False, "current": "N/A", "latest": "N/A", "description": "Checks if the cluster is running the latest EKS platform version."}
    try:
        eks_client.describe_update(name=cluster_raw['name'], updateId='dummy-id-for-platform-version')
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException' and "Latest platform version for" in (msg := e.response['Error']['Message']):
            latest_pv, current_pv = msg.split(" is ")[-1].strip(), cluster_raw.get('platformVersion')
            insights['latest_platform_version'].update({"status": latest_pv == current_pv, "current": current_pv, "latest": latest_pv})

    return insights

# --- Main Data Aggregation Functions ---

def _process_cluster_data(c_raw, with_details=False, eks_client=None, role_arn=None, session=None):
    """Processes raw EKS cluster data into a standardized dictionary."""
    now = datetime.now(timezone.utc)
    ninety_days_from_now = now + timedelta(days=90)

    account_id = c_raw.get("arn", "").split(':')[4] if c_raw.get("arn") else "UnknownAccount"
    version = c_raw.get("version", "Unknown")
    status = c_raw.get("status", "Unknown")

    health_issues = c_raw.get("health", {}).get("issues", [])
    health_status = "HEALTHY" if not health_issues else "HAS_ISSUES"
    if status.startswith("ERROR"): health_status = "UNKNOWN"

    eol_date = EKS_EOL_DATES.get(version)
    nearing_eol = bool(eol_date and eol_date <= ninety_days_from_now and eol_date > now)

    upgrade_insight = "PASSING"
    if version != "Unknown" and version < "1.29": upgrade_insight = "NEEDS_ATTENTION"
    if status == "UPDATING": upgrade_insight = "IN_PROGRESS"

    cluster_data = {
        "name": c_raw.get("name"), "arn": c_raw.get("arn"), "account_id": account_id,
        "version": version, "platformVersion": c_raw.get("platformVersion"), "status": status,
        "region": c_raw.get("region"), "createdAt": c_raw.get("createdAt", now),
        "health_issues": health_issues, "health_status_summary": health_status,
        "upgrade_insight_status": upgrade_insight, "is_nearing_eol_90_days": nearing_eol,
        "tags": c_raw.get("tags", {}),
        "cost_30d": "N/A", # Placeholder
    }

    if with_details and eks_client and session:
        cluster_name = c_raw["name"]

        # Fetch Cost Data
        cost_map = get_cost_for_clusters(session, [cluster_name])
        cluster_data['cost_30d'] = cost_map.get(cluster_name, "N/A")

        # Fetch Nodegroups
        managed_nodegroups_raw = fetch_managed_nodegroups(eks_client, cluster_name)
        if c_raw.get("endpoint") and c_raw.get("certificateAuthority", {}).get("data"):
            karpenter_nodes_raw = fetch_karpenter_nodes_for_cluster(
                cluster_name, c_raw["endpoint"], c_raw["certificateAuthority"]["data"], role_arn
            )
            # Fetch Workloads, Vulnerabilities, and Relationship Map
            cluster_data["workloads"] = get_kubernetes_workloads_and_map(
                cluster_name, c_raw["endpoint"], c_raw["certificateAuthority"]["data"], role_arn
            )
        else:
            karpenter_nodes_raw = []
            cluster_data["workloads"] = {"error": "Missing cluster endpoint or CA data."}
            print(f"Skipping K8s API fetch for {cluster_name} due to missing endpoint or CA data.")

        processed_nodegroups = []
        for ng in managed_nodegroups_raw:
            processed_nodegroups.append({
                "name": ng.get("nodegroupName"), "status": ng.get("status"),
                "amiType": ng.get("amiType"), "instanceTypes": ng.get("instanceTypes", []),
                "releaseVersion": ng.get("releaseVersion"), "version": ng.get("version"),
                "createdAt": ng.get("createdAt"), "desiredSize": ng.get("scalingConfig", {}).get("desiredSize"),
                "is_karpenter_node": False
            })

        processed_nodegroups.extend(karpenter_nodes_raw)

        cluster_data.update({
            "nodegroups_data": processed_nodegroups,
            "addons": fetch_addons_for_cluster(eks_client, cluster_name),
            "fargate_profiles": fetch_fargate_profiles_for_cluster(eks_client, cluster_name),
            "oidc_provider_url": fetch_oidc_provider_for_cluster(c_raw),
            "networking": c_raw.get("resourcesVpcConfig", {}),
            "security_insights": get_security_insights(c_raw, eks_client),
            # Add new cost optimization insights
            "cost_insights": get_cost_optimization_insights(session, c_raw['region'], cluster_name)
        })

    return cluster_data


def get_live_eks_data(user_groups: list[str] | None, group_map_str: str):
    """
    Fetches a summary of all EKS clusters across configured accounts,
    filtered by the user's group permissions, and includes cost data.
    """
    print("DEBUG_GLED: get_live_eks_data initiated.")

    # --- Group-Based Authentication Logic ---
    group_to_account_list = {}
    if group_map_str:
        for mapping in group_map_str.split(','):
            try:
                group, account_id = mapping.strip().split(':')
                group, account_id = group.strip(), account_id.strip()
                if group not in group_to_account_list: group_to_account_list[group] = []
                group_to_account_list[group].append(account_id)
            except ValueError:
                print(f"WARNING: Invalid mapping format in GROUP_TO_ACCOUNT_MAP: '{mapping}'")

    accessible_accounts = set()
    if user_groups is not None:
        for group in user_groups:
            accessible_accounts.update(group_to_account_list.get(group, []))
    else:
        print("WARNING: No user groups provided, defaulting to scanning all configured accounts.")
        for acc_list in group_to_account_list.values(): accessible_accounts.update(acc_list)

    print(f"User groups: {user_groups}, Accessible accounts: {accessible_accounts}")

    target_roles_str = os.getenv("AWS_TARGET_ACCOUNTS_ROLES", "")
    all_possible_accounts = []
    if target_roles_str:
        for role_arn in target_roles_str.split(','):
            if role_arn.strip():
                try:
                    all_possible_accounts.append({'role_arn': role_arn.strip(), 'id': role_arn.strip().split(':')[4]})
                except IndexError:
                    print(f"WARNING: Invalid Role ARN format: {role_arn}")

    try:
        primary_account_id = boto3.client('sts').get_caller_identity().get('Account')
        if primary_account_id not in [acc['id'] for acc in all_possible_accounts]:
            all_possible_accounts.append({'role_arn': None, 'id': primary_account_id})
    except (NoCredentialsError, PartialCredentialsError, ClientError) as e:
        print(f"WARNING: Could not determine primary account ID: {e}")

    accounts_to_scan = [acc for acc in all_possible_accounts if acc['id'] in accessible_accounts]

    if not accounts_to_scan and group_to_account_list:
        print("WARNING: User has access to no configured accounts. Returning empty data.")
        return {"clusters": [], "quick_info": {}, "errors": ["User has no access to any configured AWS accounts."]}

    print(f"Final accounts to scan for this user: {[acc['id'] for acc in accounts_to_scan]}")

    regions_str = os.getenv("AWS_REGIONS", os.getenv("AWS_DEFAULT_REGION", "us-east-1"))
    target_regions = [r.strip() for r in regions_str.split(',') if r.strip()]

    all_clusters_raw, errors, clusters_to_describe = [], [], []

    print("--- Phase 1: Listing all clusters ---")
    for account in accounts_to_scan:
        session = get_session(account.get('role_arn'))
        if not session:
            errors.append(f"Failed to get session for account {account['id']}. Skipping.")
            continue
        for region in target_regions:
            try:
                eks = session.client('eks', region_name=region)
                for page in eks.get_paginator('list_clusters').paginate():
                    for name in page.get('clusters', []):
                        clusters_to_describe.append({'name': name, 'region': region, 'account': account, 'session': session})
            except Exception as e:
                errors.append(f"Error listing clusters in account {account['id']}/{region}: {e}")

    print(f"\n--- Phase 2: Describing {len(clusters_to_describe)} clusters ---")
    for cluster_info in clusters_to_describe:
        try:
            desc = cluster_info['session'].client('eks', region_name=cluster_info['region']).describe_cluster(name=cluster_info['name']).get('cluster', {})
            desc['region'] = cluster_info['region']
            all_clusters_raw.append(desc)
        except Exception as e:
            errors.append(f"Error describing cluster {cluster_info['name']}: {e}")

    print("\n--- Phase 3: Processing all successfully described clusters ---")
    processed_clusters = [_process_cluster_data(c) for c in all_clusters_raw]

    # --- Phase 4: Fetching Fleet Cost Data ---
    # Group clusters by account to make one cost-explorer call per account
    clusters_by_account = {}
    for cluster in processed_clusters:
        acc_id = cluster['account_id']
        if acc_id not in clusters_by_account:
            clusters_by_account[acc_id] = []
        clusters_by_account[acc_id].append(cluster['name'])

    total_cost = 0.0
    for account in accounts_to_scan:
        session = get_session(account.get('role_arn'))
        if not session:
            continue
        cluster_names_in_account = clusters_by_account.get(account['id'], [])
        if cluster_names_in_account:
            print(f"Fetching costs for {len(cluster_names_in_account)} clusters in account {account['id']}")
            cost_map = get_cost_for_clusters(session, cluster_names_in_account)
            for cluster in processed_clusters:
                if cluster['account_id'] == account['id'] and cluster['name'] in cost_map:
                    cost_str = cost_map[cluster['name']]
                    cluster['cost_30d'] = cost_str
                    try:
                        total_cost += float(cost_str.replace('$', '').replace(',', ''))
                    except ValueError:
                        pass

    print("\n--- Phase 5: Finalizing data ---")
    for cluster in processed_clusters:
        if isinstance(cluster.get('createdAt'), datetime):
            cluster['createdAt'] = cluster['createdAt'].isoformat()

    return {
        "clusters": processed_clusters, "errors": errors,
        "quick_info": {
            "total_clusters": len(processed_clusters),
            "total_cost_30d": f"${total_cost:,.2f}",
            "clusters_with_health_issues": sum(1 for c in processed_clusters if c["health_issues"]),
            "clusters_with_upgrade_insights_attention": sum(1 for c in processed_clusters if c["upgrade_insight_status"] == "NEEDS_ATTENTION"),
            "clusters_nearing_eol_90_days": sum(1 for c in processed_clusters if c["is_nearing_eol_90_days"]),
            "accounts_running_kubernetes_clusters": len({c["account_id"] for c in processed_clusters}),
            "regions_running_kubernetes_clusters": len({c["region"] for c in processed_clusters}),
        },
    }

def get_single_cluster_details(account_id, region, cluster_name, role_arn=None):
    """Fetches comprehensive details for a single EKS cluster."""
    print(f"Fetching details for {cluster_name} in {region} (Account: {account_id})")
    session = get_session(role_arn)
    if not session:
        return {"errors": [f"Failed to get session for account {account_id}."]}
    
    try:
        eks_client = session.client('eks', region_name=region)
        cluster_raw = eks_client.describe_cluster(name=cluster_name).get('cluster', {})
        if not cluster_raw:
             return {"errors": [f"Cluster {cluster_name} not found."]}
        
        cluster_raw['region'] = region
        cluster_details = _process_cluster_data(
            cluster_raw, 
            with_details=True, 
            eks_client=eks_client, 
            role_arn=role_arn,
            session=session
        )

        return cluster_details
    except Exception as e:
        msg = f"Error fetching details for cluster {cluster_name}: {e}"
        print(msg)
        return {"name": cluster_name, "errors": [msg]}
