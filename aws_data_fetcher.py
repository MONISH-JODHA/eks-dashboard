import boto3
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from datetime import datetime, timezone, timedelta
import os
import json
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

# Kubernetes Imports
from kubernetes import client, config
from kubernetes.config.kube_config import KubeConfigLoader
from kubernetes.client.rest import ApiException

# --- EKS Data ---
EKS_EOL_DATES = {
    "1.23": datetime(2024, 6, 4, tzinfo=timezone.utc), "1.24": datetime(2024, 8, 1, tzinfo=timezone.utc),
    "1.25": datetime(2024, 10, 22, tzinfo=timezone.utc), "1.26": datetime(2025, 1, 22, tzinfo=timezone.utc),
    "1.27": datetime(2025, 6, 22, tzinfo=timezone.utc), "1.28": datetime(2025, 7, 22, tzinfo=timezone.utc),
    "1.29": datetime(2025, 11, 1, tzinfo=timezone.utc), "1.30": datetime(2026, 6, 1, tzinfo=timezone.utc),
}
COST_TAG_KEY = os.getenv("COST_TAG_KEY", "eks:cluster-name")


# --- Utility & Session Management ---

def get_session(role_arn=None):
    """Gets a boto3 session, assuming a role if one is provided."""
    if not role_arn:
        try:
            boto3.client('sts').get_caller_identity()
            return boto3.Session()
        except (NoCredentialsError, PartialCredentialsError, ClientError) as e:
            logging.error(f"Default credentials are not configured or invalid. Error: {e}")
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
        logging.error(f"Could not assume role {role_arn}. Error: {e}")
        return None

# --- Kubernetes Client & Helper Functions ---
def get_k8s_api_client(cluster_name, cluster_endpoint, cluster_ca_data, region, role_arn=None):
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
                'args': ['eks', 'get-token', '--cluster-name', cluster_name, '--region', region]
            }
        }}]
    }
    if role_arn:
        kube_config_dict['users'][0]['user']['exec']['args'].extend(['--role-arn', role_arn])

    loader = KubeConfigLoader(config_dict=kube_config_dict)
    cfg = client.Configuration()
    loader.load_and_set(cfg)
    return client.ApiClient(configuration=cfg)


# --- Detailed AWS & K8s Fetcher Functions ---
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
                    logging.error(f"Error describing nodegroup {ng_name} in {cluster_name}: {e}")
                    nodegroups_details.append({"nodegroupName": ng_name, "status": "ERROR_DESCRIBING", "error": str(e)})
    except ClientError as e:
        logging.error(f"Error listing nodegroups for {cluster_name}: {e}")
    return nodegroups_details

def fetch_karpenter_nodes_for_cluster(core_v1_api):
    logging.info("Fetching Karpenter/Auto-Mode nodes...")
    karpenter_nodes = []
    try:
        nodes = core_v1_api.list_node(timeout_seconds=30).items
        for node in nodes:
            labels = node.metadata.labels or {}
            # Identifies nodes managed by Karpenter or unmanaged nodes (typical for cluster-autoscaler)
            if 'karpenter.sh/provisioner-name' in labels or labels.get('eks.amazonaws.com/compute-type') == 'ec2':
                karpenter_nodes.append({
                    "name": node.metadata.name,
                    "status": "Ready" if any(c.status == 'True' for c in node.status.conditions if c.type == 'Ready') else "NotReady",
                    "desiredSize": 1, "instanceTypes": [labels.get('node.kubernetes.io/instance-type', 'unknown')],
                    "amiType": "AUTO-MODE", "version": node.status.node_info.kubelet_version,
                    "releaseVersion": "N/A", "createdAt": node.metadata.creation_timestamp, "is_karpenter_node": True
                })
        logging.info(f"Found {len(karpenter_nodes)} Karpenter/Auto-Mode nodes.")
    except Exception as e:
        logging.error(f"ERROR fetching Kubernetes API nodes for Karpenter: {e}")
    return karpenter_nodes

def fetch_ecr_vulnerabilities(region, image_uris, role_arn=None):
    """Fetches vulnerability scan findings for a list of ECR image URIs."""
    session = get_session(role_arn)
    if not session: return {"error": "Failed to get session for vulnerability scan."}
    
    # ECR clients need to be created for the region the repository is in.
    # We assume all images are in the same region as the cluster for simplicity.
    # A more robust solution would parse the region from the image URI and manage multiple clients.
    ecr_client = session.client('ecr', region_name=region)
    
    scan_results = {}
    ecr_image_pattern = re.compile(r"^(?P<aws_account_id>\d{12})\.dkr\.ecr\.(?P<aws_region>[a-z0-9-]+)\.amazonaws\.com\/(?P<repository_name>[\w\d._/-]+)(?::(?P<image_tag>[\w\d_.-]+)|@(?P<image_digest>sha256:[a-f0-9]{64}))$")

    for uri in image_uris:
        match = ecr_image_pattern.match(uri)
        if not match:
            scan_results[uri] = {"status": "NOT_ECR_IMAGE"}
            continue

        parts = match.groupdict()
        image_identifier = {}
        if parts.get('image_digest'):
            image_identifier['imageDigest'] = parts['image_digest']
        else:
            image_identifier['imageTag'] = parts.get('image_tag', 'latest')

        try:
            findings = ecr_client.describe_image_scan_findings(
                repositoryName=parts['repository_name'],
                imageId=image_identifier
            )
            scan_results[uri] = {
                "status": findings.get('imageScanStatus', {}).get('status', 'UNKNOWN'),
                "summary": findings.get('imageScanFindingsSummary', {}).get('findingSeverityCounts', {}),
                "scanCompletedAt": findings.get('imageScanFindings', {}).get('imageScanCompletedAt')
            }
        except ClientError as e:
            if e.response['Error']['Code'] == 'ScanNotFoundException':
                scan_results[uri] = {"status": "NOT_SCANNED", "summary": {}}
            else:
                logging.error(f"Error fetching ECR scan for {uri}: {e}")
                scan_results[uri] = {"status": "ERROR", "error": str(e)}

    return scan_results

def get_kubernetes_cluster_objects(cluster_name, cluster_endpoint, cluster_ca, region, role_arn=None):
    """Fetches a wide range of Kubernetes objects and ECR vulnerabilities for a given cluster."""
    logging.info(f"Fetching full Kubernetes object map for {cluster_name}...")
    k8s_data = {
        "pods": [], "services": [], "ingresses": [], "nodes": [], "deployments": [], 
        "events": [], "roles": [], "clusterroles": [], "rolebindings": [], "clusterrolebindings": [],
        "map_nodes": [], "map_edges": [], "error": None
    }

    try:
        api_client = get_k8s_api_client(cluster_name, cluster_endpoint, cluster_ca, region, role_arn)
        core_v1 = client.CoreV1Api(api_client)
        apps_v1 = client.AppsV1Api(api_client)
        networking_v1 = client.NetworkingV1Api(api_client)
        rbac_v1 = client.RbacAuthorizationV1Api(api_client)

        with ThreadPoolExecutor(max_workers=8) as executor:
            future_pods = executor.submit(core_v1.list_pod_for_all_namespaces, timeout_seconds=120)
            future_svcs = executor.submit(core_v1.list_service_for_all_namespaces, timeout_seconds=60)
            future_ings = executor.submit(networking_v1.list_ingress_for_all_namespaces, timeout_seconds=60)
            future_nodes = executor.submit(core_v1.list_node, timeout_seconds=60)
            future_deps = executor.submit(apps_v1.list_deployment_for_all_namespaces, timeout_seconds=60)
            future_events = executor.submit(core_v1.list_event_for_all_namespaces, limit=250, timeout_seconds=60)
            future_roles = executor.submit(rbac_v1.list_role_for_all_namespaces, timeout_seconds=60)
            future_clusterroles = executor.submit(rbac_v1.list_cluster_role, timeout_seconds=60)
            future_rolebindings = executor.submit(rbac_v1.list_role_binding_for_all_namespaces, timeout_seconds=60)
            future_clusterrolebindings = executor.submit(rbac_v1.list_cluster_role_binding, timeout_seconds=60)

            k8s_data["pods"] = [api_client.sanitize_for_serialization(p) for p in future_pods.result().items]
            k8s_data["services"] = [api_client.sanitize_for_serialization(s) for s in future_svcs.result().items]
            k8s_data["ingresses"] = [api_client.sanitize_for_serialization(i) for i in future_ings.result().items]
            k8s_data["nodes"] = [api_client.sanitize_for_serialization(n) for n in future_nodes.result().items]
            k8s_data["deployments"] = [api_client.sanitize_for_serialization(d) for d in future_deps.result().items]
            k8s_data["events"] = sorted([api_client.sanitize_for_serialization(e) for e in future_events.result().items], key=lambda x: x.get('lastTimestamp') or x.get('eventTime'), reverse=True)
            k8s_data["roles"] = [api_client.sanitize_for_serialization(r) for r in future_roles.result().items]
            k8s_data["clusterroles"] = [api_client.sanitize_for_serialization(cr) for cr in future_clusterroles.result().items]
            k8s_data["rolebindings"] = [api_client.sanitize_for_serialization(rb) for rb in future_rolebindings.result().items]
            k8s_data["clusterrolebindings"] = [api_client.sanitize_for_serialization(crb) for crb in future_clusterrolebindings.result().items]

        now = datetime.now(timezone.utc)
        
        # Step 1: Process Pods, calculate age, and collect ECR image URIs
        ecr_image_uris = set()
        for pod in k8s_data["pods"]:
            creation_time = datetime.fromisoformat(pod['metadata']['creationTimestamp'].replace("Z", "+00:00"))
            pod['age'] = str(now - creation_time).split('.')[0]
            pod['restarts'] = sum(cs.get('restartCount', 0) for cs in pod.get('status', {}).get('containerStatuses', []))
            for container_status in pod.get('status', {}).get('containerStatuses', []):
                if image_uri := container_status.get('image'):
                    if 'dkr.ecr' in image_uri:
                        ecr_image_uris.add(image_uri)
        
        # Step 2: Fetch vulnerabilities for all collected ECR images
        vulnerability_results = fetch_ecr_vulnerabilities(region, list(ecr_image_uris), role_arn)

        # Step 3: Build visualization map and attach vulnerability data to pods
        map_nodes, map_edges = [], []

        for pod in k8s_data["pods"]:
            pod['vulnerabilities'] = {}
            for cs in pod.get('status', {}).get('containerStatuses', []):
                if (image_uri := cs.get('image')) and image_uri in vulnerability_results:
                    pod['vulnerabilities'][image_uri] = vulnerability_results[image_uri]

            owner_ref = pod['metadata'].get('ownerReferences', [{}])[0]
            details = {
                "kind": "Pod", "name": pod["metadata"]["name"], "namespace": pod["metadata"]["namespace"], 
                "status": pod["status"]["phase"], "pod_ip": pod["status"].get("podIP", "N/A"), 
                "node_name": pod["spec"].get("nodeName", "N/A"), "restarts": pod['restarts'], 
                "age": pod['age'], "controlled_by": f"{owner_ref.get('kind', 'N/A')}/{owner_ref.get('name', 'N/A')}",
                "created": pod['metadata']['creationTimestamp'], "vulnerabilities": pod['vulnerabilities']
            }
            map_nodes.append({"id": pod["metadata"]["uid"], "label": pod["metadata"]["name"], "group": "pod", "title": f"Pod: {details['name']}<br>Status: {details['status']}", "details": details})
            
            if pod["spec"].get("nodeName"):
                for n in k8s_data["nodes"]:
                    if n["metadata"]["name"] == pod["spec"]["nodeName"]:
                        map_edges.append({"from": pod["metadata"]["uid"], "to": n["metadata"]["uid"], "arrows": "to"}); break
            
            pod_labels = pod["metadata"].get("labels", {})
            if pod_labels:
                for svc in k8s_data["services"]:
                    selector = svc["spec"].get("selector", {})
                    if selector and svc["metadata"]["namespace"] == pod["metadata"]["namespace"] and all(pod_labels.get(k) == v for k, v in selector.items()):
                        map_edges.append({"from": svc["metadata"]["uid"], "to": pod["metadata"]["uid"], "arrows": "to"})

        for ing in k8s_data["ingresses"]:
            details = { "kind": "Ingress", "name": ing["metadata"]["name"], "namespace": ing["metadata"]["namespace"], "class": ing["spec"].get("ingressClassName", "N/A"), "hosts": [rule.get("host") for rule in ing.get("spec", {}).get("rules", [])], "created": ing['metadata']['creationTimestamp']}
            map_nodes.append({"id": ing["metadata"]["uid"], "label": ing["metadata"]["name"], "group": "ingress", "title": f"Ingress: {details['name']}<br>Namespace: {details['namespace']}", "details": details})
            for rule in ing.get("spec", {}).get("rules", []):
                for path in rule.get("http", {}).get("paths", []):
                    if svc_name := path.get("backend", {}).get("service", {}).get("name"):
                        for svc in k8s_data["services"]:
                            if svc["metadata"]["name"] == svc_name and svc["metadata"]["namespace"] == ing["metadata"]["namespace"]:
                                map_edges.append({"from": ing["metadata"]["uid"], "to": svc["metadata"]["uid"], "arrows": "to"}); break
        for svc in k8s_data["services"]:
            details = {"kind": "Service", "name": svc["metadata"]["name"], "namespace": svc["metadata"]["namespace"], "type": svc["spec"]["type"], "cluster_ip": svc["spec"].get("clusterIP", "N/A"), "ports": [f"{p.get('name', '')} {p['port']}:{p['targetPort']}/{p['protocol']}" for p in svc["spec"].get("ports", [])], "selector": svc["spec"].get("selector"), "created": svc['metadata']['creationTimestamp']}
            map_nodes.append({"id": svc["metadata"]["uid"], "label": svc["metadata"]["name"], "group": "svc", "title": f"Service: {details['name']}<br>Type: {details['type']}", "details": details})
        for n in k8s_data["nodes"]:
            details = {"kind": "Node", "name": n["metadata"]["name"], "instance_type": n['metadata']['labels'].get('node.kubernetes.io/instance-type', 'N/A'), "os_image": n["status"]["nodeInfo"].get("osImage", "N/A"), "kernel_version": n["status"]["nodeInfo"].get("kernelVersion", "N/A"), "kubelet_version": n["status"]["nodeInfo"].get("kubeletVersion", "N/A"), "allocatable_cpu": n["status"].get("allocatable", {}).get("cpu", "N/A"), "allocatable_memory": n["status"].get("allocatable", {}).get("memory", "N/A"), "conditions": [{c['type']: c['status']} for c in n.get('status', {}).get('conditions', [])], "created": n['metadata']['creationTimestamp']}
            map_nodes.append({"id": n["metadata"]["uid"], "label": n["metadata"]["name"], "group": "node", "title": f"Node: {details['name']}<br>Type: {details['instance_type']}", "details": details})

        k8s_data["map_nodes"], k8s_data["map_edges"] = map_nodes, map_edges

    except ApiException as e:
        k8s_data['error'] = f"Kubernetes API Error: {e.reason} (Status: {e.status})"
        logging.error(f"Error fetching k8s map for {cluster_name}: {e.body}")
    except Exception as e:
        k8s_data['error'] = f"An unexpected error occurred connecting to Kubernetes: {str(e)}"
        logging.error(f"UNEXPECTED ERROR fetching k8s map for {cluster_name}: {e}", exc_info=True)

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
                except ClientError as e: logging.error(f"Error describing addon {addon_name}: {e}")
    except ClientError as e: logging.error(f"Error listing addons for {cluster_name}: {e}")
    return addons_details

def fetch_fargate_profiles_for_cluster(eks_client, cluster_name):
    profiles = []
    try:
        for page in eks_client.get_paginator('list_fargate_profiles').paginate(clusterName=cluster_name):
            profiles.extend(page.get('fargateProfileNames', []))
    except ClientError as e: logging.error(f"Error fetching fargate profiles for {cluster_name}: {e}")
    return [{"name": p} for p in profiles]

def fetch_oidc_provider_for_cluster(cluster_raw):
    return cluster_raw.get('identity', {}).get('oidc', {}).get('issuer')


# --- Action Functions ---
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

# --- Metrics Fetcher ---
def get_cluster_metrics(account_id, region, cluster_name, role_arn=None):
    session = get_session(role_arn)
    if not session:
        return {"error": f"Failed to get session for account {account_id}."}

    cw_client = session.client('cloudwatch', region_name=region)
    metric_definitions = {
        "node_status_ready": ('node_status_ready', 'Average'), "container_restarts": ('pod_number_of_container_restarts', 'Sum'),
        "node_cpu_utilization": ('node_cpu_utilization', 'Average'), "node_memory_utilization": ('node_memory_utilization', 'Average'),
        "node_filesystem_utilization": ('node_filesystem_utilization', 'Average'), "pod_cpu_utilization": ('pod_cpu_utilization', 'Average'),
        "pod_memory_utilization": ('pod_memory_utilization', 'Average'), "pod_status_running": ('pod_status_running', 'Average'),
        "pod_status_pending": ('pod_status_pending', 'Average'),
        "apiserver_request_total": ('apiserver_request_total', 'Sum'), "apiserver_request_latency_get": ('apiserver_request_latencies_GET', 'Average'),
        "apiserver_request_latency_list": ('apiserver_request_latencies_LIST', 'Average'), "apiserver_request_latency_post": ('apiserver_request_latencies_POST', 'Average'),
        "scheduler_pending_pods": ('scheduler_pending_pods', 'Average'),
    }

    queries = [{
        'Id': f'm{i}', 'Label': key,
        'MetricStat': { 'Metric': {'Namespace': 'ContainerInsights', 'MetricName': name, 'Dimensions': [{'Name': 'ClusterName', 'Value': cluster_name}]}, 'Period': 300, 'Stat': stat},
        'ReturnData': True
    } for i, (key, (name, stat)) in enumerate(metric_definitions.items())]

    try:
        response = cw_client.get_metric_data(
            MetricDataQueries=queries,
            StartTime=datetime.now(timezone.utc) - timedelta(hours=6), EndTime=datetime.now(timezone.utc),
            ScanBy='TimestampDescending'
        )
        return {res['Label']: {'timestamps': [ts.isoformat() for ts in res['Timestamps']], 'values': res['Values']} for res in response['MetricDataResults']}
    except ClientError as e:
        return {'error': f"Could not fetch metrics. Ensure Container Insights is enabled. Error: {e.response['Error']['Message']}"}
    except Exception as e:
        return {'error': f'An unexpected error occurred fetching metrics: {str(e)}'}


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
def _process_cluster_data(c_raw, with_details=False, detail_results=None):
    now = datetime.now(timezone.utc)
    ninety_days_from_now = now + timedelta(days=90)
    version = c_raw.get("version", "Unknown")
    eol_date = EKS_EOL_DATES.get(version)

    cluster_data = {
        "name": c_raw.get("name"), "arn": c_raw.get("arn"), "account_id": c_raw.get("arn", "::::").split(':')[4],
        "version": version, "platformVersion": c_raw.get("platformVersion"), "status": c_raw.get("status", "Unknown"),
        "region": c_raw.get("region"), "createdAt": c_raw.get("createdAt", now), "tags": c_raw.get("tags", {}),
        "health_issues": c_raw.get("health", {}).get("issues", []),
        "health_status_summary": "HEALTHY" if not c_raw.get("health", {}).get("issues", []) else "HAS_ISSUES",
        "upgrade_insight_status": "PASSING" if version == "Unknown" or version >= "1.29" else "NEEDS_ATTENTION",
        "is_nearing_eol_90_days": bool(eol_date and now < eol_date <= ninety_days_from_now),
    }

    if with_details and detail_results:
        managed_nodegroups_raw = detail_results.get("nodegroups", [])
        karpenter_nodes_raw = []
        
        cluster_data["k8s_data"] = detail_results.get("k8s_objects", {"error": "Kubernetes data not fetched."})
        if not cluster_data["k8s_data"].get("error"):
            try:
                 api_client = get_k8s_api_client(c_raw["name"], c_raw["endpoint"], c_raw["certificateAuthority"]["data"], c_raw["region"], detail_results.get("role_arn"))
                 karpenter_nodes_raw = fetch_karpenter_nodes_for_cluster(client.CoreV1Api(api_client))
            except Exception as e:
                 logging.error(f"Failed to perform agentless node analysis for {c_raw['name']}: {e}")

        processed_nodegroups = [{"name": ng.get("nodegroupName"), "status": ng.get("status"), "amiType": ng.get("amiType"), "instanceTypes": ng.get("instanceTypes", []), "releaseVersion": ng.get("releaseVersion"), "version": ng.get("version"), "createdAt": ng.get("createdAt"), "desiredSize": ng.get("scalingConfig", {}).get("desiredSize"), "is_karpenter_node": False} for ng in managed_nodegroups_raw]
        processed_nodegroups.extend(karpenter_nodes_raw)
        
        cluster_data.update({
            "nodegroups_data": processed_nodegroups, "addons": detail_results.get("addons", []),
            "fargate_profiles": detail_results.get("fargate", []), "security_insights": detail_results.get("security", {}),
            "oidc_provider_url": fetch_oidc_provider_for_cluster(c_raw), "networking": c_raw.get("resourcesVpcConfig", {}),
        })

    return cluster_data

def get_live_eks_data(user_groups: list[str] | None, group_map_str: str):
    group_to_account_list = {}
    if group_map_str:
        for mapping in group_map_str.split(','):
            try:
                group, account_id = [x.strip() for x in mapping.strip().split(':')]
                group_to_account_list.setdefault(group, []).append(account_id)
            except ValueError: logging.warning(f"Invalid group-account mapping: '{mapping}'")

    accessible_accounts = {acc for grp in user_groups for acc in group_to_account_list.get(grp, [])} if user_groups is not None else {acc for acc_list in group_to_account_list.values() for acc in acc_list}
    all_possible_roles = [{'role_arn': r.strip(), 'id': r.strip().split(':')[4]} for r in os.getenv("AWS_TARGET_ACCOUNTS_ROLES", "").split(',') if r.strip()]
    
    try:
        primary_account_id = boto3.client('sts').get_caller_identity().get('Account')
        if not any(acc['id'] == primary_account_id for acc in all_possible_roles):
            all_possible_roles.append({'role_arn': None, 'id': primary_account_id})
    except Exception as e:
        logging.warning(f"Could not determine primary account ID from default credentials: {e}")

    accounts_to_scan = [acc for acc in all_possible_roles if not accessible_accounts or acc['id'] in accessible_accounts]
    if not accounts_to_scan and group_to_account_list:
        return {"clusters": [], "quick_info": {}, "errors": ["User has no access to any configured AWS accounts."]}

    all_clusters_raw, errors = [], []
    with ThreadPoolExecutor(max_workers=30) as executor:
        describe_futures = {}
        for account in accounts_to_scan:
            session = get_session(account.get('role_arn'))
            if not session:
                errors.append(f"Failed session for account {account['id']}."); continue
            for region in [r.strip() for r in os.getenv("AWS_REGIONS", os.getenv("AWS_DEFAULT_REGION", "us-east-1")).split(',') if r.strip()]:
                try:
                    eks_client = session.client('eks', region_name=region)
                    cluster_names = [n for p in eks_client.get_paginator('list_clusters').paginate() for n in p.get('clusters', [])]
                    for name in cluster_names:
                        future = executor.submit(eks_client.describe_cluster, name=name)
                        describe_futures[future] = region
                except Exception as e: errors.append(f"Error listing clusters in {account['id']}/{region}: {e}")

        for future in as_completed(describe_futures):
            region = describe_futures[future]
            try:
                desc = future.result().get('cluster', {})
                if desc:
                    desc['region'] = region
                    all_clusters_raw.append(desc)
            except Exception as e: errors.append(f"Error describing cluster: {e}")
    
    processed_clusters = [_process_cluster_data(c) for c in all_clusters_raw]
    for c in processed_clusters: c['createdAt'] = c['createdAt'].isoformat() if isinstance(c.get('createdAt'), datetime) else c.get('createdAt')
    
    quick_info = {
        "total_clusters": len(processed_clusters),
        "clusters_with_health_issues": sum(1 for c in processed_clusters if c["health_issues"]),
        "clusters_with_upgrade_insights_attention": sum(1 for c in processed_clusters if c["upgrade_insight_status"] == "NEEDS_ATTENTION"),
        "clusters_nearing_eol_90_days": sum(1 for c in processed_clusters if c["is_nearing_eol_90_days"]),
        "accounts_running_kubernetes_clusters": len({c["account_id"] for c in processed_clusters}),
        "regions_running_kubernetes_clusters": len({c["region"] for c in processed_clusters})
    }
    return {"clusters": processed_clusters, "errors": errors, "quick_info": quick_info}

def get_single_cluster_details(account_id, region, cluster_name, role_arn=None):
    """Fetches comprehensive details for a single EKS cluster concurrently."""
    session = get_session(role_arn)
    if not session: return {"errors": [f"Failed to get session for account {account_id}."]}
    
    try:
        eks_client = session.client('eks', region_name=region)
        cluster_raw = eks_client.describe_cluster(name=cluster_name).get('cluster', {})
        if not cluster_raw: return {"errors": [f"Cluster {cluster_name} not found."]}
        cluster_raw['region'] = region

        detail_results = {"role_arn": role_arn}
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_map = {}
            future_map[executor.submit(fetch_managed_nodegroups, eks_client, cluster_name)] = "nodegroups"
            future_map[executor.submit(fetch_addons_for_cluster, eks_client, cluster_name)] = "addons"
            future_map[executor.submit(fetch_fargate_profiles_for_cluster, eks_client, cluster_name)] = "fargate"
            future_map[executor.submit(get_security_insights, cluster_raw, eks_client)] = "security"
            
            if cluster_raw.get("endpoint") and cluster_raw.get("certificateAuthority", {}).get("data"):
                future_map[executor.submit(get_kubernetes_cluster_objects, cluster_name, cluster_raw["endpoint"], cluster_raw["certificateAuthority"]["data"], region, role_arn)] = "k8s_objects"
            else:
                detail_results["k8s_objects"] = {"error": "Cluster endpoint or certificate authority data is not available."}

            for future in as_completed(future_map):
                key = future_map[future]
                try:
                    detail_results[key] = future.result()
                except Exception as e:
                    logging.error(f"Error fetching detail '{key}' for cluster {cluster_name}: {e}", exc_info=True)
                    detail_results[key] = {"error": f"Failed to fetch {key}: {e}"}

        return _process_cluster_data(cluster_raw, with_details=True, detail_results=detail_results)
    except Exception as e:
        logging.error(f"Error in get_single_cluster_details for {cluster_name}: {e}", exc_info=True)
        return {"name": cluster_name, "errors": [f"Error fetching details for cluster {cluster_name}: {e}"]}
