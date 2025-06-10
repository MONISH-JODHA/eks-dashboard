import boto3
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from datetime import datetime, timezone, timedelta
import os
import json
from collections import Counter
import time
import base64
import requests
import subprocess

# --- EKS & Cost Data ---
EKS_EOL_DATES = {
    "1.23": datetime(2024, 6, 4, tzinfo=timezone.utc), "1.24": datetime(2024, 8, 1, tzinfo=timezone.utc),
    "1.25": datetime(2024, 10, 22, tzinfo=timezone.utc), "1.26": datetime(2025, 1, 22, tzinfo=timezone.utc),
    "1.27": datetime(2025, 6, 22, tzinfo=timezone.utc), "1.28": datetime(2025, 7, 22, tzinfo=timezone.utc),
    "1.29": datetime(2025, 11, 1, tzinfo=timezone.utc), "1.30": datetime(2026, 6, 1, tzinfo=timezone.utc),
    "1.31": datetime(2026, 7, 1, tzinfo=timezone.utc), "1.32": datetime(2026, 9, 1, tzinfo=timezone.utc),
}

EC2_PRICING_ESTIMATES_PER_HOUR = {
    "t3.medium": 0.0416, "t3.large": 0.0832, "t3.xlarge": 0.1664,
    "m5.large": 0.096, "m5.xlarge": 0.192, "m5.2xlarge": 0.384, "m5.4xlarge": 0.768,
    "c5.large": 0.085, "c5.xlarge": 0.17, "c5.2xlarge": 0.34, "c5.4xlarge": 0.68,
    "c6g.large": 0.068, "c6g.xlarge": 0.136, "c6g.2xlarge": 0.272,
    "r5.large": 0.126, "r5.xlarge": 0.252, "r5.2xlarge": 0.504, "r5.4xlarge": 1.008,
}

# --- Utility & Session Management ---

def pp_debug(label, data):
    try:
        print(f"DEBUG: {label}:\n{json.dumps(data, indent=2, default=str)}")
    except TypeError:
        print(f"DEBUG: {label}: {data} (Could not JSON serialize fully)")

def get_session(role_arn=None):
    if not role_arn:
        return boto3.Session()
    try:
        sts_client = boto3.client('sts')
        session_name = f"eks-dashboard-session-{int(datetime.now(timezone.utc).timestamp())}"
        assumed_role_object = sts_client.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
        credentials = assumed_role_object['Credentials']
        return boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
        )
    except ClientError as e:
        print(f"ERROR_GARS: Could not assume role {role_arn}. Error: {e}")
        return None

def get_eks_token(cluster_name: str, role_arn: str = None) -> str:
    command = ["aws", "eks", "get-token", "--cluster-name", cluster_name]
    if role_arn:
        command.extend(["--role-arn", role_arn])
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=30)
        token_data = json.loads(result.stdout)
        return token_data["status"]["token"]
    except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError, subprocess.TimeoutExpired) as e:
        print(f"ERROR getting EKS token via AWS CLI: {e}")
        if hasattr(e, 'stderr'):
            print(f"AWS CLI Stderr: {e.stderr}")
        raise

# --- Detailed Fetcher Functions ---

def fetch_managed_nodegroups(eks_client, cluster_name):
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
    print(f"Fetching Karpenter/Auto-Mode nodes for {cluster_name}...")
    karpenter_nodes = []
    try:
        token = get_eks_token(cluster_name, role_arn)
        headers = {'Authorization': f'Bearer {token}'}

        ca_path = f"/tmp/{cluster_name}_ca.crt"
        with open(ca_path, "wb") as f:
            f.write(base64.b64decode(cluster_ca))

        response = requests.get(f"{cluster_endpoint}/api/v1/nodes", headers=headers, verify=ca_path, timeout=30)
        os.remove(ca_path)
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
        print(f"Found {len(karpenter_nodes)} Karpenter/Auto-Mode nodes.")

    except Exception as e:
        print(f"ERROR fetching Karpenter nodes for {cluster_name}: {e}")
    return karpenter_nodes

def fetch_addons_for_cluster(eks_client, cluster_name):
    addons_details = []
    try:
        paginator = eks_client.get_paginator('list_addons')
        for page in paginator.paginate(clusterName=cluster_name):
            for addon_name in page.get('addons', []):
                try:
                    addon_desc = eks_client.describe_addon(clusterName=cluster_name, addonName=addon_name).get('addon', {})
                    if addon_desc:
                        addons_details.append(addon_desc)
                except ClientError as e:
                    print(f"ERROR_FAFC_DESC: describing addon {addon_name} for {cluster_name}: {e}")
    except ClientError as e:
        print(f"ERROR_FAFC_LIST: listing addons for {cluster_name}: {e}")
    return addons_details

def fetch_fargate_profiles_for_cluster(eks_client, cluster_name):
    profiles = []
    try:
        paginator = eks_client.get_paginator('list_fargate_profiles')
        for page in paginator.paginate(clusterName=cluster_name):
            profiles.extend(page.get('fargateProfileNames', []))
    except ClientError as e:
        print(f"ERROR_FFPFC: listing fargate profiles for {cluster_name}: {e}")
    return [{"name": p} for p in profiles]

def fetch_oidc_provider_for_cluster(cluster_raw):
    return cluster_raw.get('identity', {}).get('oidc', {}).get('issuer')


# --- Action and Streaming Functions ---

def upgrade_nodegroup_version(account_id, region, cluster_name, nodegroup_name, role_arn=None):
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

def stream_cloudwatch_logs(account_id, region, log_group_name, log_type_prefix, role_arn=None):
    print(f"Starting log stream for {log_group_name} with prefix '{log_type_prefix}'...")
    session = get_session(role_arn)
    if not session:
        yield f"data: {json.dumps({'error': 'Failed to get session for log streaming.'})}\n\n"
        return

    logs_client = session.client('logs', region_name=region)
    
    try:
        paginator = logs_client.get_paginator('describe_log_streams')
        all_streams = []
        for page in paginator.paginate(logGroupName=log_group_name, logStreamNamePrefix=log_type_prefix):
            all_streams.extend(page.get('logStreams', []))

        if not all_streams:
            yield f"data: {json.dumps({'message': f'No log streams found for log type "{log_type_prefix}". Make sure this log type is enabled.'})}\n\n"
            return
            
        latest_stream = max(all_streams, key=lambda s: s.get('lastEventTimestamp', 0))
        log_stream_name = latest_stream['logStreamName']
        print(f"Found latest log stream: {log_stream_name}")

        start_time = int((datetime.now(timezone.utc) - timedelta(minutes=10)).timestamp() * 1000)
        
        paginator = logs_client.get_paginator('filter_log_events')
        pages = paginator.paginate(
            logGroupName=log_group_name,
            logStreamNames=[log_stream_name],
            startTime=start_time,
            interleaved=True
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

# --- Security Insights ---

def get_security_insights(cluster_raw, eks_client):
    insights = {}
    
    encryption_config = cluster_raw.get('encryptionConfig', [])
    insights['secrets_encrypted'] = {
        "status": any(cfg.get('provider', {}).get('keyArn') for cfg in encryption_config),
        "description": "Checks if envelope encryption for Kubernetes secrets is enabled with a KMS key."
    }
    
    insights['public_endpoint'] = {
        "status": not cluster_raw.get('resourcesVpcConfig', {}).get('endpointPublicAccess', False),
        "description": "Checks if the cluster's API server endpoint is private (best practice)."
    }
    
    enabled_logs = cluster_raw.get('logging', {}).get('clusterLogging', [{}])[0].get('types', [])
    all_log_types = ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler']
    insights['logging_enabled'] = {
        "status": all(log_type in enabled_logs for log_type in all_log_types),
        "missing_logs": [lt for lt in all_log_types if lt not in enabled_logs],
        "description": "Checks if all control plane log types are enabled and sent to CloudWatch."
    }

    insights['latest_platform_version'] = {
        "status": False, "current": "N/A", "latest": "N/A",
        "description": "Checks if the cluster is running the latest EKS platform version."
    }
    try:
        eks_client.describe_update(name=cluster_raw['name'], updateId='dummy-id-for-platform-version')
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            msg = e.response['Error']['Message']
            if "Latest platform version for" in msg:
                latest_pv = msg.split(" is ")[-1].strip()
                current_pv = cluster_raw.get('platformVersion')
                insights['latest_platform_version']['status'] = (latest_pv == current_pv)
                insights['latest_platform_version']['current'] = current_pv
                insights['latest_platform_version']['latest'] = latest_pv
    
    return insights

# --- Main Data Aggregation Functions ---

def _process_cluster_data(c_raw, with_details=False, eks_client=None, role_arn=None):
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
    }

    if with_details and eks_client:
        managed_nodegroups_raw = fetch_managed_nodegroups(eks_client, c_raw["name"])
        karpenter_nodes_raw = fetch_karpenter_nodes_for_cluster(
            c_raw["name"], 
            c_raw["endpoint"], 
            c_raw["certificateAuthority"]["data"],
            role_arn
        )

        processed_nodegroups = []
        for ng in managed_nodegroups_raw:
            ng_data = {
                "name": ng.get("nodegroupName"), "status": ng.get("status"),
                "amiType": ng.get("amiType"), "instanceTypes": ng.get("instanceTypes", []),
                "releaseVersion": ng.get("releaseVersion"), "version": ng.get("version"),
                "createdAt": ng.get("createdAt"), "desiredSize": ng.get("scalingConfig", {}).get("desiredSize"),
                "is_karpenter_node": False
            }
            monthly_cost = 0
            if ng_data["desiredSize"] and ng_data["instanceTypes"]:
                price_per_hour = EC2_PRICING_ESTIMATES_PER_HOUR.get(ng_data["instanceTypes"][0].lower(), 0)
                monthly_cost = round(price_per_hour * ng_data["desiredSize"] * 24 * 30.5, 2)
            ng_data["estimatedMonthlyCostUSD"] = monthly_cost
            processed_nodegroups.append(ng_data)

        for node in karpenter_nodes_raw:
            node_data = {
                "name": node.get("name"), "status": node.get("status"),
                "amiType": node.get("amiType"), "instanceTypes": node.get("instanceTypes", []),
                "releaseVersion": node.get("releaseVersion"), "version": node.get("version"),
                "createdAt": node.get("createdAt"), "desiredSize": node.get("desiredSize"),
                "is_karpenter_node": True
            }
            monthly_cost = 0
            if node_data["desiredSize"] and node_data["instanceTypes"]:
                price_per_hour = EC2_PRICING_ESTIMATES_PER_HOUR.get(node_data["instanceTypes"][0].lower(), 0)
                monthly_cost = round(price_per_hour * node_data["desiredSize"] * 24 * 30.5, 2)
            node_data["estimatedMonthlyCostUSD"] = monthly_cost
            processed_nodegroups.append(node_data)
        
        cluster_data.update({
            "nodegroups_data": processed_nodegroups,
            "addons": fetch_addons_for_cluster(eks_client, c_raw["name"]),
            "fargate_profiles": fetch_fargate_profiles_for_cluster(eks_client, c_raw["name"]),
            "oidc_provider_url": fetch_oidc_provider_for_cluster(c_raw),
            "networking": { 
                "vpcId": c_raw.get("resourcesVpcConfig", {}).get("vpcId"),
                "subnetIds": c_raw.get("resourcesVpcConfig", {}).get("subnetIds", []),
                "endpointPublicAccess": c_raw.get("resourcesVpcConfig", {}).get("endpointPublicAccess"),
                "endpointPrivateAccess": c_raw.get("resourcesVpcConfig", {}).get("endpointPrivateAccess") 
            },
            "security_insights": get_security_insights(c_raw, eks_client)
        })

    return cluster_data


def get_live_eks_data():
    print("DEBUG_GLED: get_live_eks_data initiated.")
    regions_str = os.getenv("AWS_REGIONS", os.getenv("AWS_DEFAULT_REGION", "us-east-1"))
    target_regions = [r.strip() for r in regions_str.split(',') if r.strip()]
    target_roles_str = os.getenv("AWS_TARGET_ACCOUNTS_ROLES", "")
    
    accounts_to_scan = [{'role_arn': None, 'id': 'Primary Account'}]
    if target_roles_str:
        for role_arn in target_roles_str.split(','):
            if role_arn.strip():
                try:
                    accounts_to_scan.append({'role_arn': role_arn.strip(), 'id': role_arn.strip().split(':')[4]})
                except IndexError:
                    print(f"WARNING: Invalid Role ARN format: {role_arn}")

    all_clusters_raw = []
    errors = []
    for account in accounts_to_scan:
        session = get_session(account['role_arn'])
        if not session:
            errors.append(f"Failed to get session for account {account['id']}. Skipping.")
            continue
        for region in target_regions:
            try:
                eks = session.client('eks', region_name=region)
                paginator = eks.get_paginator('list_clusters')
                for page in paginator.paginate():
                    for name in page.get('clusters', []):
                        desc = eks.describe_cluster(name=name).get('cluster', {})
                        desc['region'] = region
                        all_clusters_raw.append(desc)
            except Exception as e:
                msg = f"Error scanning account {account['id']} in {region}: {e}"
                print(msg)
                errors.append(msg)

    processed_clusters = [_process_cluster_data(c) for c in all_clusters_raw]
    
    for cluster in processed_clusters:
        if isinstance(cluster.get('createdAt'), datetime):
            cluster['createdAt'] = cluster['createdAt'].isoformat()

    quick_info = {
        "total_clusters": len(processed_clusters),
        "clusters_with_health_issues": sum(1 for c in processed_clusters if c["health_issues"]),
        "clusters_with_upgrade_insights_attention": sum(1 for c in processed_clusters if c["upgrade_insight_status"] == "NEEDS_ATTENTION"),
        "clusters_nearing_eol_90_days": sum(1 for c in processed_clusters if c["is_nearing_eol_90_days"]),
        "accounts_running_kubernetes_clusters": len({c["account_id"] for c in processed_clusters if c.get("account_id") != "UnknownAccount"}),
        "regions_running_kubernetes_clusters": len({c["region"] for c in processed_clusters if c.get("region") != "Unknown Region"}),
    }
    
    final_data = {
        "clusters": processed_clusters,
        "quick_info": quick_info,
        "clusters_by_account_count": dict(Counter(c['account_id'] for c in processed_clusters)),
        "clusters_by_region_count": dict(Counter(c['region'] for c in processed_clusters)),
        "clusters_by_version_count": dict(Counter(c['version'] for c in processed_clusters)),
        "clusters_by_health_status_count": dict(Counter(c['health_status_summary'] for c in processed_clusters)),
        "errors": errors
    }
    print("DEBUG_GLED: get_live_eks_data finished.")
    return final_data

def get_single_cluster_details(account_id, region, cluster_name, role_arn=None):
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
        cluster_details = _process_cluster_data(cluster_raw, with_details=True, eks_client=eks_client, role_arn=role_arn)

        if isinstance(cluster_details.get('createdAt'), datetime):
            cluster_details['createdAt'] = cluster_details['createdAt'].isoformat()
        for ng in cluster_details.get('nodegroups_data', []):
            if isinstance(ng.get('createdAt'), datetime):
                ng['createdAt'] = ng['createdAt'].isoformat()
        for addon in cluster_details.get('addons', []):
             if isinstance(addon.get('createdAt'), datetime):
                addon['createdAt'] = addon['createdAt'].isoformat()
             if isinstance(addon.get('modifiedAt'), datetime):
                addon['modifiedAt'] = addon['modifiedAt'].isoformat()

        return cluster_details
    except Exception as e:
        msg = f"Error fetching details for cluster {cluster_name}: {e}"
        print(msg)
        return {"name": cluster_name, "errors": [msg]}
