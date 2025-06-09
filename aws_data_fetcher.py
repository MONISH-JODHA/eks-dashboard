import boto3
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from datetime import datetime, timezone, timedelta
import os
import json

EKS_EOL_DATES = {
    "1.23": datetime(2024, 6, 4, tzinfo=timezone.utc),
    "1.24": datetime(2024, 8, 1, tzinfo=timezone.utc),
    "1.25": datetime(2024, 10, 22, tzinfo=timezone.utc),
    "1.26": datetime(2025, 1, 22, tzinfo=timezone.utc),
    "1.27": datetime(2025, 6, 22, tzinfo=timezone.utc),
    "1.28": datetime(2025, 7, 22, tzinfo=timezone.utc),
    "1.29": datetime(2025, 11, 1, tzinfo=timezone.utc),
}

def pp_debug(label, data):
    try:
        print(f"DEBUG: {label}:\n{json.dumps(data, indent=2, default=str)}")
    except TypeError:
        print(f"DEBUG: {label}: {data} (Could not JSON serialize fully)")

def get_eks_client(region_name=None):
    try:
        effective_region = region_name or os.getenv("AWS_DEFAULT_REGION")
        if not effective_region:
            client = boto3.client('eks')
        else:
            client = boto3.client('eks', region_name=effective_region)
        return client
    except (NoCredentialsError, PartialCredentialsError):
        print("ERROR_GFX: AWS credentials not found or incomplete in get_eks_client.")
        return None
    except Exception as e:
        print(f"ERROR_GFX: Error creating EKS client: {e}")
        return None

def fetch_nodegroups_for_cluster(eks_client, cluster_name, region_name):
    nodegroups_details = []
    try:
        nodegroups_response = eks_client.list_nodegroups(clusterName=cluster_name)
        nodegroup_names = nodegroups_response.get('nodegroups', [])
        for ng_name in nodegroup_names:
            try:
                ng_desc_response = eks_client.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng_name)
                nodegroup_data = ng_desc_response.get('nodegroup', {})
                if nodegroup_data:
                    nodegroups_details.append(nodegroup_data)
            except ClientError as e:
                print(f"ERROR_FNFC: describing nodegroup {ng_name} for {cluster_name}: {e}")
                nodegroups_details.append({"nodegroupName": ng_name, "status": "ERROR_DESCRIBING_NODEGROUP", "error_message": str(e)})
    except ClientError as e:
        print(f"ERROR_FNFC: listing nodegroups for {cluster_name}: {e}")
    return nodegroups_details

def fetch_all_clusters_in_region(eks_client, region_name):
    clusters_details = []
    try:
        list_clusters_response = eks_client.list_clusters()
        cluster_names = list_clusters_response.get('clusters', [])
        if not cluster_names: return []
        for name in cluster_names:
            try:
                describe_cluster_response = eks_client.describe_cluster(name=name)
                cluster_info = describe_cluster_response.get('cluster', {})
                if not cluster_info: continue
                cluster_info['region'] = region_name
                cluster_info['nodegroups'] = fetch_nodegroups_for_cluster(eks_client, name, region_name)
                clusters_details.append(cluster_info)
            except ClientError as e:
                print(f"ERROR_FACIR: describing cluster {name} in {region_name}: {e}")
                clusters_details.append({"name": name, "arn": f"arn:aws:eks:{region_name}:<unknown>:cluster/{name}", "version": "Unknown", "status": "ERROR_DESCRIBING_CLUSTER", "region": region_name, "createdAt": datetime.now(timezone.utc), "health_issues": [{"code": "DescribeFailed", "message": str(e)}], "nodegroups": []})
        return clusters_details
    except ClientError as e:
        print(f"ERROR_FACIR: listing clusters in {region_name}: {e}")
        return []

def get_live_eks_data():
    print("DEBUG_GLED: get_live_eks_data initiated.")
    regions_str = os.getenv("AWS_REGIONS", os.getenv("AWS_DEFAULT_REGION", "us-east-1"))
    target_regions = [region.strip() for region in regions_str.split(',')]
    all_clusters_raw = []
    overall_error_messages = []

    for region_name in target_regions:
        eks_client = get_eks_client(region_name=region_name)
        if not eks_client:
            overall_error_messages.append(f"Could not create EKS client for region {region_name}.")
            continue
        all_clusters_raw.extend(fetch_all_clusters_in_region(eks_client, region_name))

    if not all_clusters_raw and not overall_error_messages:
        overall_error_messages.append("No EKS clusters found or connection failed.")

    processed_clusters = []
    now = datetime.now(timezone.utc)
    ninety_days_from_now = now + timedelta(days=90)

    for c_raw in all_clusters_raw:
        account_id = "UnknownAccount"
        cluster_arn = c_raw.get("arn", "")
        if cluster_arn and isinstance(cluster_arn, str) and cluster_arn.count(':') >= 4:
            try: account_id = cluster_arn.split(':')[4]
            except IndexError: pass

        version = c_raw.get("version", "Unknown")
        status = c_raw.get("status", "Unknown")
        health_info = c_raw.get("health", {})
        health_issues = health_info.get("issues", c_raw.get("health_issues", []))
        health_status_summary_val = "HEALTHY" if not health_issues else "HAS_ISSUES"
        if status.startswith("ERROR_"): health_status_summary_val = "UNKNOWN"

        eol_date = EKS_EOL_DATES.get(version)
        is_nearing_eol_90_days = False
        if eol_date and eol_date <= ninety_days_from_now and eol_date > now:
            is_nearing_eol_90_days = True

        upgrade_insight_status_val = "PASSING"
        if version != "Unknown" and version < "1.27": upgrade_insight_status_val = "NEEDS_ATTENTION"
        if status == "UPDATING": upgrade_insight_status_val = "IN_PROGRESS"
        if status.startswith("ERROR_"): upgrade_insight_status_val = "ERROR"
        
        upgrade_policy_mock_val = "STANDARD"
        if "dev" in c_raw.get("name", "").lower(): upgrade_policy_mock_val = "DEV_CYCLE"
        
        processed_nodegroups = []
        for ng_raw in c_raw.get('nodegroups', []):
            processed_nodegroups.append({"name": ng_raw.get("nodegroupName"), "status": ng_raw.get("status"), "amiType": ng_raw.get("amiType"), "instanceTypes": ng_raw.get("instanceTypes", []), "desiredSize": ng_raw.get("scalingConfig", {}).get("desiredSize"), "releaseVersion": ng_raw.get("releaseVersion"), "version": ng_raw.get("version"), "createdAt": ng_raw.get("createdAt"), "tags": ng_raw.get("tags", {})})

        processed_clusters.append({"name": c_raw.get("name", "Unknown Cluster"), "arn": cluster_arn, "account_id": account_id, "version": version, "platformVersion": c_raw.get("platformVersion"), "status": status, "region": c_raw.get("region", "Unknown Region"), "createdAt": c_raw.get("createdAt", now), "health_issues": health_issues, "upgrade_insight_status": upgrade_insight_status_val, "health_status_summary": health_status_summary_val, "nodegroups_data": processed_nodegroups, "upgrade_policy_mock": upgrade_policy_mock_val, "is_nearing_eol_90_days": is_nearing_eol_90_days, "tags": c_raw.get("tags", {})})

    total_clusters_agg = len(processed_clusters)
    nearing_eol_agg = sum(1 for c in processed_clusters if c["is_nearing_eol_90_days"])

    # Initialize aggregations
    clusters_by_upgrade_policy_agg, clusters_by_health_status_agg, clusters_by_upgrade_insight_agg = {}, {}, {}
    clusters_by_version_agg, clusters_by_region_agg, clusters_by_account_agg, mock_clusters_by_ou_agg = {}, {}, {}, {}

    if not processed_clusters:
        for agg_dict in [clusters_by_upgrade_policy_agg, clusters_by_health_status_agg, clusters_by_upgrade_insight_agg, clusters_by_version_agg, clusters_by_region_agg, clusters_by_account_agg, mock_clusters_by_ou_agg]:
            agg_dict["No Data"] = 0 
    else:
        for c in processed_clusters:
            clusters_by_upgrade_policy_agg[c.get("upgrade_policy_mock", "UNKNOWN")] = clusters_by_upgrade_policy_agg.get(c.get("upgrade_policy_mock", "UNKNOWN"), 0) + 1
            clusters_by_health_status_agg[c.get("health_status_summary", "UNKNOWN")] = clusters_by_health_status_agg.get(c.get("health_status_summary", "UNKNOWN"), 0) + 1
            clusters_by_upgrade_insight_agg[c.get("upgrade_insight_status", "UNKNOWN")] = clusters_by_upgrade_insight_agg.get(c.get("upgrade_insight_status", "UNKNOWN"), 0) + 1
            clusters_by_version_agg[c.get("version", "Unknown")] = clusters_by_version_agg.get(c.get("version", "Unknown"), 0) + 1
            clusters_by_region_agg[c.get("region", "Unknown Region")] = clusters_by_region_agg.get(c.get("region", "Unknown Region"), 0) + 1
            clusters_by_account_agg[c.get("account_id", "UnknownAccount")] = clusters_by_account_agg.get(c.get("account_id", "UnknownAccount"), 0) + 1
        if clusters_by_account_agg and not (len(clusters_by_account_agg)==1 and ("No Data" in clusters_by_account_agg or "UnknownAccount" in clusters_by_account_agg)):
            for acc_id, count in clusters_by_account_agg.items():
                if acc_id not in ["UnknownAccount", "No Data"]:
                    mock_clusters_by_ou_agg[f"ou-{acc_id[:4]}-prod"] = count
        elif total_clusters_agg > 0: 
             mock_clusters_by_ou_agg["ou-default-generated"] = total_clusters_agg
        else: 
            mock_clusters_by_ou_agg["No Data"] = 0


    clusters_eol_schedule_agg = {"Nearing EOL (90 days)": nearing_eol_agg, "Not Immediately Nearing EOL": total_clusters_agg - nearing_eol_agg}
    if total_clusters_agg == 0: clusters_eol_schedule_agg = {"No Data": 0}

    mock_extended_support_cost_projection = {"labels": ["30 Days", "60 Days", "90 Days", "120 Days", "180 Days", "365 Days"], "projected_costs_usd": [0.0] * 6}
    if processed_clusters:
        cost_per_cluster_monthly = 432; temp_costs = []
        for days_out_str in mock_extended_support_cost_projection["labels"]:
            days_out = int(days_out_str.split(" ")[0]); clusters_in_ext_support = 0
            for c in processed_clusters:
                eol = EKS_EOL_DATES.get(c["version"])
                if eol and (now > eol or eol < (now + timedelta(days=days_out))): clusters_in_ext_support +=1
            num_months = max(1, days_out // 30) if clusters_in_ext_support > 0 else 0
            temp_costs.append(round(clusters_in_ext_support * cost_per_cluster_monthly * num_months, 2))
        mock_extended_support_cost_projection["projected_costs_usd"] = temp_costs
    
    clusters_by_provider_type_agg = {"EKS": total_clusters_agg} if total_clusters_agg > 0 else {"No Data":0}

    accounts_running_clusters_agg = {c.get("account_id") for c in processed_clusters if c.get("account_id") and c.get("account_id") != "UnknownAccount"}
    regions_running_clusters_agg = {c.get("region") for c in processed_clusters if c.get("region") and c.get("region") != "Unknown Region"}

    final_data_to_return = {
        "clusters": processed_clusters,
        "quick_info": {
            "total_clusters": total_clusters_agg,
            "clusters_with_health_issues": sum(1 for c in processed_clusters if c.get("health_issues")),
            "clusters_with_upgrade_insights_attention": sum(1 for c in processed_clusters if c.get("upgrade_insight_status") == "NEEDS_ATTENTION"),
            "clusters_nearing_eol_90_days": nearing_eol_agg,
            "kubernetes_clusters_count": total_clusters_agg,
            "accounts_running_kubernetes_clusters": len(accounts_running_clusters_agg),
            "regions_running_kubernetes_clusters": len(regions_running_clusters_agg),
            "organizational_units_running_kubernetes_clusters": len(mock_clusters_by_ou_agg) if not (len(mock_clusters_by_ou_agg)==1 and "No Data" in mock_clusters_by_ou_agg) else 0,
            "total_nodegroups": sum(len(p.get("nodegroups_data", [])) for p in processed_clusters),
            "active_nodegroups": sum(1 for p in processed_clusters for ng in p.get("nodegroups_data", []) if ng.get("status") == "ACTIVE")
        },
        "clusters_by_version_count": clusters_by_version_agg,
        "clusters_by_region_count": clusters_by_region_agg,
        "clusters_by_account_count": clusters_by_account_agg,
        "clusters_by_ou_count": mock_clusters_by_ou_agg,
        "clusters_by_upgrade_policy_count": clusters_by_upgrade_policy_agg,
        "clusters_eol_schedule_count": clusters_eol_schedule_agg,
        "clusters_by_health_status_count": clusters_by_health_status_agg,
        "extended_support_cost_projection_data": mock_extended_support_cost_projection,
        "clusters_by_upgrade_insight_count": clusters_by_upgrade_insight_agg,
        "clusters_by_provider_type_count": clusters_by_provider_type_agg,
        "errors": overall_error_messages
    }
    pp_debug("GLED: Final data object being returned to app.py", final_data_to_return)
    print("DEBUG_GLED: get_live_eks_data finished.")
    return final_data_to_return