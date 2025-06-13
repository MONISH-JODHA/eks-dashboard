import boto3

def get_identity_store_id():
    """Get the Identity Store ID from the SSO Admin instance."""
    sso_admin = boto3.client('sso-admin')
    response = sso_admin.list_instances()
    if not response['Instances']:
        raise Exception("No Identity Center instances found.")
    
    identity_store_id = response['Instances'][0]['IdentityStoreId']
    return identity_store_id

def get_group_id_by_name(identity_store_id, group_name):
    """Search for a group by display name and return its Group ID."""
    identitystore = boto3.client('identitystore')
    response = identitystore.list_groups(
        IdentityStoreId=identity_store_id,
        Filters=[{
            'AttributePath': 'DisplayName',
            'AttributeValue': group_name
        }]
    )
    
    groups = response.get('Groups', [])
    if not groups:
        raise Exception(f"Group '{group_name}' not found.")
    
    group_id = groups[0]['GroupId']
    return group_id

def main():
    group_name = "dev-team"  # Change this to the group you're searching for
    try:
        identity_store_id = get_identity_store_id()
        group_id = get_group_id_by_name(identity_store_id, group_name)
        print(f"Group '{group_name}' has ID: {group_id}")
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()