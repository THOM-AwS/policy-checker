import boto3
import json

def assume_role(role_arn):
    sts_client = boto3.client('sts')
    response = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName='AssumeRoleSession'
    )
    credentials = response['Credentials']
    return credentials

def main():
    sts_client = boto3.client('sts')
    response = sts_client.get_caller_identity()
    master_account_arn = response['Arn']
    master_account_id = master_account_arn.split(':')[4]
    org_access_role_name = 'OrganizationAccountAccessRole'  

    sts_client = boto3.client('sts')
    response = sts_client.get_caller_identity()
    master_account_arn = response['Arn']
    org_access_role_arn = f'arn:aws:iam::{master_account_id}:role/{org_access_role_name}'  

    organizations_client = boto3.client('organizations')

    paginator = organizations_client.get_paginator('list_accounts')
    accounts_iterator = paginator.paginate()    
    
    for response in accounts_iterator:
        accounts = response['Accounts']        
    
        for account in accounts:
            account_id = account['Id']
            role_arn = f'arn:aws:iam::{account_id}:role/{org_access_role_name}'

            # Assume the organizational account access role
            try:
                credentials = assume_role(role_arn)
                
                # Create a new session using the assumed role credentials
                session = boto3.Session(
                    aws_access_key_id=credentials['AccessKeyId'],
                    aws_secret_access_key=credentials['SecretAccessKey'],
                    aws_session_token=credentials['SessionToken']
                )
                
                # Get the roles in the account
                iam_client = session.client('iam')
                response = iam_client.list_roles()
                roles = response['Roles']                
    
                print(f'Roles in account: {account_id}')
                for role in roles:
                    role_name = role['RoleName']
                    print(f'Role: {role_name}')
                    
                    # Get and print the trust relationship policy document
                    response = iam_client.get_role(RoleName=role_name)
                    role = response['Role']
                    trust_policy = role['AssumeRolePolicyDocument']
                    
                    with open(f'{account_id}_{role_name}_trust_policy.json', 'w') as f:
                        json.dump(trust_policy, f, indent=4)
                    print(f'Trust Policy: {trust_policy}')
            except:
                with open(f'{account_id}_FAIL.json', 'w') as f:
                    print("failed on ", account_id)
                    continue
            print('------------------')

if __name__ == '__main__':
    main()