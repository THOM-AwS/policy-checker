import boto3
import json

def get_all_accounts():
    organizations_client = boto3.client('organizations')
    paginator = organizations_client.get_paginator('list_accounts')
    accounts_iterator = paginator.paginate()
    all_accounts = []
    for response in accounts_iterator:
        accounts = response['Accounts']
        all_accounts.extend(accounts)
    return all_accounts

def print_discovered_accounts(accounts):
    print('Discovered AWS Accounts:')
    for account in accounts:
        account_id = account['Id']
        account_name = account['Name']
        print(f'Account ID: {account_id}, Account Name: {account_name}')

def assume_role(role_arn):
    sts_client = boto3.client('sts')
    response = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName='AssumeRoleSession'
    )
    credentials = response['Credentials']
    print('Assuming role to next account....')
    return credentials

def get_role_policies(session, role_name, account_id):
    iam_client = session.client('iam')
    inline_policies_response = iam_client.list_role_policies(RoleName=role_name)
    inline_policies = inline_policies_response['PolicyNames']
    attached_policies_response = iam_client.list_attached_role_policies(RoleName=role_name)
    attached_policies = attached_policies_response['AttachedPolicies']

    policies = {'inline': [], 'attached': {}}

    for inline_policy_name in inline_policies:
        policy_response = iam_client.get_role_policy(RoleName=role_name, PolicyName=inline_policy_name)
        policy_document = policy_response['PolicyDocument']
        policies['inline'].append(policy_document)

    for attached_policy in attached_policies:
        policy_arn = attached_policy['PolicyArn']
        policy_response = iam_client.get_policy(PolicyArn=policy_arn)
        policy_version = iam_client.get_policy_version(PolicyArn=policy_arn,
                                                       VersionId=policy_response['Policy']['DefaultVersionId'])
        policy_document = policy_version['PolicyVersion']['Document']
        policies['attached'][policy_arn]=policy_document
        # dump_policy(acc, arn, document)
        # policies['attached'].append(policy_arn)


    return policies

def get_roles(session, roles, account_id):

    for role in roles:
        role_name = role['RoleName']
        print(f'Role: {role_name}')
        try:
            # Get and print the role policies
            role_policies = get_role_policies(session, role_name, account_id)
            
            with open(f'./permissions/{account_id}_{role_name}_permission_policy.json', 'w') as f:
                        json.dump(role_policies, f, indent=4)

            print (json.dumps(role_policies))
            # for policy_document in role_policies:
            #     print(f'Policy Document: {policy_document}')

        except Exception as e:
            print(f'Failed on account {account_id}: {str(e)}')

def process_role_policies(accounts):
    org_access_role_name = 'OrganizationAccountAccessRole'
    sts_client = boto3.client('sts')
    response = sts_client.get_caller_identity()
    master_account_arn = response['Arn']
    master_account_id = master_account_arn.split(':')[4]
    print(master_account_id)

    print('\nProcessing role policies...\n')

    for account in accounts:
        account_id = account['Id']

        if account_id == master_account_id:
            # iam_client = boto3.client('iam')
            # response = iam_client.list_roles()
            # roles = response['Roles']
            # print(f'Roles in master account')
            # get_roles(roles, account_id)
            continue
        else:
            role_arn = f'arn:aws:iam::{account_id}:role/{org_access_role_name}'
            credentials = assume_role(role_arn)
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

            get_roles(session, roles, account_id)

def main():
    accounts = get_all_accounts()
    print_discovered_accounts(accounts)
    process_role_policies(accounts)

if __name__ == '__main__':
    main()
