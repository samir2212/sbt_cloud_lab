import os
import subprocess
import urllib.request
import boto3
import botocore
import json
import time

# Version of Terraform that we're using
TERRAFORM_VERSION = '1.3.4'

# Download URL for Terraform
TERRAFORM_DOWNLOAD_URL = (
    'https://releases.hashicorp.com/terraform/%s/terraform_%s_linux_amd64.zip'
    % (TERRAFORM_VERSION, TERRAFORM_VERSION))

# Paths where Terraform should be installed
TERRAFORM_DIR = os.path.join('/tmp', 'terraform_%s' % TERRAFORM_VERSION)
TERRAFORM_PATH = os.path.join(TERRAFORM_DIR, 'terraform')

def access_user_account(accountARN, region):
    # Create session using your current creds
    boto_sts=boto3.client('sts')

    # Request to assume the role like this, the ARN is the Role's ARN from
    # the other account you wish to assume. Not your current ARN.
    stsresponse = boto_sts.assume_role(
        RoleArn=accountARN,
        RoleSessionName='newsession'
    )

    # Save the details from assumed role into global vars
    newsession_id = stsresponse["Credentials"]["AccessKeyId"]
    newsession_key = stsresponse["Credentials"]["SecretAccessKey"]
    newsession_token = stsresponse["Credentials"]["SessionToken"]

    # Use the assumed session vars to create a new boto3 client with the assumed role creds
    # Here I create an s3 client using the assumed creds.
    global assumed_session
    assumed_session = boto3.session.Session(
        region_name=region,
        aws_access_key_id=newsession_id,
        aws_secret_access_key=newsession_key,
        aws_session_token=newsession_token
    )

import boto3

def cloudwatch_rules_deletion():
    client = assumed_session.client('events')
    rules = client.list_rules()['Rules']
    for rule in rules:
        rule_targets = client.list_targets_by_rule(
            Rule=rule['Name']
        )['Targets']
        target_ids = [target['Id'] for target in rule_targets]
        remove_targets_response = client.remove_targets(
            Rule=rule['Name'],
            Ids=target_ids
        )
        print(remove_targets_response)
        delete_rule_response = client.delete_rule(
            Name=rule['Name']
        )
        print(delete_rule_response)

#create terraform user with access and secret key
#username need to be the same name like terraform_user_name
def create_terraform_destory_keys():
    keys = [ ]
    iam = assumed_session.client('iam')
    response = iam.create_user(
      UserName='terraform_destroy'
    )
    access_secrete_key = iam.create_access_key(
    UserName='terraform_destroy'
    )
    keys.append(access_secrete_key['AccessKey']['AccessKeyId'])
    keys.append(access_secrete_key['AccessKey']['SecretAccessKey'])
    return keys

def create_default_terraform_destory_iam_policy():
    # Create IAM client
    iam = assumed_session.client('iam')

    # Create a policy

    my_managed_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }
        ]
    }

    default_policy_response = iam.create_policy(
        PolicyName='terraform_destroy_default_policy',
        PolicyDocument=json.dumps(my_managed_policy)
    )
    print(default_policy_response ['Policy']['Arn'])
    return default_policy_response ['Policy']['Arn']

def attach_terraform_destroy_policy():
    terraform_destroy_policy_arn = create_default_terraform_destory_iam_policy()
    iam = assumed_session.client('iam')
    response = iam.attach_user_policy(
        UserName= 'terraform_destroy',
        PolicyArn=terraform_destroy_policy_arn
    )


def check_call(args):
    """Wrapper for subprocess that checks if a process runs correctly,
    and if not, prints stdout and stderr.
    """
    proc = subprocess.Popen(args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd='/tmp')
    stdout, stderr = proc.communicate()
    if proc.returncode != 0:
        print(stdout)
        print(stderr)
        raise subprocess.CalledProcessError(
            returncode=proc.returncode,
            cmd=args)


def install_terraform():
    """Install Terraform on the Lambda instance."""
    # http://docs.aws.amazon.com/lambda/latest/dg/lambda-introduction.html
    if os.path.exists(TERRAFORM_PATH):
        return

    urllib.request.urlretrieve(TERRAFORM_DOWNLOAD_URL, '/tmp/terraform.zip')
    data_type = '{}.zip'.format('/tmp/terraform.zip')

    # Flags:
    #   '-o' = overwrite existing files without prompting
    #   '-d' = output directory
    check_call(['unzip', '-o', '/tmp/terraform.zip', '-d', TERRAFORM_DIR])
    check_call([TERRAFORM_PATH, '--version'])

    print ("TERRAFORM_DIR : " + TERRAFORM_DIR)
    print("TERRAFORM_PATH : " + TERRAFORM_PATH)


def terraform_plan_apply(access_key,secret_key):
    """Download a Terraform plan from S3 and run a 'terraform apply'.
    :param s3_bucket: Name of the S3 bucket where the plan is stored.
    :param path: Path to the Terraform planfile in the S3 bucket.
    """

    BUCKET_NAME = 'terraform-scripts-sbt-vpc'
    KEY = 'nuke_destroy.zip'
    s3_client = boto3.client('s3')
    #Download private key file from secure S3 bucket
    s3_client.download_file(BUCKET_NAME, KEY, '/tmp/nuke_destroy.zip')
    # UNZIP CODEBASE
    print(subprocess.getstatusoutput('unzip /tmp/nuke_destroy.zip -d /tmp'))
    print("list /tmp/nuke_destroy")
    os.chdir('/tmp/nuke_destroy')
    cwd = os.getcwd()
    print(cwd)
    access_key = access_key
    secret_key = secret_key
    terraform_command = f'echo \'provider "aws" {{\n  region="eu-west-2"\n  access_key = "{access_key}"\n  secret_key = "{secret_key}"\n}}\' > provider.tf'
    status, output = subprocess.getstatusoutput(terraform_command)
    print(subprocess.getstatusoutput('cat provider.tf'))
    print(subprocess.getstatusoutput('/tmp/terraform_1.3.4/terraform fmt /tmp/nuke_destroy/provider.tf'))
    print(subprocess.getstatusoutput('/tmp/terraform_1.3.4/terraform fmt'))
    print(subprocess.getstatusoutput('echo "Done fmt"'))
    print(subprocess.getstatusoutput('/tmp/terraform_1.3.4/terraform init'))
    print(subprocess.getstatusoutput('echo "Done init"'))
    #print(subprocess.getstatusoutput('/tmp/terraform_1.3.4/terraform plan'))
    #print(subprocess.getstatusoutput('echo "Done plan"'))
    print(subprocess.getstatusoutput('/tmp/terraform_1.3.4/terraform destroy -auto-approve'))
    print(subprocess.getstatusoutput('echo "Done destroy"'))

def delete_all_iam_users():
    iam = assumed_session.client('iam')
    for user in iam.list_users()['Users']:
        response=iam.list_attached_user_policies(UserName=user["UserName"])
        policies_arn=[d['PolicyArn'] for d in response['AttachedPolicies']  if 'PolicyArn' in d]
        for policy_Arn in policies_arn:
                iam.detach_user_policy(UserName=user["UserName"],PolicyArn=policy_Arn)
        try:
            paginator = iam.get_paginator('list_access_keys')
            for response in paginator.paginate(UserName=user["UserName"],):
                  access_id=response['AccessKeyMetadata'][0]['AccessKeyId']
                  iam.delete_access_key(AccessKeyId=access_id, UserName=user["UserName"])
                  iam.delete_user(UserName=user['UserName'])
        except:
            try:
                iam.get_login_profile(UserName='sbt-user')
                iam.delete_login_profile(UserName=user["UserName"])
                iam.delete_user(UserName=user['UserName'])
            except:
                #logger.error('No Login Profile')
                iam.delete_user(UserName=user['UserName'])
    print("all_users_are_deleted")

def delete_all_customer_managed_policies():
    iam = assumed_session.client('iam')
    for policies_arn in iam.list_policies(Scope = 'Local')['Policies']:
        iam.delete_policy(PolicyArn=policies_arn['Arn'])

def delete_all_customer_created_roles():
    iam = assumed_session.client('iam')
    roles = iam.list_roles()
    Role_list = roles['Roles']
    for key in Role_list:
        response = iam.list_role_tags(RoleName=key['RoleName'])
        for tags in response['Tags']:
            if any("CloudLabRole" in values for values in tags.values()):
                #print("key exists in list_of_dictionaries")
                response=iam.list_attached_role_policies(RoleName=key['RoleName'])
                policies_arn=[d['PolicyArn'] for d in response['AttachedPolicies']  if 'PolicyArn' in d]
                for policy_Arn in policies_arn:
                    iam.detach_role_policy(RoleName=key['RoleName'],PolicyArn=policy_Arn)
                instance_profiles_for_role= iam.list_instance_profiles_for_role(RoleName=key['RoleName'])
                instance_profiles_names_list=[d['InstanceProfileName'] for d in instance_profiles_for_role['InstanceProfiles']  if 'InstanceProfileName' in d]
                for instance_profiles_names in instance_profiles_names_list:
                    iam.remove_role_from_instance_profile(InstanceProfileName= instance_profiles_names,RoleName=key['RoleName'])
                iam.delete_role(RoleName=key['RoleName'])
                print(key['RoleName'] +" roles are deleted")
            else:
              print("key does not exists in list_of_dictionaries "+key['RoleName'])

def delete_instances_profile():
    iam = assumed_session.client('iam')
    response = iam.list_instance_profiles()
    instance_profile_name=[d['InstanceProfileName'] for d in response['InstanceProfiles']  if 'InstanceProfileName' in d]
    response = iam.delete_instance_profile(
    InstanceProfileName=instance_profile_name[0]
    )
def lambda_handler(event, context):
    ## In prod we can pass user_id from request_id or any unique_id from the event
    access_user_account('arn:aws:iam::629045748974:role/OrganizationAccountAccessRole', 'eu-west-2')
    cloudwatch_rules_deletion()
    install_terraform()
    keys=create_terraform_destory_keys()
    attach_terraform_destroy_policy()
    access_key=keys[0]
    secret_key=keys[1]
    terraform_plan_apply(access_key,secret_key)
    delete_all_iam_users()
    delete_all_customer_managed_policies()
    delete_all_customer_created_roles()
    delete_instances_profile()
