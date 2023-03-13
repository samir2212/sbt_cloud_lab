import os
import subprocess
import urllib.request
import boto3
import botocore
import json

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

#create terraform user with access and secret key
def create_terraform_user(terraform_user_name):
    keys = [ ]
    iam = assumed_session.client('iam')

    response = iam.create_user(
      UserName=terraform_user_name
    )
    access_secrete_key = iam.create_access_key(
    UserName=terraform_user_name
    )
    keys.append(access_secrete_key['AccessKey']['AccessKeyId'])
    keys.append(access_secrete_key['AccessKey']['SecretAccessKey'])
    return keys
#create SBT user with console password and the functions returns all credentials needed to sign in.
def create_normal_user(name):
    iam = assumed_session.client('iam')
    password="Securityblueteam123@"

    create_user = iam.create_user(
      UserName=name
    )

    create_login_password = iam.create_login_profile(
    UserName=name,
    Password=password,
    PasswordResetRequired=False
    )

    user_arn= create_user['User']['Arn']
    account_number=user_arn[13:25]  ### To get account id no boto3 function or response that get sing-in
    url= "https://{}.signin.aws.amazon.com/console".format(account_number)
    print("The user-name is "+name +" The passowrd is "+ password +" The console sign in url is " + url)

def create_default_user_iam_policy(lab_ip):
    # Create IAM client
    iam = assumed_session.client('iam')
    sbt_lab_ip=lab_ip

    # Create a policy

    my_managed_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "NotIpAddress": {
                       "aws:SourceIp": [
                           sbt_lab_ip
                        ]
                    }
                }
            }
        ]
    }

    default_policy_response = iam.create_policy(
        PolicyName='user_default_policy',
        PolicyDocument=json.dumps(my_managed_policy)
    )
    print(default_policy_response ['Policy']['Arn'])
    return default_policy_response ['Policy']['Arn']

def attach_default_user_policy(name, lab_ip):
    default_user_policy_arn = create_default_user_iam_policy(lab_ip)
    iam = assumed_session.client('iam')
    response = iam.attach_user_policy(
        UserName= name,
        PolicyArn=default_user_policy_arn
    )


def read_normal_user_policy(user_policy_dict):
    policies_arn=[]
    path = "./sbt_user_policy"
    os.chdir(path)
    for file in os.listdir():
        for user_dict_policy_value in user_policy_dict:
        #for user_dict_policy_value in user_policy_dict.values():
            if file == user_dict_policy_value:
               my_managed_policy = open(file,'r')
               user_policy=my_managed_policy.read()
               print(user_policy)
               policies_arn.append(create_normal_user_iam_policy(user_policy,file))
        else:
            print("Other Policy can not be attached as it does not exist in user_policy_dict")
        #my_managed_policy = open(file_path,'r')
        #user_policy=my_managed_policy.read()
        #print(user_policy)
        #policies_arn.append(create_normal_user_iam_policy(user_policy,file_path))
    return policies_arn


#Create SBT user policy
def create_normal_user_iam_policy(my_managed_policy,user_policy_name):
    # Create IAM client
    iam = assumed_session.client('iam')
    #my_managed_policy= open('./sbt_user_policy/user_1_policy.json','r')
    response = iam.create_policy(
        PolicyName=user_policy_name,
        PolicyDocument=my_managed_policy
    )
    print(response['Policy']['Arn'])
    return response['Policy']['Arn']

def attach_user_policy(name,user_policy_dict):
    policies_Arn=read_normal_user_policy(user_policy_dict)
    iam = assumed_session.client('iam')
    for policy in policies_Arn:
        response = iam.attach_user_policy(
        UserName=name,
        PolicyArn = policy
        )


def read_terraform_user_policy():
    terraform_policies_arn=[]
    terraform_path = ".././terraform_user_policy"
    os.chdir(terraform_path)
    for terraform_policy_file in os.listdir():
        terraform_file_path = f"{terraform_policy_file}"
        if os.path.isfile(terraform_file_path):
            print("File exists"+ terraform_file_path)
        else:
            print("file does not exist" + terraform_file_path)
        terraform_my_managed_policy = open(terraform_file_path,'r')
        terraform_policy=terraform_my_managed_policy .read()
        terraform_policies_arn.append(create_terraform_iam_policy(terraform_policy,terraform_file_path))
    return terraform_policies_arn
#Create Terrafrom policy
def create_terraform_iam_policy(terraform_my_managed_policy,terraform_policy_name):
    # Create IAM client
    iam = assumed_session.client('iam')
    # Create a policy
    response = iam.create_policy(
        PolicyName=terraform_policy_name,
        PolicyDocument=terraform_my_managed_policy
    )
    print(response['Policy']['Arn'])
    return response['Policy']['Arn']

def attach_terraform_policy(terraform_user_name):
    terraform_policies_Arn=read_terraform_user_policy()
    iam = assumed_session.client('iam')
    for terraform_policy in terraform_policies_Arn:
        response = iam.attach_user_policy(
        UserName=terraform_user_name,
        PolicyArn = terraform_policy
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
    KEY = 'Archive.zip'
    s3_client = boto3.client('s3')
    #Download private key file from secure S3 bucket
    s3_client.download_file(BUCKET_NAME, KEY, '/tmp/Archive.zip')
    # UNZIP CODEBASE
    print(subprocess.getstatusoutput('unzip /tmp/Archive.zip -d /tmp'))
    print("list /tmp/Archive")
    os.chdir('/tmp/Archive')
    cwd = os.getcwd()
    print(cwd)
    access_key = access_key
    secret_key = secret_key
    terraform_command = f'echo \'provider "aws" {{\n  region="eu-west-2"\n  access_key = "{access_key}"\n  secret_key = "{secret_key}"\n}}\' > provider.tf'
    status, output = subprocess.getstatusoutput(terraform_command)
    print(subprocess.getstatusoutput('cat provider.tf'))
    print(subprocess.getstatusoutput('/tmp/terraform_1.3.4/terraform fmt /tmp/Archive/provider.tf'))
    print(subprocess.getstatusoutput('/tmp/terraform_1.3.4/terraform fmt'))
    print(subprocess.getstatusoutput('echo "Done fmt"'))
    print(subprocess.getstatusoutput('/tmp/terraform_1.3.4/terraform init'))
    print(subprocess.getstatusoutput('echo "Done init"'))
    print(subprocess.getstatusoutput('/tmp/terraform_1.3.4/terraform plan'))
    print(subprocess.getstatusoutput('echo "Done plan"'))
    print(subprocess.getstatusoutput('/tmp/terraform_1.3.4/terraform apply -auto-approve'))
    print(subprocess.getstatusoutput('echo "Done apply"'))
    #print(subprocess.getstatusoutput('/tmp/terraform_1.3.4/terraform destroy -auto-approve'))
    #print(subprocess.getstatusoutput('echo "Done destroy"'))

def lambda_handler(event, context):

    ## In prod we can pass user_id from request_id or any unique_id from the event
    access_user_account('arn:aws:iam::629045748974:role/OrganizationAccountAccessRole', 'eu-west-2')
    user_policy_dict = event["Policies"]
    name="sbt-user"
    create_normal_user(name)
    attach_default_user_policy(name,event["UserIp"])
    attach_user_policy(name,user_policy_dict)
    terraform_user_name="terraform_user"
    keys=create_terraform_user(terraform_user_name)
    attach_terraform_policy(terraform_user_name)
    install_terraform()
    access_key=keys[0]
    secret_key=keys[1]
    terraform_plan_apply(access_key,secret_key)
