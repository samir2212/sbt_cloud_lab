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

#create terraform user with access and secret key
#username need to be the same name like terraform_user_name
def create_terraform_user_keys():
    keys = [ ]
    iam = assumed_session.client('iam')
    access_secrete_key = iam.create_access_key(
    UserName="terraform_user"
    )
    keys.append(access_secrete_key['AccessKey']['AccessKeyId'])
    keys.append(access_secrete_key['AccessKey']['SecretAccessKey'])
    return keys




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
    KEY = 'aws_nuke.zip'
    s3_client = boto3.client('s3')
    #Download private key file from secure S3 bucket
    s3_client.download_file(BUCKET_NAME, KEY, '/tmp/aws_nuke.zip')
    # UNZIP CODEBASE
    print(subprocess.getstatusoutput('unzip /tmp/aws_nuke.zip -d /tmp'))
    print("list /tmp/aws_nuke")
    os.chdir('/tmp/aws_nuke')
    cwd = os.getcwd()
    print(cwd)
    access_key = access_key
    secret_key = secret_key
    terraform_command = f'echo \'provider "aws" {{\n  region="eu-west-2"\n  access_key = "{access_key}"\n  secret_key = "{secret_key}"\n}}\' > provider.tf'
    status, output = subprocess.getstatusoutput(terraform_command)
    print(subprocess.getstatusoutput('cat provider.tf'))
    print(subprocess.getstatusoutput('/tmp/terraform_1.3.4/terraform fmt /tmp/aws_nuke/provider.tf'))
    print(subprocess.getstatusoutput('/tmp/terraform_1.3.4/terraform fmt'))
    print(subprocess.getstatusoutput('echo "Done fmt"'))
    print(subprocess.getstatusoutput('/tmp/terraform_1.3.4/terraform init'))
    print(subprocess.getstatusoutput('echo "Done init"'))
    print(subprocess.getstatusoutput('/tmp/terraform_1.3.4/terraform plan'))
    print(subprocess.getstatusoutput('echo "Done plan"'))
    print(subprocess.getstatusoutput('/tmp/terraform_1.3.4/terraform apply -auto-approve'))
    print(subprocess.getstatusoutput('echo "Done apply"'))

def lambda_handler(event, context):
    ## In prod we can pass user_id from request_id or any unique_id from the event
    access_user_account('arn:aws:iam::629045748974:role/OrganizationAccountAccessRole', 'eu-west-2')
    install_terraform()
    keys=create_terraform_user_keys()
    access_key=keys[0]
    secret_key=keys[1]
    terraform_plan_apply(access_key,secret_key)
 
