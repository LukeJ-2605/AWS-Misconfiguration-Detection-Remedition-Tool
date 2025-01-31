import boto3
from botocore.exceptions import ClientError

def check_s3_buckets():
    """Check for misconfigured S3 buckets."""
    s3 = boto3.client('s3')
    try:
        response = s3.list_buckets()
        for bucket in response['Buckets']:
            bucket_name = bucket['Name']
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            public = any(
                grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers'
                for grant in acl['Grants']
            )
            encryption = None
            try:
                encryption = s3.get_bucket_encryption(Bucket=bucket_name)
            except ClientError:
                pass

            print(f"Bucket: {bucket_name}")
            print(f"  Public Access: {'Yes' if public else 'No'}")
            print(f"  Encryption: {'Enabled' if encryption else 'Disabled'}")
    except ClientError as e:
        print(f"Error fetching bucket details: {e}")

def check_iam_users():
    """Check for IAM misconfigurations."""
    iam = boto3.client('iam')
    try:
        users = iam.list_users()['Users']
        for user in users:
            print(f"User: {user['UserName']}")
            access_keys = iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
            for key in access_keys:
                print(f"  Access Key: {key['AccessKeyId']} (Status: {key['Status']})")
    except ClientError as e:
        print(f"Error fetching IAM details: {e}")

def check_security_groups():
    """Check for overly permissive security groups."""
    ec2 = boto3.client('ec2')
    try:
        response = ec2.describe_security_groups()
        for sg in response['SecurityGroups']:
            for perm in sg['IpPermissions']:
                for ip_range in perm.get('IpRanges', []):
                    if ip_range['CidrIp'] == '0.0.0.0/0':
                        print(f"Security Group: {sg['GroupName']} ({sg['GroupId']}) allows open access!")
    except ClientError as e:
        print(f"Error fetching security group details: {e}")

def main():
    print("Starting AWS Misconfiguration Checks...")
    print("\nChecking S3 Buckets...")
    check_s3_buckets()

    print("\nChecking IAM Users...")
    check_iam_users()

    print("\nChecking Security Groups...")
    check_security_groups()

if __name__ == "__main__":
    main()
