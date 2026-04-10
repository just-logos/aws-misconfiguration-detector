import boto3

# Create clients for each service
s3_client = boto3.client('s3')
iam_client = boto3.client('iam')
ec2_client = boto3.client('ec2')

############
# S3 Scanner
############

# Define a function to scan S3 buckets
def scan_s3_buckets():
    s3_bucket_list = s3_client.list_buckets()

    for bucket_name in s3_bucket_list['Buckets']:

        # Retrieve public access block configuration for each bucket
        public_access = s3_client.get_public_access_block(Bucket=bucket_name['Name'])

        # Extract the public access block settings from the response
        config = public_access['PublicAccessBlockConfiguration']

        # Conditional check to classify bucket as compliant if all public access settings are enabled
        if all ([
            config['BlockPublicAcls'],
            config['IgnorePublicAcls'],
            config['BlockPublicPolicy'],
            config['RestrictPublicBuckets']
        ]):
            print(f"{bucket_name['Name']} is compliant")
        else:
            print(f"{bucket_name['Name']} is misconfigured")

scan_s3_buckets()

#############
# IAM Scanner
#############

# Define a function to scan IAM policies for wildcard permissions
def scan_iam_policies():
    iam_policies_list = iam_client.list_policies(Scope='Local')

    for policy in iam_policies_list['Policies']:

        # Retrieve the policy document for each policy
        policy_version = iam_client.get_policy_version(
            PolicyArn=policy['Arn'],
            VersionId=policy['DefaultVersionId']
        )
        
        # Extract the policy statements from the document
        statements = policy_version['PolicyVersion']['Document']['Statement']
        
        # Check each statement for wildcard actions
        for statement in statements:
            if '*' in statement['Action']:
                print(f"{policy['PolicyName']} is misconfigured")
            else:
                print(f"{policy['PolicyName']} is compliant")
                  
scan_iam_policies()