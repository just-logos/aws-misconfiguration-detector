import boto3

# Create clients for each service
s3_client = boto3.client('s3')
iam_client = boto3.client('iam')
ec2_client = boto3.client('ec2')

############
# S3 Scanner
############

# List all S3 buckets
s3_client.list_buckets()

# Define a function to scan S3 buckets
def scan_s3_buckets():
    s3_bucket_list = s3_client.list_buckets()

    for bucket_name in s3_bucket_list['Buckets']:

        # Retrieve public access block configuration for each bucket
        public_access = s3_client.get_public_access_block(Bucket=bucket_name['Name'])

        # Extract the public access block settings from the response
        config = public_access['PublicAccessBlockConfiguration']

        # Conditional check for public access policies
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