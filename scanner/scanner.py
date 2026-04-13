import boto3

# Create clients for each service
s3_client = boto3.client('s3')
iam_client = boto3.client('iam')
ec2_client = boto3.client('ec2')

import pandas as pd

results = []

############
# S3 Scanner
############

# Define a function to scan S3 buckets
def scan_s3_buckets():

    # Retrieve all S3 buckets in the account
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
            
            # Append compliant S3 bucket result to results list
            results.append({
                'resource_name': bucket_name['Name'],
                'resource_type': 's3',
                'is_public': 0,
                'has_wildcard': 0,
                'open_ports': 0,
                'label': 'compliant'
                })
            
            print(f"{bucket_name['Name']} is compliant")

        else:

            # Append misconfigured S3 bucket result to results list
            results.append({
                'resource_name': bucket_name['Name'],
                'resource_type': 's3',
                'is_public': 1,
                'has_wildcard': 0,
                'open_ports': 0,
                'label': 'misconfigured'
                })
            
            print(f"{bucket_name['Name']} is misconfigured")

scan_s3_buckets()

#############
# IAM Scanner
#############

# Define a function to scan IAM policies for wildcard permissions
def scan_iam_policies():

    # Retrieve all locally created IAM policies
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

                # Append misconfigured IAM policy result to results list
                results.append({
                'resource_name': policy['PolicyName'],
                'resource_type': 'iam',
                'is_public': 0,
                'has_wildcard': 1,
                'open_ports': 0,
                'label': 'misconfigured'
                })                

                print(f"{policy['PolicyName']} is misconfigured")

            else:

                # Append compliant IAM policy result to results list
                results.append({
                'resource_name': policy['PolicyName'],
                'resource_type': 'iam',
                'is_public': 0,
                'has_wildcard': 0,
                'open_ports': 0,
                'label': 'compliant'
                })  
                print(f"{policy['PolicyName']} is compliant")
                  
scan_iam_policies()

########################
# Security Group Scanner
########################

# Define a function to scan Security Groups for unrestricted inbound access
def scan_security_group():

    # Retrieve security groups filtered by name
    security_groups = ec2_client.describe_security_groups(
        Filters=[
            {'Name': 'group-name', 'Values': ['misconfigured-sg', 'secure-sg']}
        ]
    )

    for security_group in security_groups['SecurityGroups']:

        # Loop through each inbound rule for the security group
        for rule in security_group['IpPermissions']:

            # Flag as misconfigured if all ports are open from any IP
            if (rule['FromPort'] == 0 and 
                rule['ToPort'] == 65535 and 
                any(r['CidrIp'] == '0.0.0.0/0' for r in rule['IpRanges'])):

                # Append misconfigured security group result to results list
                results.append({
                'resource_name': security_group['GroupName'],
                'resource_type': 'sg',
                'is_public': 0,
                'has_wildcard': 0,
                'open_ports': 1,
                'label': 'misconfigured'
                })

                print(f"{security_group['GroupName']} is misconfigured")

            else:

                # Append compliant security group result to results list
                results.append({
                'resource_name': security_group['GroupName'],
                'resource_type': 'sg',
                'is_public': 0,
                'has_wildcard': 0,
                'open_ports': 0,
                'label': 'compliant'
                })

                print(f"{security_group['GroupName']} is compliant")

scan_security_group()

# Convert results to a pandas DataFrame
df = pd.DataFrame(results)

# Save the DataFrame to a CSV file
df.to_csv('../data/scan_results.csv', index=False)

print("\nScan complete. Results saved to data/scan_results.csv")