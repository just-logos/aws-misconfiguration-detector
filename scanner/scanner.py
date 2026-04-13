import boto3
import joblib
import pandas as pd
import sqlite3
from datetime import datetime

# Load trained model
model = joblib.load('../models/model.pkl')

# Create clients for each service
s3_client = boto3.client('s3')
iam_client = boto3.client('iam')
ec2_client = boto3.client('ec2')

# Connect to SQLite database
conn = sqlite3.connect('../data/scan_results.db')
cursor = conn.cursor()

# Create findings table if it doesn't exist
cursor.execute('''
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        resource_name TEXT,
        resource_type TEXT,
        is_public INTEGER,
        has_wildcard INTEGER,
        open_ports INTEGER,
        risk_rating TEXT,
        remediation TEXT,
        label TEXT
    )
''')
conn.commit()

# Initialize empty list to store scan results
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

        # Determine if bucket has public access enabled
        is_public = 0 if all([
            config['BlockPublicAcls'],
            config['IgnorePublicAcls'],
            config['BlockPublicPolicy'],
            config['RestrictPublicBuckets']
        ]) else 1

        # Build features for model prediction    
        features = pd.DataFrame([{
                'is_public': is_public,
                'has_wildcard': 0,
                'open_ports': 0,
                'resource_type_iam': 0,
                'resource_type_s3': 1,
                'resource_type_sg': 0
        }])
        
        # Get model prediction
        prediction = model.predict(features)[0]

        # Assign risk rating and remediation based on prediction
        if prediction == 1:
            risk_rating = 'High'
            remediation = 'Enable All S3 Block Public Access settings to prevent public exposure of bucket data'
        else:
            risk_rating = 'Low'
            remediation = 'No remediation required'

        # Append S3 bucket scan result to results list
        results.append({
            'resource_name': bucket_name['Name'],
            'resource_type': 's3',
            'is_public': is_public,
            'has_wildcard': 0,
            'open_ports': 0,
            'risk_rating': risk_rating,
            'remediation': remediation,
            'label': 'misconfigured' if prediction == 1 else 'compliant'
        })

        # Print finding
        print(f"{bucket_name['Name']} | Risk: {risk_rating} | {remediation}")    

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
        
        # Determine if policy statement contains wildcard actions
        for statement in statements:
            if '*' in statement['Action']:
                has_wildcard = 1
            else:
                has_wildcard = 0
            
            # Build features for model prediction    
            features = pd.DataFrame([{
                    'is_public': 0,
                    'has_wildcard': has_wildcard,
                    'open_ports': 0,
                    'resource_type_iam': 1,
                    'resource_type_s3': 0,
                    'resource_type_sg': 0
            }])         

            # Get model prediction
            prediction = model.predict(features)[0]

            # Assign risk rating and remediation based on prediction
            if prediction == 1:
                risk_rating = 'Critical'
                remediation = 'Remove wildcard permissions in IAM policy'
            else:
                risk_rating = 'Low'
                remediation = 'No remediation required'

            # Append IAM policy scan result to results list
            results.append({
                'resource_name': policy['PolicyName'],
                'resource_type': 'iam',
                'is_public': 0,
                'has_wildcard': has_wildcard,
                'open_ports': 0,
                'risk_rating': risk_rating,
                'remediation': remediation,
                'label': 'misconfigured' if prediction == 1 else 'compliant'
            })
            
            # Print finding
            print(f"{policy['PolicyName']} | Risk: {risk_rating} | {remediation}")  
      
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

            # Determine if security group has unrestricted inbound access
            if (rule['FromPort'] == 0 and 
                rule['ToPort'] == 65535 and 
                any(r['CidrIp'] == '0.0.0.0/0' for r in rule['IpRanges'])):

                open_ports = 1

            else:
                open_ports = 0

            # Build features for model prediction    
            features = pd.DataFrame([{
                'is_public': 0,
                'has_wildcard': 0,
                'open_ports': open_ports,
                'resource_type_iam': 0,
                'resource_type_s3': 0,
                'resource_type_sg': 1
            }])

            # Get model prediction
            prediction = model.predict(features)[0]

            # Assign risk rating and remediation based on prediction
            if prediction == 1:
                risk_rating = 'Medium'
                remediation = 'Restrict inbound rules to only required ports and trusted IP ranges instead of allowing all traffic from 0.0.0.0/0'
            else:
                risk_rating = 'Low'
                remediation = 'No remediation required'

            # Append security group scan result to results list
            results.append({
                'resource_name': security_group['GroupName'],
                'resource_type': 'sg',
                'is_public': 0,
                'has_wildcard': 0,
                'open_ports': open_ports,
                'risk_rating': risk_rating,
                'remediation': remediation,
                'label': 'misconfigured' if prediction == 1 else 'compliant'
            })

            # Print finding
            print(f"{security_group['GroupName']} | Risk: {risk_rating} | {remediation}") 

scan_security_group()

# Convert results to a pandas DataFrame
df = pd.DataFrame(results)

# Save the DataFrame to a CSV file
df.to_csv('../data/scan_results.csv', index=False)

print("\nScan complete. Results saved to data/scan_results.csv")

# Insert each scan finding into the database with a timestamp
for result in results:
    cursor.execute('''
        INSERT INTO findings (timestamp, resource_name, resource_type, is_public, has_wildcard, open_ports, risk_rating, remediation, label)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        result['resource_name'],
        result['resource_type'],
        result['is_public'],
        result['has_wildcard'],
        result['open_ports'],
        result['risk_rating'],
        result['remediation'],
        result['label']
    ))

# Commit and close database connection
conn.commit()
conn.close()

print("Findings logged to database.")