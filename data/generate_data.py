import random
import pandas as pd

# Define three AWS resource types to generate data for
resource_type = [
    's3',
    'iam',
    'sg'
]

# Initialize empty list to store generated results
results = []

# Generate 500 AWS resource scan results
for i in range(500):

    # Randomly select a resource type and compliance label
    resource = random.choice(['s3', 'iam', 'sg'])
    label = random.choice(['misconfigured', 'compliant'])

    # Generate S3 bucket rows
    if resource == 's3':
        if label == 'misconfigured':
            # Misconfigured S3 bucket: public access enabled
            results.append({
                'resource_name': f's3-bucket-{i}',
                'resource_type': 's3',
                'is_public': 1,
                'has_wildcard': 0,
                'open_ports': 0,
                'label': 'misconfigured'
            })
        else:
            # Compliant S3 bucket: public access disabled
            results.append({
                'resource_name': f's3-bucket-{i}',
                'resource_type': 's3',
                'is_public': 0,
                'has_wildcard': 0,
                'open_ports': 0,
                'label': 'compliant'
            })

    # Generate IAM policy rows
    elif resource == 'iam':
        if label == 'misconfigured':
            # Misconfigured IAM policy: wildcard permissions
            results.append({
                'resource_name': f'iam-policy-{i}',
                'resource_type': 'iam',
                'is_public': 0,
                'has_wildcard': 1,
                'open_ports': 0,
                'label': 'misconfigured'
            })
        else:
            # Compliant IAM policy: least privilege permissions
            results.append({
                'resource_name': f'iam-policy-{i}',
                'resource_type': 'iam',
                'is_public': 0,
                'has_wildcard': 0,
                'open_ports': 0,
                'label': 'compliant'
            })

    # Generate security group rows
    elif resource == 'sg':
        if label == 'misconfigured':
            # Misconfigured security group: unrestricted inbound access
            results.append({
                'resource_name': f'sg-{i}',
                'resource_type': 'sg',
                'is_public': 0,
                'has_wildcard': 0,
                'open_ports': 1,
                'label': 'misconfigured'
            })
        else:
            # Compliant security group: restricted inbound access
            results.append({
                'resource_name': f'sg-{i}',
                'resource_type': 'sg',
                'is_public': 0,
                'has_wildcard': 0,
                'open_ports': 0,
                'label': 'compliant'
            })

# Convert results to a pandas DataFrame
df = pd.DataFrame(results)

# Save the DataFrame to a CSV file
df.to_csv('scan_results.csv', index=False)

print("\nResults saved to /data/scan_results.csv")