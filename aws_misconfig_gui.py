import tkinter as tk
from tkinter import scrolledtext, messagebox
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

# Function to set AWS credentials
def set_aws_credentials():
    aws_access_key = access_key_entry.get().strip()
    aws_secret_key = secret_key_entry.get().strip()
    aws_region = region_entry.get().strip()

    if not aws_access_key or not aws_secret_key or not aws_region:
        messagebox.showerror("Error", "All fields (Access Key, Secret Key, and Region) must be filled out!")
        return

    try:
        boto3.setup_default_session(
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            region_name=aws_region
        )
        messagebox.showinfo("Success", "AWS credentials set successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to set AWS credentials: {e}")

# Function to get a boto3 client
def get_boto3_client(service_name):
    try:
        return boto3.client(service_name)
    except (NoCredentialsError, PartialCredentialsError):
        messagebox.showerror("Error", "AWS credentials not set or invalid. Please set them first.")
        return None

# Function to check S3 buckets
def check_s3_buckets():
    output_text.delete(1.0, tk.END)  # Clear previous output
    s3 = get_boto3_client('s3')  # Get the S3 client
    if not s3:
        return  # Exit if the client could not be created
    try:
        response = s3.list_buckets()  # List all S3 buckets
        if not response['Buckets']:
            output_text.insert(tk.END, "No Buckets found.\n")
        else:
            for bucket in response['Buckets']:
                bucket_name = bucket['Name']  # Get the bucket name
                acl = s3.get_bucket_acl(Bucket=bucket_name)  # Get the bucket's ACL
                public = any(
                    grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers'
                    for grant in acl['Grants']
                )  # Check if the bucket is public
                output_text.insert(tk.END, f"Bucket: {bucket_name} | Public: {'Yes' if public else 'No'}\n")
                if public:
                    output_text.insert(tk.END, "Suggestion: ", "suggestion")  # Use the tag for suggestion
                    output_text.insert(tk.END, f"Make bucket '{bucket_name}' private.\n")  # Suggest making the bucket private
    except ClientError as e:
        output_text.insert(tk.END, f"Error checking S3 buckets: {e}\n")  # Handle errors

# Function to check IAM users
def check_iam_users():
    output_text.delete(1.0, tk.END)  # Clear previous output
    iam = get_boto3_client('iam')  # Get the IAM client
    if not iam:
        return  # Exit if the client could not be created
    try:
        users = iam.list_users()['Users']  # List all IAM users
        if not users:  # Check if no IAM users are found
            output_text.insert(tk.END, "No IAM Users found.\n")
        else:
            for user in users:
                output_text.insert(tk.END, f":User  {user['UserName']}\n")  # Display the username
                # Check for MFA
                mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])['MFADevices']  # List MFA devices for the user
                if not mfa_devices:  # If no MFA devices are found
                    output_text.insert(tk.END, "Suggestion: ", "suggestion")  # Use the tag for suggestion
                    output_text.insert(tk.END, f"User  '{user['UserName']}' should enable MFA.\n")  # Suggest enabling MFA
    except ClientError as e:
        output_text.insert(tk.END, f"Error checking IAM users: {e}\n")  # Handle errors

# Function to check security groups
def check_security_groups():
    output_text.delete(1.0, tk.END)  # Clear previous output
    ec2 = get_boto3_client('ec2')  # Get the EC2 client
    if not ec2:
        return  # Exit if the client could not be created
    try:
        response = ec2.describe_security_groups()  # Describe all security groups
        if not response['SecurityGroups']:  # Check if no security groups are found
            output_text.insert(tk.END, "No Security Groups found.\n")
        else:
            for sg in response['SecurityGroups']:
                for perm in sg['IpPermissions']:
                    for ip_range in perm.get('IpRanges', []):
                        if ip_range['CidrIp'] == '0.0.0.0/0':  # Check for open access
                            output_text.insert(
                                tk.END, f"Security Group: {sg['GroupName']} ({sg['GroupId']}) allows open access!\n"
                            )  # Log the open access
                            output_text.insert(tk.END, "Suggestion: ", "suggestion")  # Use the tag for suggestion
                            output_text.insert(tk.END, "Restrict access to specific IPs or remove this rule.\n")  # Suggest a fix
    except ClientError as e:
        output_text.insert(tk.END, f"Error checking Security Groups: {e}\n")  # Handle errors

# Function to apply fixes to S3 buckets
def apply_s3_bucket_fixes():
    output_text.delete(1.0, tk.END)  # Clear previous output
    s3 = get_boto3_client('s3')  # Get the S3 client
    if not s3:
        return  # Exit if the client could not be created
    try:
        response = s3.list_buckets()  # List all S3 buckets
        if not response['Buckets']:
            output_text.insert(tk.END, "No Buckets found.\n")
        else:
            for bucket in response['Buckets']:
                bucket_name = bucket['Name']  # Get the bucket name
                acl = s3.get_bucket_acl(Bucket=bucket_name)  # Get the bucket's ACL
                public = any(
                    grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers'
                    for grant in acl['Grants']
                )  # Check if the bucket is public
                if public:
                    # Make the bucket private by setting an empty ACL
                    s3.put_bucket_acl(Bucket=bucket_name, AccessControlPolicy={'Grants': [], 'Owner': acl['Owner']})
                    output_text.insert(tk.END, f"Made bucket '{bucket_name}' private.\n")  # Log the action
    except ClientError as e:
        output_text.insert(tk.END, f"Error applying fixes for S3 buckets: {e}\n")  # Handle errors

# Function to apply fixes to IAM users
def apply_iam_user_fixes():
    output_text.delete(1.0, tk.END)  # Clear previous output
    iam = get_boto3_client('iam')  # Get the IAM client
    if not iam:
        return  # Exit if the client could not be created
    try:
        users = iam.list_users()['Users']  # List all IAM users
        if not users:
            output_text.insert(tk.END, "No IAM Users found.\n")
        else:
            for user in users:
                mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])['MFADevices']  # List MFA devices for the user
                if not mfa_devices:  # If no MFA devices are found
                    output_text.insert(tk.END, f"User  '{user['UserName']}' has no MFA enabled. Please enable MFA manually.\n")
    except ClientError as e:
        output_text.insert(tk.END, f"Error applying fixes for IAM users: {e}\n")  # Handle errors

# Function to apply fixes to security groups
def apply_security_group_fixes():
    output_text.delete(1.0, tk.END)  # Clear previous output
    ec2 = get_boto3_client('ec2')  # Get the EC2 client
    if not ec2:
        return  # Exit if the client could not be created
    try:
        response = ec2.describe_security_groups()  # Describe all security groups
        if not response['SecurityGroups']:  # Check if no security groups are found
            output_text.insert(tk.END, "No Security Groups found.\n")
        else:
            for sg in response['SecurityGroups']:
                for perm in sg['IpPermissions']:
                    for ip_range in perm.get('IpRanges', []):
                        if ip_range['CidrIp'] == '0.0.0.0/0':  # Check for open access
                            # Ensure 'FromPort' and 'ToPort' exist before accessing
                            from_port = perm.get('FromPort', None)  
                            to_port = perm.get('ToPort', None)

                            revoke_params = {
                                'GroupId': sg['GroupId'],
                                'IpPermissions': [{
                                    'IpProtocol': perm['IpProtocol'],
                                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                                }]
                            }

                            # Only add port details if they exist
                            if from_port is not None:
                                revoke_params['IpPermissions'][0]['FromPort'] = from_port
                            if to_port is not None:
                                revoke_params['IpPermissions'][0]['ToPort'] = to_port

                            # Remove the overly permissive rule
                            ec2.revoke_security_group_ingress(**revoke_params)
                            output_text.insert(tk.END, f"Removed open access from Security Group: {sg['GroupName']} ({sg['GroupId']}).\n")
    except ClientError as e:
        output_text.insert(tk.END, f"Error applying fixes for Security Groups: {e}\n")  # Handle errors

# Create GUI
def create_gui():
    global access_key_entry, secret_key_entry, region_entry, output_text

    window = tk.Tk()  # Create the main window
    window.title("AWS Misconfiguration Checker")  # Set the window title
    window.geometry("600x700")  # Set the window size

    # Set the background color to match AWS color scheme
    window.configure(bg="#f7f7f7")  # Light gray background

    tk.Label(window, text="AWS Misconfiguration Checker", font=("Arial", 16), bg="#f7f7f7").pack(pady=10)  # Title label

    credentials_frame = tk.Frame(window, bg="#f7f7f7")  # Frame for AWS credentials
    credentials_frame.pack(pady=10)
    tk.Label(credentials_frame, text="Access Key ID:", bg="#f7f7f7").grid(row=0, column=0, padx=5)  # Access Key label
    access_key_entry = tk.Entry(credentials_frame, width=30)  # Entry for Access Key
    access_key_entry.grid(row=0, column=1, padx=5)

    tk.Label(credentials_frame, text="Secret Access Key:", bg="#f7f7f7").grid(row=1, column=0, padx=5)  # Secret Key label
    secret_key_entry = tk.Entry(credentials_frame, width=30, show="*")  # Entry for Secret Key
    secret_key_entry.grid(row=1, column=1, padx=5)

    tk.Label(credentials_frame, text="Region:", bg="#f7f7f7").grid(row=2, column=0, padx=5)  # Region label
    region_entry = tk.Entry(credentials_frame, width=30)  # Entry for Region
    region_entry.grid(row=2, column=1, padx=5)

    tk.Button(credentials_frame, text="Set AWS Credentials", command=set_aws_credentials, width=20).grid(row=3, column=0, columnspan=2, pady=10) 
    button_frame = tk.Frame(window, bg="#f7f7f7")  # Frame for action buttons
    button_frame.pack(pady=5)
    tk.Button(button_frame, text="Check S3 Buckets", command=check_s3_buckets, width=20).grid(row=0, column=0, padx=10)  # Button to check S3 buckets
    tk.Button(button_frame, text="Apply S3 Fixes", command=apply_s3_bucket_fixes, width=20).grid(row=0, column=1, padx=10)  # Button to apply S3 fixes
    tk.Button(button_frame, text="Check IAM Users", command=check_iam_users, width=20).grid(row=0, column=2, padx=10)  # Button to check IAM users
    tk.Button(button_frame, text="Apply IAM Fixes", command=apply_iam_user_fixes, width=20).grid(row=0, column=3, padx=10)  # Button to apply IAM fixes
    tk.Button(button_frame, text="Check Security Groups", command=check_security_groups, width=20).grid(row=1, column=0, padx=10)  # Button to check security groups
    tk.Button(button_frame, text="Apply Security Group Fixes", command=apply_security_group_fixes, width=20).grid(row=1, column=1, padx=10)  # Button to apply security group fixes

    output_frame = tk.Frame(window, bg="#f7f7f7")  # Frame for output text area
    output_frame.pack(pady=10, fill="both", expand=True)
    output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=20, bg="#ffffff", fg="#000000")  # Scrolled text area for output
    output_text.pack(fill="both", expand=True)

    # Configure text tags for styling
    output_text.tag_configure("suggestion", foreground="red", font=("Arial", "10", "bold"))  # Tag for suggestions

    window.mainloop()  # Start the GUI event loop

# Run the GUI
if __name__ == "__main__":
    create_gui()  # Call the function to create and display the GUI