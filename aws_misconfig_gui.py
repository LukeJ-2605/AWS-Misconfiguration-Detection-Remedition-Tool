import tkinter as tk
from tkinter import scrolledtext, messagebox
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

# Function to set AWS credentials
def set_aws_credentials():
    """
    Sets the AWS credentials (Access Key ID, Secret Access Key, and Region) 
    based on user input from the GUI. Configures boto3 to use these credentials
    for subsequent AWS API calls.
    """
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
    """
    Creates and returns a boto3 client for the specified AWS service.
    If credentials are missing or invalid, displays an error message.

    Args:
        service_name (str): The name of the AWS service (e.g., 's3', 'iam', 'ec2').

    Returns:
        boto3.Client: The client for the specified service, or None if an error occurs.
    """
    try:
        return boto3.client(service_name)
    except (NoCredentialsError, PartialCredentialsError):
        messagebox.showerror("Error", "AWS credentials not set or invalid. Please set them first.")
        return None

# Misconfiguration check functions
def check_s3_buckets():
    """
    Checks for S3 buckets in the AWS account and determines if they are publicly accessible.
    Results are displayed in the GUI output text box. If no buckets are found, a message is displayed.
    """
    output_text.delete(1.0, tk.END)  # Clear previous output
    s3 = get_boto3_client('s3')
    if not s3:
        return
    try:
        response = s3.list_buckets()
        if not response['Buckets']:  # Check if the bucket list is empty
            output_text.insert(tk.END, "No Buckets found.\n")
        else:
            for bucket in response['Buckets']:
                bucket_name = bucket['Name']
                acl = s3.get_bucket_acl(Bucket=bucket_name)
                public = any(
                    grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers'
                    for grant in acl['Grants']
                )
                output_text.insert(tk.END, f"Bucket: {bucket_name} | Public: {'Yes' if public else 'No'}\n")
    except ClientError as e:
        output_text.insert(tk.END, f"Error checking S3 buckets: {e}\n")

def check_iam_users():
    """
    Lists IAM users in the AWS account and displays their usernames in the GUI output text box.
    If no IAM users are found, a message is displayed.
    """
    output_text.delete(1.0, tk.END)  # Clear previous output
    iam = get_boto3_client('iam')
    if not iam:
        return
    try:
        users = iam.list_users()['Users']
        if not users:  # Check if no IAM users are found
            output_text.insert(tk.END, "No IAM Users found.\n")
        else:
            for user in users:
                output_text.insert(tk.END, f"User: {user['UserName']}\n")
    except ClientError as e:
        output_text.insert(tk.END, f"Error checking IAM users: {e}\n")

def check_security_groups():
    """
    Checks security groups in the AWS account for overly permissive rules 
    (e.g., open access to 0.0.0.0/0). Results are displayed in the GUI output text box.
    If no security groups are found or no open access is detected, appropriate messages are displayed.
    """
    output_text.delete(1.0, tk.END)  # Clear previous output
    ec2 = get_boto3_client('ec2')
    if not ec2:
        return
    try:
        response = ec2.describe_security_groups()
        if not response['SecurityGroups']:  # Check if no security groups are found
            output_text.insert(tk.END, "No Security Groups found.\n")
        else:
            open_access_found = False
            for sg in response['SecurityGroups']:
                for perm in sg['IpPermissions']:
                    for ip_range in perm.get('IpRanges', []):
                        if ip_range['CidrIp'] == '0.0.0.0/0':
                            output_text.insert(
                                tk.END, f"Security Group: {sg['GroupName']} ({sg['GroupId']}) allows open access!\n"
                            )
                            open_access_found = True
            if not open_access_found:
                output_text.insert(tk.END, "No Security Groups with open access found.\n")
    except ClientError as e:
        output_text.insert(tk.END, f"Error checking Security Groups: {e}\n")

# Create GUI
def create_gui():
    """
    Creates the graphical user interface (GUI) for the AWS Misconfiguration Checker tool.
    The GUI includes:
    - Input fields for AWS credentials (Access Key, Secret Key, and Region).
    - Buttons to check S3 buckets, IAM users, and security groups.
    - A scrollable output text box to display results or error messages.
    """
    global access_key_entry, secret_key_entry, region_entry, output_text

    # Initialize Tkinter window
    window = tk.Tk()
    window.title("AWS Misconfiguration Checker")
    window.geometry("600x500")

    # Title label
    tk.Label(window, text="AWS Misconfiguration Checker", font=("Arial", 16)).pack(pady=10)

    # AWS credentials input section
    credentials_frame = tk.Frame(window)
    credentials_frame.pack(pady=10)
    tk.Label(credentials_frame, text="Access Key ID:").grid(row=0, column=0, padx=5)
    access_key_entry = tk.Entry(credentials_frame, width=30)
    access_key_entry.grid(row=0, column=1, padx=5)

    tk.Label(credentials_frame, text="Secret Access Key:").grid(row=1, column=0, padx=5)
    secret_key_entry = tk.Entry(credentials_frame, width=30, show="*")  # Hide secret key input
    secret_key_entry.grid(row=1, column=1, padx=5)

    tk.Label(credentials_frame, text="Region:").grid(row=2, column=0, padx=5)
    region_entry = tk.Entry(credentials_frame, width=30)
    region_entry.grid(row=2, column=1, padx=5)

    # Button to set AWS credentials
    tk.Button(credentials_frame, text="Set AWS Credentials", command=set_aws_credentials, width=20).grid(row=3, column=0, columnspan=2, pady=10)

    # Misconfiguration check buttons
    button_frame = tk.Frame(window)
    button_frame.pack(pady=5)
    tk.Button(button_frame, text="Check S3 Buckets", command=check_s3_buckets, width=20).grid(row=0, column=0, padx=10)
    tk.Button(button_frame, text="Check IAM Users", command=check_iam_users, width=20).grid(row=0, column=1, padx=10)
    tk.Button(button_frame, text="Check Security Groups", command=check_security_groups, width=20).grid(row=0, column=2, padx=10)

    # Output text area
    output_frame = tk.Frame(window)
    output_frame.pack(pady=10, fill="both", expand=True)
    output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=15)
    output_text.pack(fill="both", expand=True)

    # Run the Tkinter main loop
    window.mainloop()

# Run the GUI
if __name__ == "__main__":
    """
    Entry point of the script. Initializes and starts the AWS Misconfiguration Checker GUI.
    """
    create_gui()
