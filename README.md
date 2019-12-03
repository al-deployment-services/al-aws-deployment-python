# AWS Alert Logic Deployment using Python
This is a python script that will allow you to create an Alert Logic Deployment for AWS in the Alert Logic Console.

## Usage
#### These properties are required to ensure that the script can create the deployment successfully. 
- alert_logic_username = '' // Alert Logic Username
- alert_logic_password = '' // Alert Logic Password
- alert_logic_cid = "" // Alert Logic Customer ID
- role_arn = "" // AWS Cross Account Role ARN
- aws_id = "" // Customer AWS Account ID
- central_role_arn = "" // AWS Cross Account Role ARN for Centralized CloudTrail Logging Account (Optional)
- entitlement = "" // Alert Logic Entitlement Level (Essentials or Professional)

### Examples for scope of protection & external assets
#### These objects are required for setting scope of protection. 
- euwest1=["vpc-1xxx","vpc-2xxx","vpc-3xxx"]
- apsoutheast2=["all"]
- uswest2=["vpc-axxx"]

#### These objects are required for external assets to be scanned externally by Alert Logic's Datacentre, post deployment. 
- external_dns_names=["www.example.com","www.google.com"]
- external_ip_addresses=["8.8.8.8", "8.8.4.4"]

### How to run the script: 
python3 create_deployment.py
