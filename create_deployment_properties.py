############################################################
#####  Configuration settings for Deployment Creation  #####
############################################################

# This configuration file is used to set all required 
# variables in order to create an aws deployment into 
# an Alert Logic Customer ID. 

## Pre-requisites: 
# 1) Cross Account Role for the AWS account set up, and role ARN obtained (https://docs.alertlogic.com/prepare/aws-cross-account-role-setup.htm)
# 2) Centralized Cross Account Role if the AWS account is utilizing centralised CloudTrail log collection (https://docs.alertlogic.com/prepare/aws-cross-account-role-setup.htm)
# 

## Authentication Information
# Here you can specify either a username/password, or 
# access/secret keys (that can be generated through the 
# Alert Logic Console), in order to obtain an authentication 
# token to authorise all following API requests. The script 
# will use API Keys first if they are present 

# The Username & Password you would like to use for authentication: 
alert_logic_username = ''
alert_logic_password = ''

# The API Keys you would like to use for authentication (https://docs.alertlogic.com/prepare/access-key-management.htm) 
alert_logic_access_apikey = ''
alert_logic_secret_apikey = ''

## Main Configuration
# The Alert Logic Customer ID you would like to create the deployment into: 
alert_logic_cid = ""

#The role ARN of the Cross Account Role, for this AWS account:
role_arn = ""
aws_id = ""

#The role ARN for the Centralised CloudTrail account, if this AWS account is utilizing a seperate AWS account for CloudTrail collection
central_role_arn = "" 

#Deployment mode - This should be set to manual mode
mode = "manual"

#CloudTrail's install region. This is us-east-1 by default. 
ct_install_region = "us-east-1"

#Scope of Protection
# Here you must add each VPC you would like to be protected, to each of the regions 
# below in a list format. Alternatively you can protect the entire region, 
# by entering "all" instead. Leave any uneeded regions blank. 
#  Examples: 
#	euwest1=["vpc-1xxx","vpc-2xxx","vpc-3xxx"]
#	apsoutheast2=["all"]
#	uswest2=["vpc-axxx"]

apnortheast1=[]
apnortheast2=[]
apsouth1=[]
apsoutheast1=[]
apsoutheast2=[]
cacentral1=[]
eucentral1=[]
euwest1=[]
euwest2=[]
euwest3=[]
saeast1=[]
useast1=[]
useast2=[]
uswest1=[]
uswest2=[]
usgoveast1=[]
usgovwest1=[]

#The protection level you would like to set on each of the protected regions/VPC's above. 
# Must be either "Essentials" or "Professional"
entitlement = ""

#External Assets
# Here you can add external assets which will be scanned from Alert Logic's Datacenter. 
# You will need to add each DNS name or IP address in the following lists. 
#  Examples: 
#       external_dns_names=["www.example.com","www.google.com"]
#       external_ip_addresses=["8.8.8.8", "8.8.4.4"]

external_dns_names=[]
external_ip_addresses=[]

