#!/usr/bin/python3 -u

#Required Libraries
import json
import os
import requests
#import getpass
import time
from datetime import datetime

#Read in configuration file
from create_deployment_properties import *
#from create_deployment_properties_test import *

#Setting true/false variables to avoid conflict later
true=True
false=False

#Set global URL's
global_url= 'https://api.global.alertlogic.com/'

#Header just to make the script look prettier
print('''
====================================================================================================

              :ydho`                 Title:     Create_Deployment.sh
            +ddddd:                 Author:     Alert Logic Deployment Services
           .ddddh+             Description:     A tool for creating deployments
           yddy/``                              into the Alert Logic UI for 
          +dh:   +/                             your chosen Customer ID
         +dy` ''',end='')
print('``',end='')
print('''  sy-          
       `odh.''',end='')
print('-/+++-', end='')
print('''.dd+`        
      .yddo ''',end='')
print(':++++/',end='')
print(''' sddy-            Usage:      python3 Create_Deployment.py
     /hddd/  ''',end='')                
print('.::-',end='')
print('''  sdddh/                
    /ddddd-        oddddd.           Note:      Ensure that all required fields in the configuration 
    +dddds         .hdddh`                      file have been input. For any assistance, please 
     .::.            -:-`                       contact Alert Logic Deployment Services                

====================================================================================================
''')


#Checks to ensure that the configuration file has all required fields before even starting the script

if alert_logic_cid == '':
	print ('\nThe Alert Logic Customer ID has not been stored in the configuration file.\n')
	exit()

if role_arn == '':
        print ('\nThe role ARN for the cross account role has not been stored in the configuration file.\n')
        exit()

if aws_id == '':
        print ('\nThe AWS account ID that we are deploying into has not been stored in the configuration file.\n')
        exit()

entitlement=entitlement.capitalize()

if entitlement == '':
        print ('\nThe protection level has not been set in the configuration file.\n')
        exit()
elif entitlement not in ['Professional','Essentials']:
	print('\nThe protection level has been set incorrectly in the configuration file. Please specify either "Essentials" or "Professional".\n')
	exit()

#Function to get AIMS Token once we have creds
def get_token_userpass ():
	url = '{}aims/v1/authenticate'.format(global_url)
	global auth_token
	#Use credentials
	aims_user = alert_logic_username
	aims_pass = alert_logic_password
	
	if "alertlogic.com" in aims_user : 
		print ('\nAlert Logic User Detected. Cannot authenticate since MFA is mandatory. Use API Keys.\n')
		exit()
	
	print('\nValidating stored credentials...', end = '')
	
	#POST request to the URL using credentials. Load the response into auth_info then parse out the token
	token_response = requests.post(url, auth=(aims_user, aims_pass))
	
	if token_response.status_code != 200: 
		print('There was an error. Got the following response: ',end='') 
		print(token_response)
		print()
		exit()
	
	auth_info = json.loads(token_response.text)
	auth_token = auth_info['authentication']['token']

#Same as previous, but uses stored API Keys if they are detected
def get_token_apikey ():
	url = '{}aims/v1/authenticate'.format(global_url)
	global auth_token
	print('Detected stored API Keys. Validating...', end = '')
	#POST request to the URL using keys. Load the response into auth_info then parse out the token
	token_response = requests.post(url, auth=(alert_logic_access_apikey, alert_logic_secret_apikey))
	
	if token_response.status_code != 200: 
		print('There was an error. Got the following response: ',end='') 
		print(token_response)
		print()
		exit()
	
	auth_info = json.loads(token_response.text)
	auth_token = auth_info['authentication']['token']

#Function to validate the AIMS token was successfully generated, and that it has not expired
def validate_token ():
	url = '{}aims/v1/token_info'.format(global_url)
	headers = {'x-aims-auth-token': '{}'.format(auth_token)}
	global validate_info
	validate_response = requests.get(url, headers=headers)
	validate_info = json.loads(validate_response.text)
	
	#get current unix timestamp,make global for later
	global current_time
	current_time = int(time.time())
	#get token expiration timestamp
	token_expiration = validate_info['token_expiration']
	num_seconds_before_expired=(token_expiration - current_time)
	
	if num_seconds_before_expired < 0 :
		print(' Could not generate / validate AIMS Token. Please check credentials and try again\n')
		exit()
	else :
		print(' AIMS token generated and validated.\n')
		time.sleep(1)

if alert_logic_access_apikey != '' and alert_logic_secret_apikey != '':
	get_token_apikey()
	validate_token()
elif alert_logic_username != '' and alert_logic_password != '':
	get_token_userpass()
	validate_token()
else: 
		print ('\nNo credentials stored in the configuration file, to allow authentication against the API.\n')
		exit()
#Authentication complete

headers = {"x-aims-auth-token": "{}".format(auth_token)} #Set header for all future API calls

#Get base endpoint for customer ID
endpoint_url = '{0}endpoints/v1/{1}/residency/default/services/assets/endpoint/api'.format(global_url, alert_logic_cid)
endpoint_response = requests.get(endpoint_url, headers=headers)

#In case we don't get a 200 response getting the endpoint
if endpoint_response.status_code != 200:
	print('Could not determine API endpoint for the Customer ID stored. Got response code: ' + str(endpoint_response.status_code))
	print()
	exit()
	
endpoint_info = json.loads(endpoint_response.text) 
base_url = endpoint_info['assets']
base_url = 'https://' + base_url

#Get CID that the token exists in (CID the authenticated user was in). Then check if that CID is authorised to view 
users_CID = validate_info['user']['account_id']

#Print out authenticated user information
print('Authenticated Users Info:\n')
user_name = validate_info['user']['name']
user_email = validate_info['user']['email']
user_role = validate_info['roles'][0]['name']
user_lastlogin_unix = validate_info['user']['user_credential']['last_login']
user_lastlogin_hr = datetime.utcfromtimestamp(user_lastlogin_unix ).strftime('%d/%m/%Y %H:%M:%S %Z')
print('    Name: ' + user_name)
print('    Email: ' + user_email)
print('    User Role: ' + user_role) 
print('    CID: ' + users_CID)
#print('    Last authentication: ' + user_lastlogin_hr) #Don't think this is needed, last time user logged into the UI
print()


#If the CID the user has authenticated from, is not equal to the target CID
if alert_logic_cid != users_CID: 
	#This is checking whether there is a managed relationship (ensuring a parent-child relationship) between the 2 CID's. 
	managed_CID_check_url = '{0}aims/v1/{1}/accounts/managed/{2}'.format(global_url, users_CID, alert_logic_cid)
	managed_CID_check_response = requests.get(managed_CID_check_url, headers=headers)
	managed_CID_check_statuscode = managed_CID_check_response.status_code
	
	#1 - Make sure the CID's have a managed relationship (Status Code 204 is a success response)
	if managed_CID_check_statuscode != 204:
		print(' Authenticated user does not have authorisation to perform actions in CID ' + alert_logic_cid + ' Please try another user.\n')
		exit()
	
	#2 - If yes to step 1, make sure authenticated user has permissions to create stuff in target CID
	if user_role == 'Read Only' or user_role == 'Support/Care' or user_role == 'Power User' :
		print ('Authenticated user does not have the required permission to create in CID ' + alert_logic_cid)
		print ('\n    User must be Administrator or Owner\n')
		exit()

#If the CID the user has authenticated from, is equal to the target CID
elif alert_logic_cid == users_CID:
	# Make sure the autenticated user has permission to create in target CID
	if user_role == 'Read Only' or user_role == 'Support/Care' :
		print ('Authenticated user does not have the required permission to create in CID ' + alert_logic_cid)
		print ('\n    User must be Administrator, Owner or Power user\n')
		exit()
#Get some account information from the CID
print('Target CID Info:\n')
account_info_url = '{0}aims/v1/{1}/account'.format(global_url, alert_logic_cid)
account_info_response = requests.get(account_info_url, headers=headers)
account_info = json.loads(account_info_response.text)
account_name = account_info['name']
account_CID = alert_logic_cid
account_defaultloc = account_info['default_location']
print('    Account Name: ' + account_name)
print('    Accound CID: ' + account_CID)
print('    Default Location: ' + account_defaultloc)
print('    Base URL: ' + base_url)
print()

#Get the policy ID's for the protection levels.
policies_info_url = '{0}/policies/v1/{1}/policies'.format(base_url, alert_logic_cid)
policies_info_response = requests.get(policies_info_url, headers=headers)
policies_info = json.loads(policies_info_response.text)
#The following code pulls in the entitlement set in the configuration file and returns the entitlement ID
entitlement=entitlement.capitalize()
policy_id = [x for x in policies_info if x['name'] == entitlement]
entitlement_id=policy_id[0]['id']


#Function to create the credential in the back-end
def create_credentials (): 

	payload = {
		"name": aws_id +" discover cred",
		"secrets": {
		"type": "aws_iam_role",
		"arn": role_arn
		}
	}
	
	create_payload=json.dumps(payload)
	create_cred_url = '{0}/credentials/v2/{1}/credentials'.format(base_url, alert_logic_cid)
	create_cred_response = requests.post(create_cred_url, create_payload, headers=headers)
	if create_cred_response.status_code != 201:
		print('    Credential creation failed. Got the following response: ',end='')
		print(create_cred_response)
		print()
		exit()
	else : 
		print('    Credential successfully created.')

	create_cred_info = json.loads(create_cred_response.text)
	global credential_id
	credential_id = create_cred_info['id']

def create_central_ct_credential ():

	central_ct_payload={
			"name": aws_id +"x-account-monitor",
			"secrets": {
				"type": "aws_iam_role",
				"arn": central_role_arn
			}
		}

	create_central_ct_payload=json.dumps(central_ct_payload)
	create_central_ct_cred_url = '{0}/credentials/v2/{1}/credentials'.format(base_url, alert_logic_cid)
	create_central_ct_cred_response = requests.post(create_central_ct_cred_url, create_central_ct_payload, headers=headers)
	if create_central_ct_cred_response.status_code != 201:
		print('    Centralised Collection Credential creation failed. Got the following response: ',end='')
		print(create_central_ct_cred_response)
		print()
		exit()
	else :
		print('    Centralised Collection Credential successfully created.')

	create_central_ct_cred_info = json.loads(create_central_ct_cred_response.text)
	global central_credential_id
	central_credential_id = create_central_ct_cred_info['id']

#Create scope into a JSON object from the config file
#Harcoded lists of regions. One for list names, the other for the correctly formatted region name
list_regions=[apnortheast1,apnortheast2,apsouth1,apsoutheast1,apsoutheast2,cacentral1,eucentral1,euwest1,euwest2,euwest3,saeast1,useast1,useast2,uswest1,uswest2,usgoveast1,usgovwest1]
list_regions_text=["ap-northeast-1","ap-northeast-2","ap-south-1","ap-southeast-1","ap-southeast-2","ca-central-1","eu-central-1","eu-west-1","eu-west-2","eu-west-3","sa-east-1","us-east-1","us-east-2","us-west-1","us-west-2","us-gov-east-1","us-gov-west-1"]


#Defining the scope variable we're going to append to, also list for logging purposes
full_scope=[]
protected_scope_logging=[]
#Counter to iterate through the text list above, so that we can pull the correctly formatted name
counter=0

for region in list_regions:

        #If the list is empty, do nothing
        if len(region) == 0:
                pass
        #If the list is not empty, then
        else :
                #If the value in the list is 'all', protect entire region + append JSON to variable
                if 'all' in region :
                        region_name=list_regions_text[counter]
                        full_scope.append("{\"type\":\"region\",\"key\":\"/aws/"+region_name+"\",\"policy\":{\"id\":\""+entitlement_id+"\"}}")
                        protected_scope_logging.append("\t\t\t\tRegion: "+region_name+"\t\tVPC's: All VPC's Protected\n")

                #Else loop through each VPC + append JSON to variable
                else :
                        for x in region:
                                region_name=list_regions_text[counter]
                                full_scope.append("{\"type\":\"vpc\",\"key\":\"/aws/"+region_name+"/vpc/"+x+"\",\"policy\":{\"id\":\""+entitlement_id+"\"}}")
                        protected_scope_logging.append("\t\t\t\tRegion: "+region_name+"\t\tVPC's: "+str(region)[1:-1].replace("'", "")+"\n")

	#Increment the counter, so we use the next region in the list
        counter=counter+1

#Logging Protected Scope
if not protected_scope_logging: 
	protected_scope_logging.append("\t\t\t\tNo scope defined in the configuration file. No scope set pre-deployment")
scope_list=''.join(protected_scope_logging)

#Convert full scope to string
scope=str(full_scope)[1:-1]

#Remove single quotes between each json object, load that into a json format then remove any slashes
scope_json=scope.replace("'","")
scope_json=json.dumps(scope_json)
scope_json=scope_json.replace("\\", "")

#Function to create the deployment, adding in all 
def create_deployment ():

	if central_role_arn == "":

		deployment_payload ={
			"name": aws_id,
			"platform": {
				"type": "aws",
				"id": aws_id,
				"monitor": {
					"enabled": true,
					"ct_install_region":  ct_install_region
				}
			},
			"mode": mode,
			"enabled": true,
			"discover": true,
			"scan": true,
			"scope": {
				 "include": [(scope_json)],
			},
			"cloud_defender": {
				"enabled": false,
				"location_id": account_defaultloc
			},
			"credentials": [{
				"id": credential_id,
				"purpose": "discover",
				"version": "2019-11-01"
			}]
		}
	else:
                
		deployment_payload ={
                        "name": aws_id,
                        "platform": {
                                "type": "aws",
                                "id": aws_id,
                                "monitor": {
                                        "enabled": true,
                                        "ct_install_region":  ct_install_region
                                }
                        },
                        "mode": mode,
                        "enabled": true,
                        "discover": true,
                        "scan": true,
                        "scope": {
                                 "include": [(scope_json)],
                        },
                        "cloud_defender": {
                                "enabled": false,
                                "location_id": account_defaultloc
                        },
                        "credentials": [{
                                "id": credential_id,
                                "purpose": "discover"
                        }, {
				"id": central_credential_id,
				"purpose": "x-account-monitor"
			}]
                }	

	create_deployment_payload=json.dumps(deployment_payload)
	create_deployment_payload_final=create_deployment_payload.replace("\\", "")
	create_deployment_payload_final=create_deployment_payload_final.replace('""', '')

	create_deployment_url = '{0}/deployments/v1/{1}/deployments'.format(base_url, alert_logic_cid)
	create_deployment_response = requests.post(create_deployment_url, create_deployment_payload_final, headers=headers)
	if create_deployment_response.status_code != 201:
		print('    Deployment creation failed. Got the following response: '+ str(create_deployment_response.status_code))
		print('    Possible Causes: ')
		print('        - The credentials could not be verified when creating deployment. Please review the Role ARNs stored')
		print('        - The AWS Account ID stored in the configuration file is not correct.')
		print('        - The external ID or AL AWS ID (733251395267 for US Customers, 857795874556 for EU Customers) is incorrect on the stored ARN.')
		print()
		exit()
	else :
		print('    Deployment successfully created. You should now see this deployment in the Alert Logic Console.')
		print()
	
	create_deployment_info = json.loads(create_deployment_response.text)
	global deployment_id
	deployment_id=create_deployment_info['id']

if central_role_arn != "":
	print('Creating credentials...')
	create_credentials()
	create_central_ct_credential()
	print()
	print('Creating deployment...')
	create_deployment()

else: 
	print('Creating credentials...')
	create_credentials()
	print()
	print('Creating deployment...')
	create_deployment()

#Next we need to add the external assets, DNS name or IP addresses. 

#List for logging purposes
external_assets_logging=[]

#Work out and POST dns names, then IP addresses if they exist 
if not external_dns_names :
	print('No external DNS names to add')
else:
	print('External DNS names detected in the config file. Creating these assets...')
	for dns in external_dns_names : 

		dns_payload= {
				"operation": "declare_asset",
				"type": "external-dns-name",
				"scope": "aws",
				"key": "/external-dns-name/"+dns+"",
				"properties": {
					"name": ""+dns+"",
					"dns_name": ""+dns+"",
					"state": "new"
				}
			}

		create_dns_payload=json.dumps(dns_payload)
		create_dns_url = '{0}/assets_write/v1/{1}/deployments/{2}/assets'.format(base_url, alert_logic_cid, deployment_id)
		create_dns_response = requests.put(create_dns_url, create_dns_payload, headers=headers)

		if create_dns_response.status_code != 201:
			print('    DNS with name '+dns+' was unable to be added. Got the following response: ',end='')
			print(create_dns_response)
		else :
			print('    DNS with name '+dns+' added successfully.')
			external_assets_logging.append("\t\t\t\tExternal DNS: "+dns+"\n")
	print()


if not external_ip_addresses:
        print('No external IP addresses to add')
else:
        print('External IP addresses detected in the config file. Creating these assets...')
        for ip in external_ip_addresses :

                ip_payload= {
                                "operation": "declare_asset",
                                "type": "external-ip",
                                "scope": "aws",
                                "key": "/external-ip/"+ip+"",
                                "properties": {
                                        "name": ""+ip+"",
                                        "dns_name": ""+ip+"",
                                        "state": "new"
                                }
                        }

                create_ip_payload=json.dumps(ip_payload)
                create_ip_url = '{0}/assets_write/v1/{1}/deployments/{2}/assets'.format(base_url, alert_logic_cid, deployment_id)
                create_ip_response = requests.put(create_ip_url, create_ip_payload, headers=headers)

                if create_ip_response.status_code != 201:
                        print('    IP address '+ip+' was unable to be added. Got the following response: ',end='')
                        print(create_ip_response)
                else :
                        print('    IP address '+ip+' added successfully.')
                        external_assets_logging.append("\t\t\t\tExternal IP: "+ip+"\n")
        print()

#Logging External Assets
if not external_assets_logging:
        external_assets_logging.append("\t\t\t\tNo external assets defined")
external_assets_list=''.join(external_assets_logging)


#List all deployments
print('Deployments for account '+alert_logic_cid+':\n')
all_deployments_url = '{0}/deployments/v1/{1}/deployments'.format(base_url, alert_logic_cid)
all_deployments_response = requests.get(all_deployments_url, headers=headers)
if all_deployments_response.status_code != 200:
	print('    Could not get existing deployments. Got response code: '+all_deployments_response.status_code)
else:
	all_deployments_info = json.loads(all_deployments_response.text)
	all_deployments_list = []
	all_deployments_list.append(["Name", "Platform", "ID", "Status"])
	#Parsing deployment output and outputting to user
	for i in range(len(all_deployments_info)):
		deployment_name=all_deployments_info[i]['name']
		deployment_platform=all_deployments_info[i]['platform']['type']
		deployment_id=all_deployments_info[i]['id']
		deployment_status=all_deployments_info[i]['status']['status']
		all_deployments_list.append([deployment_name, deployment_platform, deployment_id, deployment_status])

lengths = [max(len(str(row[i])) for row in all_deployments_list) for i in range(len(all_deployments_list[0]))] 
dep_list = ' '.join('{:<%d}' % l for l in lengths)
print(dep_list.format(*all_deployments_list[0]))
print('-' * (sum(lengths) + len(lengths) - 1))
for row in all_deployments_list[1:]:
    print(dep_list.format(*row))
print()

#Logging - Write to log file
#At the moment this is writing everything manually, may create a text payload and write that instead (more configurable). 
filename = 'aws-'+alert_logic_cid+'.log'
date_time=(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(current_time)))
if os.path.exists(filename):
    append_write = 'a' # append if already exists
else:
    append_write = 'w' # make a new file if not

write_log = open(filename,append_write)
write_log.write(str(date_time) + ":\tDeployment Name:" + str(aws_id) + "\n" + "\t\t\tRole ARN: " +role_arn+"\n" + "\t\t\tEntitlement: " +entitlement+"\n" + "\t\t\tCreated By: " +user_name+"\n" + "\t\t\tProtected Scope: \n" +scope_list+"\n" + "\t\t\tExternal Assets: \n" + external_assets_list+"\n")
write_log.close()
