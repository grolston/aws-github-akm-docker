import boto3
from botocore.exceptions import ClientError
import json
import os
import requests
from base64 import b64encode
from nacl import encoding, public

iam_client = boto3.client('iam')

def publish_message(sns_message):
  sns_arn = os.environ['snsARN']
  snsclient = boto3.client('sns')
  print("Sending Error Message:", sns_message)
  snsclient.publish(
      TargetArn=sns_arn,
      Subject=f'AWS GitHub Secret AKM Error',
      Message=sns_message
  )

def list_access_key(user, status_filter):
  keydetails=iam_client.list_access_keys(UserName=user)
  key_details={}
  user_iam_details=[]
  for keys in keydetails['AccessKeyMetadata']:
    key_details['UserName']=keys['UserName']
    key_details['AccessKeyId']=keys['AccessKeyId']
    key_details['status']=keys['Status']
    user_iam_details.append(key_details)
    key_details={}
  return user_iam_details

def disable_key(access_key, username):
    try:
        iam_client.update_access_key(UserName=username, AccessKeyId=access_key, Status="Inactive")
        print(access_key + "has been disabled.")
    except ClientError as e:
        print("The access key with id", access_key, "cannot be found")

def delete_key(access_key, username):
    try:
        iam_client.delete_access_key(UserName=username, AccessKeyId=access_key)
        print (access_key + " has been deleted.")
    except ClientError as e:
        print("The access key with id", access_key, "cannot be found")

def encrypt(public_key: str, secret_value: str) -> str:
  """Encrypt a Unicode string using the public key."""
  public_key = public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder())
  sealed_box = public.SealedBox(public_key)
  encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
  return b64encode(encrypted).decode("utf-8")

def handler(event, context):
  # Grab env vars:
  config_bucket = os.environ['REPO_BUCKET']
  s3_key = os.environ['S3_KEY']
  iam_user = os.environ['IAM_USERNAME']
  github_user = os.environ['GITHUB_USER']
  github_user_token = os.environ['GITHUB_USER_TOKEN']
  github_secret_name_access_key_id = os.environ['GITHUB_SECRET_NAME_ACCESS_KEY_ID']
  github_secret_name_access_key = os.environ['GITHUB_SECRET_NAME_ACCESS_KEY']
  print("Starting key rotation process for user: ", iam_user)
  ## get all IAM user keys
  user_access_keys = list_access_key(user=iam_user, status_filter='Active')
  ## delete all keys for security
  for user_accesskey in user_access_keys:
    print("Attempting to disable and delete Access Key ID:", user_accesskey['AccessKeyId'])
    disable_key(access_key=user_accesskey['AccessKeyId'], username=user_accesskey['UserName'])
    delete_key(access_key=user_accesskey['AccessKeyId'], username=user_accesskey['UserName'])
    print("Deletion complete for Access Key ID:", user_accesskey['AccessKeyId'])
  ## create only one new key
  print("Creating new key for", iam_user)
  access_key_metadata = iam_client.create_access_key(UserName=iam_user)
  access_key = access_key_metadata['AccessKey']['AccessKeyId']
  secret_key = access_key_metadata['AccessKey']['SecretAccessKey']
  print("New API key generated for IAM user", iam_user)
  print("IAM user key rotation process for user", iam_user, "complete.")

  ## update repos
  print("Retrieving repo config list from S3 Bucket ", config_bucket, " with key ", s3_key )
  s3 = boto3.resource('s3')
  content_object = s3.Object(config_bucket, s3_key)
  file_content = content_object.get()['Body'].read().decode('utf-8')
  repo_content = json.loads(file_content)

  for repo in repo_content['Repos']:
    repo_Name = (repo['Name'])
    repo_Owner = (repo['Owner'])
    # Each repo will have its own GH Public Key used for encrypting. The key is required when creating the secret
    repo_Get_Pub_Key_URL = 'https://api.github.com/repos/'+ repo_Owner + '/'+ repo_Name + '/actions/secrets/public-key'
    print("Requesting public key from", repo_Get_Pub_Key_URL )
    pub_key_response = requests.get(repo_Get_Pub_Key_URL, auth=(github_user,github_user_token))
    pub_key = pub_key_response.json()['key']
    pub_key_id = pub_key_response.json()['key_id']
    print("Retrieved public key id ", pub_key_id )
    encrypted_Access_Key_Id = encrypt(pub_key, access_key)
    encrypted_Secret_Key = encrypt(pub_key, secret_key)
    ## Setup Access Key (Secret Key)
    repo_Put_Secret_URL_Access_Key = 'https://api.github.com/repos/'+ repo_Owner + '/'+ repo_Name + '/actions/secrets/'+ github_secret_name_access_key
    parameters_Access_Key = {
      "encrypted_value": encrypted_Secret_Key,
      "key_id": pub_key_id
    }
    print("Access Key URL:" , repo_Put_Secret_URL_Access_Key)
    requests.request("put", repo_Put_Secret_URL_Access_Key, auth=(github_user,github_user_token), json=parameters_Access_Key )
    ## Setup Access Key ID
    repo_Put_Secret_URL_Access_Key_Id = 'https://api.github.com/repos/'+ repo_Owner + '/'+ repo_Name + '/actions/secrets/'+ github_secret_name_access_key_id
    parameters_Access_Key_Id = {
      "encrypted_value": encrypted_Access_Key_Id,
      "key_id": pub_key_id
    }
    print("Access Key ID URL:" , repo_Put_Secret_URL_Access_Key_Id)
    requests.request("put", repo_Put_Secret_URL_Access_Key_Id, auth=(github_user,github_user_token), json=parameters_Access_Key_Id )
    print("repo secret update complete for", repo_Owner, "/", repo_Name)

  print("Job Complete")
  return {
        'statusCode': 200,
        'body': 'Key rotation and secret update complete'
  }
