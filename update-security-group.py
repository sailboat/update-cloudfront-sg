import boto3
import hashlib
import json
import urllib2

# Name of the service, as seen in the ip-groups.json file, to extract information for
SERVICE = "CLOUDFRONT"
# Ports your application uses that need inbound permissions from the service for
INGRESS_PORTS = { 'Http' : 80, 'Https': 443 }
#SecurityGroups Name
GLOBAL_HTTP_SG="cfnt_global_http"
GLOBAL_HTTPS_SG="cfnt_global_https"
REGION_HTTP_SG="cfnt_region_http"
REGION_HTTPS_SG="cfnt_region_https"
# Tags which identify the security groups you want to update
SECURITY_GROUP_TAG_FOR_GLOBAL_HTTP = { 'Name': GLOBAL_HTTP_SG, 'AutoUpdate': 'true', 'Protocol': 'http' }
SECURITY_GROUP_TAG_FOR_GLOBAL_HTTPS = { 'Name': GLOBAL_HTTPS_SG, 'AutoUpdate': 'true', 'Protocol': 'https' }
SECURITY_GROUP_TAG_FOR_REGION_HTTP = { 'Name': REGION_HTTP_SG, 'AutoUpdate': 'true', 'Protocol': 'http' }
SECURITY_GROUP_TAG_FOR_REGION_HTTPS = { 'Name': REGION_HTTPS_SG, 'AutoUpdate': 'true', 'Protocol': 'https' }
# SNS Topic
TOPIC_ARN="arn:aws:sns:[region]:[accound-id]:xxxxxxxxxx"


def lambda_handler(event, context):
    mailtrg = False
    mail_message = "mail test body"
    
    print("Received event: " + json.dumps(event, indent=2))
    message = json.loads(event['Records'][0]['Sns']['Message'])

    # Load the ip ranges from the url
    ip_ranges = json.loads(get_ip_groups_json(message['url'], message['md5']))

    # extract the service ranges
    global_cf_ranges = get_ranges_for_service(ip_ranges, SERVICE, "GLOBAL")
    region_cf_ranges = get_ranges_for_service(ip_ranges, SERVICE, "REGION")
    ip_ranges = { "GLOBAL": global_cf_ranges, "REGION": region_cf_ranges }

    # update the security groups
    result, mailtrg = update_security_groups(ip_ranges)
    
    # if updated security groups, send mail
    if(mailtrg):
        send_mail(mail_message)

    return result

def get_ip_groups_json(url, expected_hash):
    print("Updating from " + url)

    response = urllib2.urlopen(url)
    ip_json = response.read()

    m = hashlib.md5()
    m.update(ip_json)
    hash = m.hexdigest()

    if hash != expected_hash:
        raise Exception('MD5 Mismatch: got ' + hash + ' expected ' + expected_hash)

    return ip_json

def get_ranges_for_service(ranges, service, subset):
    service_ranges = list()
    for prefix in ranges['prefixes']:
        if prefix['service'] == service and ((subset == prefix['region'] and subset == "GLOBAL") or (subset != 'GLOBAL' and prefix['region'] != 'GLOBAL')):
            print('Found ' + service + ' region: ' + prefix['region'] + ' range: ' + prefix['ip_prefix'])
            service_ranges.append(prefix['ip_prefix'])

    return service_ranges

def update_security_groups(new_ranges):
    client = boto3.client('ec2')

    global_http_group = get_security_groups_for_update(client, SECURITY_GROUP_TAG_FOR_GLOBAL_HTTP)
    global_https_group = get_security_groups_for_update(client, SECURITY_GROUP_TAG_FOR_GLOBAL_HTTPS)
    region_http_group = get_security_groups_for_update(client, SECURITY_GROUP_TAG_FOR_REGION_HTTP)
    region_https_group = get_security_groups_for_update(client, SECURITY_GROUP_TAG_FOR_REGION_HTTPS)

    print ('Found ' + str(len(global_http_group)) + ' ' + GLOBAL_HTTP_SG + ' HttpSecurityGroups to update')
    print ('Found ' + str(len(global_https_group)) + ' '+ GLOBAL_HTTPS_SG + ' HttpsSecurityGroups to update')
    print ('Found ' + str(len(region_http_group)) + ' ' + REGION_HTTP_SG + ' HttpSecurityGroups to update')
    print ('Found ' + str(len(region_https_group)) + ' ' + REGION_HTTPS_SG + ' HttpsSecurityGroups to update')

    result = list()
    global_http_updated = 0
    global_https_updated = 0
    region_http_updated = 0
    region_https_updated = 0
    update_trg = False

    for group in global_http_group:
        if update_security_group(client, group, new_ranges["GLOBAL"], INGRESS_PORTS['Http']):
            global_http_updated += 1
            result.append('Updated ' + group['GroupId'])
    for group in global_https_group:
        if update_security_group(client, group, new_ranges["GLOBAL"], INGRESS_PORTS['Https']):
            global_https_updated += 1
            result.append('Updated ' + group['GroupId'])
    for group in region_http_group:
        if update_security_group(client, group, new_ranges["REGION"], INGRESS_PORTS['Http']):
            region_http_updated += 1
            result.append('Updated ' + group['GroupId'])
    for group in region_https_group:
        if update_security_group(client, group, new_ranges["REGION"], INGRESS_PORTS['Https']):
            region_https_updated += 1
            result.append('Updated ' + group['GroupId'])

    result.append('Updated ' + str(global_http_updated) + ' of ' + str(len(global_http_group)) + ' ' + GLOBAL_HTTP_SG + ' HttpSecurityGroups')
    result.append('Updated ' + str(global_https_updated) + ' of ' + str(len(global_https_group)) + ' ' + GLOBAL_HTTPS_SG + ' HttpsSecurityGroups')
    result.append('Updated ' + str(region_http_updated) + ' of ' + str(len(region_http_group)) + ' ' + REGION_HTTP_SG + ' HttpSecurityGroups')
    result.append('Updated ' + str(region_https_updated) + ' of ' + str(len(region_https_group)) + ' ' + REGION_HTTPS_SG + ' HttpsSecurityGroups')
    
    # update check
    if((global_http_updated != 0) or (global_https_updated != 0) or (region_http_updated != 0) or (region_https_updated != 0)):
        update_trg = True
    
    return result,update_trg

def update_security_group(client, group, new_ranges, port):
    added = 0
    removed = 0

    if len(group['IpPermissions']) > 0:
        for permission in group['IpPermissions']:
            if permission['FromPort'] <= port and permission['ToPort'] >= port :
                old_prefixes = list()
                to_revoke = list()
                to_add = list()
                for range in permission['IpRanges']:
                    cidr = range['CidrIp']
                    old_prefixes.append(cidr)
                    if new_ranges.count(cidr) == 0:
                        to_revoke.append(range)
                        print(group['GroupId'] + ": Revoking " + cidr + ":" + str(permission['ToPort']))

                for range in new_ranges:
                    if old_prefixes.count(range) == 0:
                        to_add.append({ 'CidrIp': range })
                        print(group['GroupId'] + ": Adding " + range + ":" + str(permission['ToPort']))

                removed += revoke_permissions(client, group, permission, to_revoke)
                added += add_permissions(client, group, permission, to_add)
    else:
        to_add = list()
        for range in new_ranges:
            to_add.append({ 'CidrIp': range })
            print(group['GroupId'] + ": Adding " + range + ":" + str(port))
        permission = { 'ToPort': port, 'FromPort': port, 'IpProtocol': 'tcp'}
        added += add_permissions(client, group, permission, to_add)

    print (group['GroupId'] + ": Added " + str(added) + ", Revoked " + str(removed))
    return (added > 0 or removed > 0)

def revoke_permissions(client, group, permission, to_revoke):
    if len(to_revoke) > 0:
        revoke_params = {
            'ToPort': permission['ToPort'],
            'FromPort': permission['FromPort'],
            'IpRanges': to_revoke,
            'IpProtocol': permission['IpProtocol']
        }

        client.revoke_security_group_ingress(GroupId=group['GroupId'], IpPermissions=[revoke_params])

    return len(to_revoke)

def add_permissions(client, group, permission, to_add):
    if len(to_add) > 0:
        add_params = {
            'ToPort': permission['ToPort'],
            'FromPort': permission['FromPort'],
            'IpRanges': to_add,
            'IpProtocol': permission['IpProtocol']
        }

        client.authorize_security_group_ingress(GroupId=group['GroupId'], IpPermissions=[add_params])

    return len(to_add)

def get_security_groups_for_update(client, security_group_tag):
    filters = list();
    for key, value in security_group_tag.iteritems():
        filters.extend(
            [
                { 'Name': "tag-key", 'Values': [ key ] },
                { 'Name': "tag-value", 'Values': [ value ] }
            ]
        )

    response = client.describe_security_groups(Filters=filters)

    return response['SecurityGroups']

def send_mail(message):
   sns = boto3.client('sns')
   
   # Publish a message
   response = sns.publish(
       TargetArn=TOPIC_ARN,
       Subject="Updated CloudFront SecurityGroups",
       Message=message,
       MessageStructure='string'
   )
   return 'Success'

