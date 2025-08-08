import os
import subprocess
import boto3
from botocore.exceptions import ClientError
import concurrent.futures
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from .models import Policy
from django.conf import settings
from django.contrib.auth import logout
from datetime import datetime
import json

def login_view(request):
    if request.session.get('aws_access_key_id'):
        return redirect('manager:dashboard')
        
    if request.method == 'POST':
        aws_access_key_id = request.POST.get('aws_access_key_id')
        aws_secret_access_key = request.POST.get('aws_secret_access_key')

        try:
            session = boto3.Session(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region_name='us-east-1'
            )
            sts_client = session.client('sts')
            sts_client.get_caller_identity()
            
            request.session['aws_access_key_id'] = aws_access_key_id
            request.session['aws_secret_access_key'] = aws_secret_access_key
            return redirect('manager:dashboard')
        except ClientError:
            return render(request, 'manager/login.html', {'error': 'Invalid AWS credentials'})
    return render(request, 'manager/login.html')

def logout_view(request):
    request.session.flush()
    return redirect('manager:login')

def policy_list(request):
    policies = Policy.objects.all()
    return render(request, 'manager/policy_list.html', {'policies': policies})

def upload_policy(request):
    if request.method == 'POST':
        policy_name = request.POST.get('name')
        policy_description = request.POST.get('description')
        policy_content = request.POST.get('policy_content')

        if not policy_name or not policy_content:
            # Handle error: name and content are required
            return redirect('manager:policy_list')

        # Create policy file
        file_name = f"{policy_name.replace(' ', '_').lower()}.yml"
        file_path = os.path.join(settings.BASE_DIR, 'policies', file_name)

        with open(file_path, 'w') as f:
            f.write(policy_content)

        # Create policy object in database
        Policy.objects.create(
            name=policy_name,
            description=policy_description,
            file_path=file_path
        )
        return redirect('manager:policy_list')
    return render(request, 'manager/upload_policy.html')


def edit_policy(request, pk):
    policy = get_object_or_404(Policy, pk=pk)
    if request.method == 'POST':
        policy.name = request.POST.get('name')
        policy.description = request.POST.get('description')
        policy_content = request.POST.get('policy_content')

        with open(policy.file_path, 'w') as f:
            f.write(policy_content)

        policy.save()
        return redirect('manager:policy_list')

    with open(policy.file_path, 'r') as f:
        policy_content = f.read()

    return render(request, 'manager/edit_policy.html', {'policy': policy, 'policy_content': policy_content})


def run_policy(request, pk):
    policy = get_object_or_404(Policy, pk=pk)
    
    # Security Note: Running shell commands from a web application is dangerous.
    # 1.  **Never trust user input directly.** Sanitize and validate all inputs.
    #     In this case, `policy.file_path` comes from our database, which is safer,
    #     but we must ensure that the file path cannot be manipulated by a user.
    # 2.  **Use absolute paths** for commands and files.
    # 3.  **Run with minimal privileges.** The user running the Django server
    #     should have the least possible permissions.
    # 4.  **Avoid `shell=True`** if possible. It can be a major security risk
    #     if the command string is constructed from external input.
    #     Here, we are using a fixed command format, which is safer.
    
    try:
        # Ensure the custodian command is available and in the system's PATH
        command = ['custodian', 'run', '--output-dir', '.', policy.file_path]
        
        # Execute the command
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,  # Raise an exception for non-zero exit codes
            cwd=os.path.join(settings.BASE_DIR, 'policies') # Run in the policies directory
        )
        
        return JsonResponse({'status': 'success', 'output': result.stdout, 'error': result.stderr})
        
    except FileNotFoundError:
        return JsonResponse({'status': 'error', 'output': 'Error: "custodian" command not found. Make sure it is installed and in your PATH.'})
    except subprocess.CalledProcessError as e:
        # This catches errors from the command itself (non-zero exit code)
        return JsonResponse({'status': 'error', 'output': e.stdout, 'error': e.stderr})
    except Exception as e:
        # Catch any other exceptions
        return JsonResponse({'status': 'error', 'output': str(e)})

def get_aws_resources(aws_access_key_id, aws_secret_access_key, initial_region='us-east-1'):
    try:
        session = boto3.Session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name=initial_region
        )
        ec2_client = session.client('ec2')
        regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

        all_services = {
            'EC2 Instances': [],
            'S3 Buckets': [],
            'RDS Instances': [],
            'VPCs': [],
            'Subnets': [],
            'Security Groups': [],
        }

        # S3 is a global service, so we only need to query it once.
        s3 = session.client('s3')
        try:
            buckets = s3.list_buckets().get('Buckets', [])
            all_services['S3 Buckets'] = [{'name': b['Name'], 'region': 'global', 'status': 'N/A', 'creation_date': b['CreationDate'].isoformat()} for b in buckets]
        except ClientError as e:
            print(f"Could not list S3 buckets: {e}")


        def fetch_resources_for_region(region):
            regional_services = {
                'EC2 Instances': [],
                'RDS Instances': [],
                'VPCs': [],
                'Subnets': [],
                'Security Groups': [],
            }
            try:
                # Re-use the session to create clients for the specific region
                ec2 = session.client('ec2', region_name=region)
                rds = session.client('rds', region_name=region)

                # Get EC2 instances
                instances = ec2.describe_instances().get('Reservations', [])
                for reservation in instances:
                    for i in reservation['Instances']:
                        regional_services['EC2 Instances'].append({'id': i['InstanceId'], 'status': i['State']['Name'], 'region': region, 'creation_date': i['LaunchTime'].isoformat()})

                # Get RDS instances
                db_instances = rds.describe_db_instances().get('DBInstances', [])
                for i in db_instances:
                    regional_services['RDS Instances'].append({'id': i['DBInstanceIdentifier'], 'status': i['DBInstanceStatus'], 'region': region, 'creation_date': i['InstanceCreateTime'].isoformat()})
                
                # Get VPCs
                vpcs = ec2.describe_vpcs().get('Vpcs', [])
                for vpc in vpcs:
                    regional_services['VPCs'].append({'id': vpc['VpcId'], 'is_default': vpc['IsDefault'], 'cidr_block': vpc['CidrBlock'], 'region': region})

                # Get Subnets
                subnets = ec2.describe_subnets().get('Subnets', [])
                for subnet in subnets:
                    regional_services['Subnets'].append({'id': subnet['SubnetId'], 'vpc_id': subnet['VpcId'], 'cidr_block': subnet['CidrBlock'], 'availability_zone': subnet['AvailabilityZone'], 'region': region})

                # Get Security Groups
                sgs = ec2.describe_security_groups().get('SecurityGroups', [])
                for sg in sgs:
                    regional_services['Security Groups'].append({'id': sg['GroupId'], 'name': sg['GroupName'], 'vpc_id': sg.get('VpcId', 'N/A'), 'region': region})

            except ClientError as e:
                if e.response['Error']['Code'] in ['AuthFailure', 'InvalidClientTokenId', 'UnrecognizedClientException', 'OptInRequired']:
                    pass  # Ignore regions that are not enabled
                else:
                    # Optionally log the error for the specific region
                    print(f"Could not process region {region}: {e}")
            return regional_services

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor: # Reduced max_workers to avoid rate limiting
            future_to_region = {executor.submit(fetch_resources_for_region, region): region for region in regions}
            for future in concurrent.futures.as_completed(future_to_region):
                try:
                    regional_services = future.result()
                    all_services['EC2 Instances'].extend(regional_services['EC2 Instances'])
                    all_services['RDS Instances'].extend(regional_services['RDS Instances'])
                    all_services['VPCs'].extend(regional_services['VPCs'])
                    all_services['Subnets'].extend(regional_services['Subnets'])
                    all_services['Security Groups'].extend(regional_services['Security Groups'])
                except Exception as exc:
                    # Handle exceptions from threads if necessary
                    print(f"Error fetching resources: {exc}")
        return all_services, None
    except ClientError as e:
        return None, e.response['Error']['Message']
    except Exception as e:
        return None, str(e)

def dashboard(request):
    aws_access_key_id = request.session.get('aws_access_key_id')
    aws_secret_access_key = request.session.get('aws_secret_access_key')

    if not aws_access_key_id or not aws_secret_access_key:
        return redirect('manager:login')

    if 'services' not in request.session or request.GET.get('refresh'):
        services, error = get_aws_resources(aws_access_key_id, aws_secret_access_key)
        request.session['services'] = services
        request.session['error'] = error
        request.session['last_refreshed'] = datetime.now().isoformat()
    else:
        services = request.session['services']
        error = request.session['error']

    if services:
        resource_counts = {key: len(value) for key, value in services.items()}
    else:
        resource_counts = {}

    return render(request, 'manager/dashboard.html', {
        'services': services,
        'error': error,
        'resource_counts': resource_counts,
        'resource_counts_json': json.dumps(resource_counts),
        'last_refreshed': request.session.get('last_refreshed')
    })


def aws_services(request):
    aws_access_key_id = request.session.get('aws_access_key_id')
    aws_secret_access_key = request.session.get('aws_secret_access_key')

    if not aws_access_key_id or not aws_secret_access_key:
        return redirect('manager:login')

    if 'services' not in request.session or request.GET.get('refresh'):
        services, error = get_aws_resources(aws_access_key_id, aws_secret_access_key)
        request.session['services'] = services
        request.session['error'] = error
    else:
        services = request.session['services']
        error = request.session['error']

    return render(request, 'manager/aws_services.html', {'services': services, 'error': error})
