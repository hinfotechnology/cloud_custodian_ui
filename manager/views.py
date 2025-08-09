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
from datetime import datetime, timedelta
import json
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.contrib import messages

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

        # S3 is a global service, but we need the region for each bucket for operations.
        s3 = session.client('s3')
        try:
            buckets = s3.list_buckets().get('Buckets', [])
            for bucket in buckets:
                try:
                    location_info = s3.get_bucket_location(Bucket=bucket['Name'])
                    region = location_info['LocationConstraint']
                    if region is None:
                        # Buckets in us-east-1 have a null location constraint.
                        region = 'us-east-1'
                except ClientError as e:
                    # If we can't get bucket location, we can't do much with it.
                    # We can log the error and maybe default to a region.
                    print(f"Could not get location for bucket {bucket['Name']}: {e}")
                    region = 'us-east-1'  # Fallback region

                all_services['S3 Buckets'].append({
                    'name': bucket['Name'],
                    'region': region,
                    'status': 'N/A',
                    'creation_date': bucket['CreationDate'].isoformat()
                })
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

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor: # Increased max_workers to improve performance
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

    services, error = get_aws_resources(aws_access_key_id, aws_secret_access_key)

    if services:
        resource_counts = {key: len(value) for key, value in services.items()}
    else:
        resource_counts = {}

    return render(request, 'manager/dashboard.html', {
        'services': services,
        'error': error,
        'resource_counts': resource_counts,
        'resource_counts_json': json.dumps(resource_counts),
    })


def aws_services(request):
    aws_access_key_id = request.session.get('aws_access_key_id')
    aws_secret_access_key = request.session.get('aws_secret_access_key')

    if not aws_access_key_id or not aws_secret_access_key:
        return redirect('manager:login')

    services, error = get_aws_resources(aws_access_key_id, aws_secret_access_key)

    return render(request, 'manager/aws_services.html', {'services': services, 'error': error})


def cost_view(request):
    aws_access_key_id = request.session.get('aws_access_key_id')
    aws_secret_access_key = request.session.get('aws_secret_access_key')

    if not aws_access_key_id or not aws_secret_access_key:
        return redirect('manager:login')

    try:
        session = boto3.Session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            region_name='us-east-1'
        )
        ce_client = session.client('ce')

        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=180)

        response = ce_client.get_cost_and_usage(
            TimePeriod={
                'Start': start_date.strftime('%Y-%m-%d'),
                'End': end_date.strftime('%Y-%m-%d')
            },
            Granularity='MONTHLY',
            Metrics=['UnblendedCost'],
            GroupBy=[{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
        )

        all_cost_data = []
        for result in response['ResultsByTime']:
            for group in result['Groups']:
                all_cost_data.append({
                    'service': group['Keys'][0],
                    'amount': float(group['Metrics']['UnblendedCost']['Amount']),
                    'date': result['TimePeriod']['Start']
                })

        search_query = request.GET.get('q', '')
        if search_query:
            all_cost_data = [
                item for item in all_cost_data
                if search_query.lower() in item['service'].lower()
            ]

        paginator = Paginator(all_cost_data, 10)  # Show 10 items per page
        page_number = request.GET.get('page')
        try:
            cost_data = paginator.page(page_number)
        except PageNotAnInteger:
            cost_data = paginator.page(1)
        except EmptyPage:
            cost_data = paginator.page(paginator.num_pages)

        chart_data = {
            'labels': [item['date'] for item in all_cost_data],
            'datasets': [
                {
                    'label': service,
                    'data': [item['amount'] if item['service'] == service else 0 for item in all_cost_data],
                    'backgroundColor': f'rgba({i*50 % 255}, {i*100 % 255}, {i*150 % 255}, 0.5)',
                    'borderColor': f'rgba({i*50 % 255}, {i*100 % 255}, {i*150 % 255}, 1)',
                    'borderWidth': 1
                } for i, service in enumerate(set([item['service'] for item in all_cost_data]))
            ]
        }

        return render(request, 'manager/cost.html', {
            'cost_data': cost_data,
            'search_query': search_query,
            'chart_data': json.dumps(chart_data)
        })
    except ClientError as e:
        return render(request, 'manager/cost.html', {'error': e.response['Error']['Message']})
    except Exception as e:
        return render(request, 'manager/cost.html', {'error': str(e)})


def resource_details(request, service_name, resource_id):
    aws_access_key_id = request.session.get('aws_access_key_id')
    aws_secret_access_key = request.session.get('aws_secret_access_key')

    if not aws_access_key_id or not aws_secret_access_key:
        return redirect('manager:login')

    services, error = get_aws_resources(aws_access_key_id, aws_secret_access_key)

    if error:
        return render(request, 'manager/resource_details.html', {'error': error})

    resources = services.get(service_name, [])
    
    resource = None
    for res in resources:
        if res.get('id') == resource_id or res.get('name') == resource_id:
            resource = res
            break
    
    if not resource:
        return render(request, 'manager/resource_details.html', {'error': 'Resource not found.'})

    return render(request, 'manager/resource_details.html', {
        'service_name': service_name,
        'resource_id': resource_id,
        'resource': resource
    })


def delete_resource(request, service_name, resource_id):
    if request.method == 'POST':
        aws_access_key_id = request.session.get('aws_access_key_id')
        aws_secret_access_key = request.session.get('aws_secret_access_key')
        region = request.POST.get('region')

        if not region:
            messages.error(request, 'Region not specified.')
            return redirect('manager:aws_services')

        try:
            if service_name == 'S3 Buckets':
                # For S3, the client must be configured with the specific region of the bucket.
                s3 = boto3.client(
                    's3',
                    aws_access_key_id=aws_access_key_id,
                    aws_secret_access_key=aws_secret_access_key,
                    region_name=region
                )
                # Before deleting the bucket, we must delete all objects within it.
                paginator = s3.get_paginator('list_objects_v2')
                pages = paginator.paginate(Bucket=resource_id)

                delete_us = dict(Objects=[])
                for item in pages.search('Contents'):
                    if item:
                        delete_us['Objects'].append(dict(Key=item['Key']))

                # Check if there are any objects to delete
                if delete_us['Objects']:
                    s3.delete_objects(Bucket=resource_id, Delete=delete_us)
                
                s3.delete_bucket(Bucket=resource_id)
            else:
                session = boto3.Session(
                    aws_access_key_id=aws_access_key_id,
                    aws_secret_access_key=aws_secret_access_key,
                    region_name=region
                )
                if service_name == 'EC2 Instances':
                    ec2 = session.client('ec2')
                    ec2.terminate_instances(InstanceIds=[resource_id])
                elif service_name == 'RDS Instances':
                    rds = session.client('rds')
                    rds.delete_db_instance(DBInstanceIdentifier=resource_id, SkipFinalSnapshot=True)
            
            messages.success(request, f'Resource {resource_id} has been deleted successfully.')
        except ClientError as e:
            messages.error(request, f'Error deleting resource {resource_id}: {e}')
    return redirect('manager:aws_services')

def deactivate_resource(request, service_name, resource_id):
    if request.method == 'POST':
        aws_access_key_id = request.session.get('aws_access_key_id')
        aws_secret_access_key = request.session.get('aws_secret_access_key')
        region = request.POST.get('region')

        if not region:
            messages.error(request, 'Region not specified.')
            return redirect('manager:aws_services')

        try:
            session = boto3.Session(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region_name=region
            )
            if service_name == 'EC2 Instances':
                ec2 = session.client('ec2')
                ec2.stop_instances(InstanceIds=[resource_id])
            # Add other deactivation logic here
            
            messages.success(request, f'Resource {resource_id} has been deactivated successfully.')
        except ClientError as e:
            messages.error(request, f'Error deactivating resource {resource_id}: {e}')
    return redirect('manager:aws_services')
