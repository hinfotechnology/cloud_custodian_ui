import os
import subprocess
import boto3
from botocore.exceptions import ClientError
import concurrent.futures
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from .models import Policy
from django.conf import settings

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

def aws_services(request):
    if request.method == 'POST':
        aws_access_key_id = request.POST.get('aws_access_key_id')
        aws_secret_access_key = request.POST.get('aws_secret_access_key')
        initial_region = request.POST.get('aws_region', 'us-east-1')

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
            }

            # S3 is a global service, so we only need to query it once.
            s3 = session.client('s3')
            buckets = s3.list_buckets().get('Buckets', [])
            all_services['S3 Buckets'] = [{'name': b['Name'], 'region': 'global', 'status': 'N/A', 'creation_date': b['CreationDate']} for b in buckets]

            def fetch_resources_for_region(region):
                regional_services = {
                    'EC2 Instances': [],
                    'RDS Instances': [],
                }
                try:
                    region_session = boto3.Session(
                        aws_access_key_id=aws_access_key_id,
                        aws_secret_access_key=aws_secret_access_key,
                        region_name=region
                    )

                    # Get EC2 instances
                    ec2 = region_session.resource('ec2')
                    instances = ec2.instances.all()
                    for i in instances:
                        regional_services['EC2 Instances'].append({'id': i.id, 'status': i.state['Name'], 'region': region, 'creation_date': i.launch_time})

                    # Get RDS instances
                    rds = region_session.client('rds')
                    db_instances = rds.describe_db_instances().get('DBInstances', [])
                    for i in db_instances:
                        regional_services['RDS Instances'].append({'id': i['DBInstanceIdentifier'], 'status': i['DBInstanceStatus'], 'region': region, 'creation_date': i['InstanceCreateTime']})
                
                except ClientError as e:
                    if e.response['Error']['Code'] in ['AuthFailure', 'InvalidClientTokenId', 'UnrecognizedClientException', 'OptInRequired']:
                        pass  # Ignore regions that are not enabled
                    else:
                        # Optionally log the error for the specific region
                        print(f"Could not process region {region}: {e}")
                return regional_services

            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                future_to_region = {executor.submit(fetch_resources_for_region, region): region for region in regions}
                for future in concurrent.futures.as_completed(future_to_region):
                    try:
                        regional_services = future.result()
                        all_services['EC2 Instances'].extend(regional_services['EC2 Instances'])
                        all_services['RDS Instances'].extend(regional_services['RDS Instances'])
                    except Exception as exc:
                        # Handle exceptions from threads if necessary
                        print(f"Error fetching resources: {exc}")


            return render(request, 'manager/aws_services.html', {'services': all_services})

        except ClientError as e:
            error_message = e.response['Error']['Message']
            return render(request, 'manager/aws_services.html', {'error': error_message})
        except Exception as e:
            return render(request, 'manager/aws_services.html', {'error': str(e)})

    return render(request, 'manager/aws_services.html')
