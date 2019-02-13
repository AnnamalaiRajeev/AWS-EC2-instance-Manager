import boto3
from operator import itemgetter
from datetime import datetime, timedelta
import smtplib
import time


def send_mail(instance, instance_id, instance_type):
    fromaddr = 'rajeevchinni@gmail.com'
    toaddrs = 'rajeevchinni@gmail.com'
    username = 'rajeevchinni'
    password = 'Put_password_here'

    server = smtplib.SMTP("smtp.gmail.com:587")
    server.starttls()
    server.login(username, password)
    server.sendmail(fromaddr, toaddrs, "instance {} crossed Threshold.created new identical instance"
                                       " {} {}".format(instance, instance_id, instance_type))
    server.sendmail(fromaddr, toaddrs, "instance {} crossed Threshold.created new identical instance"
                                       " existing insatnces are {} {}".format(instance, instance_id, instance_type))
    server.sendmail(fromaddr, toaddrs, "instance {} crossed Threshold.created new identical instance"
                                       "existing insatnces are {} {}".format(instance, instance_id, instance_type))
    server.sendmail(fromaddr, toaddrs, "instance {} crossed Threshold.created new identical instance"
                                       " existing insatnces are {} {}".format(instance, instance_id, instance_type))

    server.quit()


now = datetime.utcnow()
past = now - timedelta(minutes=30)
future = now + timedelta(minutes=10)
Threshold = 90
instance_1 = 'i-037a4a3aec5719e30'
instance_2 = 'i-03e85a48a03150766'

ec2 = boto3.resource('ec2', region_name='us-west-1')
client = boto3.client('cloudwatch')


def save_me(instance):
    popped_list = [instance]
    ec2.instances.filter(InstanceIds=popped_list).stop()
    ec2.create_instances(ImageId='ami-0ad16744583f21877', MinCount=1, MaxCount=1)
    instances = ec2.instances.filter(
        Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'stopped']}])
    instance_id_array = []
    instance_type_array = []
    for instance in instances:
        instance_id_array.append(instance.id)
        instance_type_array.append(instance.instance_type)
    send_mail(instance, instance_id_array, instance_type_array)


while True:

    returned_cpu1= client.get_metric_statistics(

        Namespace='AWS/EC2',

        MetricName='CPUUtilization',

        Dimensions=[{'Name': "InstanceId", 'Value': instance_1}],

        StartTime=past,

        EndTime=future,

        Period=300,

        Statistics=['Minimum', 'Maximum', 'Average'],

        Unit='Percent'

    )
    datapoints = returned_cpu1['Datapoints']
    last_datapoint_1 = sorted(datapoints, key=itemgetter('Timestamp'))[-1]
    utilization_1 = float(last_datapoint_1['Average'])
    print("CPU_Utilization {}".format(utilization_1))


    returned_cpu2 = client.get_metric_statistics(

        Namespace='AWS/EC2',

        MetricName='CPUUtilization',

        Dimensions=[{'Name': "InstanceId", 'Value': instance_2}],

        StartTime=past,

        EndTime=future,

        Period=300,

        Statistics=['Minimum', 'Maximum', 'Average'],

        Unit='Percent'

    )

    datapoints = returned_cpu2['Datapoints']
    last_datapoint_2 = sorted(datapoints, key=itemgetter('Timestamp'))[-1]
    utilization_2 = float(last_datapoint_2['Average'])
    print("CPU_Utilization {}".format(utilization_2))

    if utilization_1 > Threshold:
        save_me(instance_1)
    elif utilization_2 > Threshold:
        save_me(instance_2)
    time.sleep(20)


