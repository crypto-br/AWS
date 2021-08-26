import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr
from datetime import date
from datetime import datetime
from dateutil.relativedelta import relativedelta
client = boto3.resource('dynamodb')
table = client.Table("YouTable")

def lambda_handler(event, context):
    ReciveEvent = event['YourEvent'] # For teste send {"YourEvent" : "YourValue"}
    cont = 0
    lista = []
    response = table.query(
        KeyConditionExpression=Key('YourKey').eq(YourEvent) # Filter by your event
            )
    Results = response['Items']
    return Results
