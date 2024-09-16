# AWS-CLI Commands
For more datails: [AWS CLI Command Reference](https://docs.aws.amazon.com/cli/latest/index.html)
## ECS
**Get your task ARN**
```sh
TASK_ARN=$(aws ecs list-tasks --cluster YOUR_CLUSTER --service YOUR_SERVICE --region YOUR_REGION --output text --query 'taskArns[0]')
```
**Describe your task**
```sh
aws ecs describe-tasks --cluster YOUR_CLUSTER --region YOUR_REGION --tasks $TASK_ARN
```
**Run command for open interactive shell**
```sh
aws ecs execute-command --region YOUR_REGION --cluster YOUR_CLUSTER --task $TASK_ARN --container YOUR_CONTAINER_NAME --command "/bin/bash" --interactive
```
## S3
**Sync local directory with bucket S3 and set public read permission**
```sh
$ aws s3 sync . s3://<yourbucket> --acl public-read
```
**Remove directory recursive**
```sh
$ aws s3 rm s3://<yourbucket> --recursive
```
**Sync bucket S3 with local directory and filter extension**
```sh
 $ aws s3 sync s3://YOUR_BUCKET/ LOCAL_PATH --exclude "*" --include "*.jpg"
```
**Sync bucket S3 with local directory and filter extension recursive**
```sh
aws s3 sync s3://YOUR_BUCKE/ LOCAL_PATH --recursive --exclude "*" --include "*.jpg"
```
**Show last file add on S3**
```sh
aws s3 ls $YOUR_BUCKET --recursive | sort | tail -n 1 | awk '{print $4}'
```

## Cloudfront
**List Cloudfront distributions**
```sh
$ aws cloudfront list-distributions
```
**Create invalidation full for Cloudfront**
```sh
$ aws cloudfront create-invalidation --distribution-id <YourDistributionID> --paths "/*"
```

## ECS
**List Tasks**
```sh
$ aws ecs list-task-definitions
```

**Run Tasks with Fargate**
```sh
$ aws ecs run-task --cluster YourCluster --task-definition YourTaskDefinition:1 --count 1 --launch-type FARGATE --network-configuration "awsvpcConfiguration={subnets=[subnet-YourSubnet],securityGroups=[sg-YourSG]}" --region <YourRegion>
```

## KMS
**Delete key**
```sh
$ aws kms schedule-key-deletion --key-id key_id --pending-window-in-days 7
```
