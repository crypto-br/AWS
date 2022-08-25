# AWS-CLI Commands
For more datails: [AWS CLI Command Reference](https://docs.aws.amazon.com/cli/latest/index.html)
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
**List Tasks
```sh
$ aws ecs list-task-definitions
```

**Run Tasks with Fargate
```sh
$ aws ecs run-task --cluster YourCluster --task-definition YourTaskDefinition:1 --count 1 --launch-type FARGATE --network-configuration "awsvpcConfiguration={subnets=[subnet-YourSubnet],securityGroups=[sg-YourSG]}" --region <YourRegion>
```
