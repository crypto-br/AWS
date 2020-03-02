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

## Cloudfront
**List Cloudfront distributions**
```sh
$ aws cloudfront list-distributions
```
**Create invalidation full for Cloudfront**
```sh
$ aws cloudfront create-invalidation --distribution-id <YourDistributionID> --paths "/*"
```
