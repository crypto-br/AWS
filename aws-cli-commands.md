# AWS-CLI Commands
## S3

**Sync local directory with bucket S3 and set public read permission**
```sh
$ aws s3 sync . s3://yourbucket --acl public-read
```
**Remove directory recursive**
```sh
$ aws s3 rm s3://mybucket/ --recursive
```

## Cloudfront
**Create invalidation full for Cloudfront**
```sh
$ aws cloudfront create-invalidation --distribution-id EDFDVBD6EXAMPLE --paths "/*"
```
