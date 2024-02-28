# Open MySQL(RDS) session using AWS System Session Manager (SSM) and SSH tunnel

## Configuration using Linux
## Install AWS-CLI
```sh
$ curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
$ unzip awscliv2.zip
$ sudo ./aws/install
```
## Install System Manager Plugin
```sh
$ curl "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/ubuntu_64bit/session-manager-plugin.deb" -o "session-manager-plugin.deb"
$ sudo dpkg -i session-manager-plugin.deb
```
## Open a session with an EC2 instance that has access to the RDS database
```sh
$ aws ssm start-session --target <instanceID> --profile <yourProfile> --document-name AWS-StartPortForwardingSession --parameters "portNumber=22,localPortNumber=9999"
```
## Start the SSH session through SSM by doing the port forwarding to RDS
```sh
$ ssh -i yourKey.pem ec2-user@localhost -p 9999 -N -L 3388:<enpointRDS>:3306
```
## Access the database
```sh
$ mysql -u seuUsuario --host=127.0.0.1 -P 3388 -p
```

**- Reference doc:** <br /> <br />
https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2-linux.html#cliv2-linux-install  <br /> <br />
https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html#install-plugin-linux
