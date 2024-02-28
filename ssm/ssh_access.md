# Open SSH Session Using AWS System Session Manager (SSM)

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
## Add the following text in the ~/.ssh/config file
```sh
 host i-* mi-*
    ProxyCommand sh -c "aws --region <YourRegion> --profile <YourProfile> ssm start-session --target %h --document-name AWS-StartSSHSession --parameters 'portNumber=%p'"
```
## Start SSH session through SSM
```sh
$ ssh -i your_key.pem ec2-user@<Instance ID>
```

**- Reference doc:** <br /> <br />
https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2-linux.html#cliv2-linux-install  <br /> <br />
https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html#install-plugin-linux
