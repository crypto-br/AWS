# Open RDP Session Using AWS System Session Manager (SSM)

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
## Access the instance via SSM from the AWS console initially to create a user via PowerShell
## Asked to enter a password
```ps
$Password = Read-Host -AsSecureString
```
## Creating a local user
```ps
New-LocalUser "yourUser" -Password $Password
```
## Adding User to Remote Access Group
```ps
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "yourUser"
```
## Open a session on the instance SSM with port forwarding
```sh
$ aws ssm start-session --target "instanceID" --profile <yourProfile> --document-name AWS-StartPortForwardingSession --parameters "localPortNumber=55678,portNumber=3389"
```
## Open the RDP session (you will be prompted for username and password)
```sh
$ rdesktop localhost:55678
```

**- Reference doc:** <br /> <br />
https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2-linux.html#cliv2-linux-install  <br /> <br />
https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html#install-plugin-linux
