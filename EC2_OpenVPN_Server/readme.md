# Install OpenVPN Server in Amazon Linux 2

**Download configuration script**
```sh
$ wget https://github.com/crypto-br/AWS/blob/master/EC2_OpenVPN_Server/configure_server.sh
```
**Set execute permission**
```sh
$ chmod +x configure_server.sh
```
**Run configuration script**
```sh
$ sudo ./configure_server.sh
```
**Now, get client file .ovpn in /root and run in your client device**

**For create new client, just run script again and select option "New Client"**
