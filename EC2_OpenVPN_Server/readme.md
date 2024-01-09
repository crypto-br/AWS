# Install OpenVPN Server in Amazon Linux 2 and Amazon Linux 2023

**Download configuration script for Amazon Linux 2**
```sh
$ wget  https://raw.githubusercontent.com/crypto-br/AWS/master/EC2_OpenVPN_Server/configure_server.sh
```
**Download configuration script for Amazon Linux 2023**
```sh
$ wget  https://raw.githubusercontent.com/crypto-br/AWS/master/EC2_OpenVPN_Server/configure_server_amzn_2023.sh
```
**Set execute permission**
```sh
$ chmod +x configure_server.sh # for Amazon Linux 2
$ chmod +x configure_server_amzn_2023.sh # for Amazon Linux 2023
```
**Run configuration script**
```sh
$ sudo ./configure_server.sh # for Amazon Linux 2
$ sudo ./configure_server_amzn_2023.sh # for Amazon Linux 2023
```
**Now, get client file .ovpn in /root and run in your client device**

**For create new client, just run script again and select option "New Client"**

[Download](https://openvpn.net/community-downloads/) Client OpenVPN for your O.S

**For remove default gateway or add new routes, edit this file**
```sh
$ sudo vim /etc/openvpn/server/server.conf
```

**Remove or comment this line for remove default gateway**
```sh
push "redirect-gateway def1 bypass-dhcp"
```
**Add new route add:**
```sh
push "route Network NetMask"
```

**Stop/Star OpenVPN Service**
```sh
$ sudo service openvpn-server@server.service stop or start
```

