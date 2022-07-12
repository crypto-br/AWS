# Install OpenVPN Server in Amazon Linux 2

**Download configuration script**
```sh
$ wget  https://raw.githubusercontent.com/crypto-br/AWS/master/EC2_OpenVPN_Server/configure_server.sh
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
