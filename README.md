# KidVPN  
The world's smallest VPN server and client (For SylixOS and Linux).  

## Configure File  
* Configure file is a ini format:  
> 
|keywords| description |  
|:----:|:----:|  
|**mode**|KidVPN run mode, 'server' or 'client'|  
|**key_file**|KidVPN AES Key file|  
|**vnd_id**|Virtual network device ID (Only for SylixOS)|  
|**tap_name**|Virtual network device name (Only for Linux)|  
|**mtu**|1280 ~ 1472 (Optional default: 1472)|  
|**local_ip**|Local IP address (Only for Server)|  
|**server**|Server IP address (Only for Client)|  
|**port**|Local port (Optional default: 10088)|
|**hole_punching**|UDP Hole punching (Optional default: 0)|  
\* *If too many client in one VPN net you can use UDP hole punching to reduce server forwarding pressure.*  

* Server configure like this:
> [**server_0**]  
**mode=server**  
**key_file=serv.key**  
**vnd_id=0**  
**tap_name=tap0**  
**mtu=1472**  
**local_ip=192.168.0.1**  
**port=10088**

* Client configure like this:
> [**client_0**]  
**mode=client**  
**key_file=cli.key**  
**vnd_id=0**  
**tap_name=tap0**  
**mtu=1472**  
**server=123.123.123.123**  
**port=10088**  

## For SylixOS
* Step 1: Add vnd interface parameter in **/etc/ifparam.ini**
> \[**vnd-X**\]  
  *#X is a number of vnd ID)*  
  **enable=1**  
  *#enable(up) this interface*  
  **ipaddr=x.x.x.x**  
  *#should be a real ip address*  
  **netmask=x.x.x.x**  
  *#should be a real netmask*  
  **mac=xx:xx:xx:xx:xx:xx**  
  *#vnd mac address, If not, the system will use random numbers*  

* Step 2: Use **'vnd'** command add a virtual net device.
> **]# vnd add X**  
  *X is a number of vnd ID*

* Step 3: Use **'kidvpn'** to create a VPN connect.
> **]# kidvpn x.ini sector password**  
  *'x.ini' is vpn config file, 'sector' is ini sector which we will use, 'password' is password*

* Step 4: Use **'route'** command add some route entry to system, make route rules.

## For Linux
* Prepare for work:
> **]$ sudo apt-get install openssl**  
  *install OpenSSL library*  
  **]$ sudo apt-get install libssl-dev**  
  *install OpenSSL develop library*  
  **]$ make**  
  *make kidvpn tartget*
        
* Step 1: Add tap interface
> **]$ sudo tunctl -t tapX -u root**  
  *X is tap number*  
  **]$ sudo ifconfig tapX up**

* Step 2: Use **'ifconfig'** command set tapX address
> **]$ ifconfig tapX inet x.x.x.x netmask x.x.x.x**

* Step 3: Use **'kidvpn'** to create a VPN connect.
> **]$ sudo ./kidvpn x.ini sector password**  
  *'x.ini' is vpn config file, 'sector' is ini sector which we will use, 'password' is password*
        
* Step 4: Use **'route'** command add some route entry to system, make route rules.

Enjoy yourself \^\_\^

For help: **hanhui@acoinfo.com**