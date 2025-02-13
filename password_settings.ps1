net accounts /MINPWAGE:20
net accounts /MAXPWAGE:90
net accounts /MINPWLEN:14
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PasswordComplexity" -Value 1 -Type DWord

# the next step should be performed manually.
# firstly run the command
#       secedit /export /areas USER_RIGHTS /cfg C:\SecPol.cfg
# then modify apporpriate file. 
# for description of variable meanings see https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/user-rights-assignment
# for description of well-known SIDS see https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
# for identifying not-known sids perform:
# $sid="<your-sid>"
# Get-CimInstance Win32_Account | Where-Object { $_.SID -eq $sid }
# or
# Get-WmiObject Win32_Account | Where-Object { $_.SID -eq $sid }
# also ensure that the line:
# SeTcbPrivilege = 
# is empty. This line is responsible for 'Act as part of the operating system' option.
# then run the command  
#       secedit /configure /db secedit.sdb /cfg C:\SecPol.cfg /areas USER_RIGHTS
# to verify changes just write:
# "whoami /priv"