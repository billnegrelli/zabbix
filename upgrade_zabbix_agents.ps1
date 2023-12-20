
$Domain=$Env:USERDOMAIN
$ZabbixServiceName = "Zabbix Agent"
$ZabbixAgentLocalArchive="c:\alx\zabbix_agent-6.4.9-windows-amd64-openssl.zip"
$ZabbixAgentUri = "https://cdn.zabbix.com/zabbix/binaries/stable/6.4/6.4.9/zabbix_agent-6.4.9-windows-amd64-openssl.zip"
#$ZabbixAgentUNC = "\\a2terrace1\c$\alxsw\zabbix_agent-6.4.9-windows-amd64-openssl.zip"
$ZabbixAgentUNC = "\\p7adm1\c$\alxsw\zabbix_agent-6.4.9-windows-amd64-openssl.zip"
$ZabbixInstallLoc = "c:\zabbix\"
$ZabbixConfigPath = "c:\zabbix\conf\"
#$ZabbixSourceConfigFile=(gwmi win32_service|?{$_.name -eq "Zabbix Agent"}|select pathname).pathname.split(" ")[2]  -replace '"', ""
$ZabbixDestConfigFile="c:\zabbix\conf\zabbix_agentd.win.conf"
$hostname=$env:computername.ToLower()
#if ($ZabbixSourceConfigFile -eq $null){ $ZabbixSourceConfigFile="C:\zabbix\conf\zabbix_agentd.win.conf" }

$ZabbixServerIP=switch($Env:USERDOMAIN){
    "P7" {"10.180.159.187";break}
    "A6" {"10.106.1.10";break}
    "A2" {"10.6.5.9";break}
    "A2G1" {"10.6.5.9";break}
    default {"10.6.5.9";break}
}

If (Get-Service $ZabbixServiceName -ErrorAction SilentlyContinue) {
        If ((Get-Service $ZabbixServiceName).Status -eq 'Running') {
            Stop-Service $ZabbixServiceName
            $ZabbixSourceConfigFile=((gwmi win32_service|?{$_.name -eq "Zabbix Agent"}|select pathname).pathname.split(" ")[2]  -replace '"', "")
            c:\zabbix\bin\zabbix_agentd.exe -d
            if ($ZabbixSourceConfigFile -eq $ZabbixDestConfigFile) {
                Copy-Item $ZabbixSourceConfigFile -Destination $ZabbixConfigPath"zabbix_agentd.win.conf"
            }
            Get-Content $ZabbixSourceConfigFile | Where { $_ -notmatch '^#.*' -and $_ -notmatch '^\s*$' }| foreach-object -begin {$h=@{}} -process { $k = [regex]::split($_,'='); if(($k[0].CompareTo("") -ne 0) -and ($k[0].StartsWith("#") -ne $True)) { $h.Add($k[0], $k[1]) } }
            }Else{
            $ZabbixSourceConfigFile="C:\zabbix\conf\zabbix_agentd.conf"
            Get-Content $ZabbixSourceConfigFile | Where { $_ -notmatch '^#.*' -and $_ -notmatch '^\s*$' }| foreach-object -begin {$h=@{}} -process { $k = [regex]::split($_,'='); if(($k[0].CompareTo("") -ne 0) -and ($k[0].StartsWith("#") -ne $True)) { $h.Add($k[0], $k[1]) } }
        }
    }


#Invoke-WebRequest -Uri $ZabbixAgentUri -outfile $ZabbixAgentLocalArchive
#Expand-Archive -Path $ZabbixAgentLocalArchive -DestinationPath $ZabbixInstallLoc -force
Expand-Archive -Path $ZabbixAgentUNC -DestinationPath $ZabbixInstallLoc -force

$h.Server = $ZabbixServerIP
$h.ServerActive = $ZabbixServerIP
$h.Hostname = $hostname
$h.TLSAccept = "psk,unencrypted"
$h.TLSPSKFile = "c:\zabbix\conf\zabbix_agentd.psk"

(Get-Content -Path $ZabbixSourceConfigFile  | Where { $_ -notmatch '^#.*' -and $_ -notmatch '^\s*$' })| ForEach-Object {
    $line = $_
    $h.GetEnumerator() | ForEach-Object {
        if ($line -match $_.key+"=")
        {
          
            $line = ($_.key+"="+$_.value)

            
        }
    }
   $line
   } | add-Content -Path $ZabbixDestConfigFile

c:\zabbix\bin\zabbix_agentd.exe -c $ZabbixDestConfigFile -i
net start "Zabbix Agent" 

