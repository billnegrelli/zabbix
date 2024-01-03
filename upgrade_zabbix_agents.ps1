
$Domain=$Env:USERDOMAIN
$ZabbixServiceName = "Zabbix Agent"
$ZabbixVersion = "6.4.10"
$ZabbixAgentLocalArchive="c:\alxsw\zabbix_agent-6.4.10-windows-amd64-openssl.zip"
#$ZabbixAgentUri = "https://cdn.zabbix.com/zabbix/binaries/stable/6.4/6.4.10/zabbix_agent-6.4.10-windows-amd64-openssl.zip"
$ZabbixAgentUNC = "\\a2terrace1\c$\alxsw\zabbix_agent-6.4.9-windows-amd64-openssl.zip"
#$ZabbixAgentUNC = "\\p2adm4\alxsw$\zabbix_agent-$ZabbixVersion-windows-amd64-openssl.zip"
#$ZabbixAgentUNC = "\\p7adm1\c$\alxsw\zabbix_agent-6.4.9-windows-amd64-openssl.zip"
$ZabbixInstallLoc = "c:\zabbix\"
$ZabbixConfigPath = "c:\zabbix\conf\"
#$ZabbixSourceConfigFile=(gwmi win32_service|?{$_.name -eq "Zabbix Agent"}|select pathname).pathname.split(" ")[2]  -replace '"', ""
$ZabbixDestConfigFile="c:\zabbix\conf\zabbix_agentd.win.conf"
$hostname=$env:computername.ToLower()
#$ZabbixTLSPSK="629c38f8e54b18ff7bc09b7bef7d10b1cb7ef6e394b33b52e54fe4f6bd429f8ced3bba1575ed0965b2a3d71a6c8e37ae1587aec5dc3ec53aa690f3832dcedcd9"
$ZabbixTLSPSK="358ea1654b4842fc333b5cf4c525cd9c705d3557eb813db1f24125ea7a2b2c4dd0e9ca6404ae4a14b3572ed66caa802f36392f93dbc41103bc93fc82fa896e3d"
#$TLSPSKIdentity="P7Zabbix"
$TLSPSKIdentity="10.226.12.116"
#if ($ZabbixSourceConfigFile -eq $null){ $ZabbixSourceConfigFile="C:\zabbix\conf\zabbix_agentd.win.conf" }

#\\a2terrace1\c$\alxsw\zabbix_agent-6.4.9-windows-amd64-openssl.zip"
#\\p2adm4\alxsw$\zabbix_agent-6.4.10-windows-amd64-openssl.zip
#\\p4adm5\alxsw$\zabbix_agent-6.4.10-windows-amd64-openssl.zip
#\\p7adm1\c$\alxsw\zabbix_agent-6.4.9-windows-amd64-openssl.zip

$ZabbixServerIP=switch($Env:USERDOMAIN){
    "P7" {"10.180.159.187";break}
    "P2" {"10.216.234.141";break}
    "A6" {"10.106.1.10";break}
    "A2" {"10.6.5.9";break}
    "P4" {"10.216.234.141";break}
    "A2G1" {"10.6.5.9";break}
    default {"10.6.5.9";break}
}



#Invoke-WebRequest -Uri $ZabbixAgentUri -outfile $ZabbixAgentLocalArchive
#Expand-Archive -Path $ZabbixAgentLocalArchive -DestinationPath $ZabbixInstallLoc -force
Expand-Archive -Path $ZabbixAgentUNC -DestinationPath $ZabbixInstallLoc -force

#Invoke-WebRequest -Uri https://a2g1monitor1.online15.net/psk/psk.php?hostid=11401

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
    }Else{
    #new install
    $ZabbixSourceConfigFile="C:\zabbix\conf\zabbix_agentd.conf"
    Get-Content $ZabbixSourceConfigFile | Where { $_ -notmatch '^#.*' -and $_ -notmatch '^\s*$' }| foreach-object -begin {$h=@{}} -process { $k = [regex]::split($_,'='); if(($k[0].CompareTo("") -ne 0) -and ($k[0].StartsWith("#") -ne $True)) { $h.Add($k[0], $k[1]) } }
}

$h.Server = $ZabbixServerIP
$h.ServerActive = $ZabbixServerIP
$h.Hostname = $hostname
$h.TLSAccept = "psk,unencrypted"
$h.TLSConnect="psk"
$h.TLSPSKIdentity=$TLSPSKIdentity
$h.TLSPSKFile = "c:\zabbix\conf\zabbix_agentd.psk"
$h.TLSCipherPSK13="TLS_AES_128_GCM_SHA256"
$h.LogFile = "c:\zabbix\zabbix_agentd.log"
$ZabbixTLSPSK| Add-Content -Path $h.TLSPSKFile


#(Get-Content -Path $ZabbixSourceConfigFile  | Where { $_ -notmatch '^#.*' -and $_ -notmatch '^\s*$' })| ForEach-Object {
#    $line = $_
#    $h.GetEnumerator() | ForEach-Object {
#        if ($line -match $_.key+"=")
#        {
#          
#            $line = ($_.key+"="+$_.value)
#
#            
#        }
#    }
#   $line
#   } | add-Content -Path $ZabbixDestConfigFile

$h.GetEnumerator() | ForEach-Object {  $line = ($_.key+"="+$_.value) |add-Content -Path $ZabbixDestConfigFile}
netsh advfirewall firewall add rule name="Open Zabbix agentd port 10050 inbound" dir=in action=allow protocol=TCP localport=10050
netsh advfirewall firewall add rule name="Open Zabbix trapper port 10051 outbound" dir=out action=allow protocol=TCP localport=10051

c:\zabbix\bin\zabbix_agentd.exe -c $ZabbixDestConfigFile -i
net start "Zabbix Agent" 

