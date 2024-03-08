function getZabbixAgentVersion()
    {
        If (Get-Service $ZabbixServiceName -ErrorAction SilentlyContinue) {
        $versionNumber=0
        $pattern = '\d+\.\d+\.\d+'
        $var = & c:\zabbix\bin\zabbix_agentd.exe -V
        if ($var[0] -match $pattern) {
        $versionNumber = $matches[0]
        }
        return $versionNumber
        }
    }

write-host "Setting up Environment..." -noNewLine -foregroundcolor Green
$P7PSK = "46483e18e3370e07a045cc9a7aaa732291a32ed247e6f92c71a682d4e66f54031842e1dbcad2909671849649fd4dfcb8005979fcec4b49f9bcb08215261f4c8d`n`r"
$A2PSK = "9ab57617df58384639dfa0578e52da695a293c468ccd9609b378991345cdf990ec9aa95754cee1b2ebf553e57d38eceb195a8c11cd2ea735bc4975e79078d6ef`n`r"
$A6PSK = "629c38f8e54b18ff7bc09b7bef7d10b1cb7ef6e394b33b52e54fe4f6bd429f8ced3bba1575ed0965b2a3d71a6c8e37ae1587aec5dc3ec53aa690f3832dcedcd9`n`r"
$B1PSK = "ce4cabfc2ca79abee334cd2f2230305274926e9f0c82e04ea8c2f163691905add4e4f58ec5237cb4070db1722ea7a1e6147dc16180b783931c5abd9c6dad70af`n`r"
$B2PSK = "ce4cabfc2ca79abee334cd2f2230305274926e9f0c82e04ea8c2f163691905add4e4f58ec5237cb4070db1722ea7a1e6147dc16180b783931c5abd9c6dad70af`n`r"
$Domain=$Env:USERDOMAIN
$ZabbixServiceName = "Zabbix Agent"
write-host "." -noNewLine -ForegroundColor Green
$ZabbixVersion = "6.4.12"
$ZabbixAgentLocalArchive="c:\alxsw\zabbix_agent-6.4.12-windows-amd64-openssl.zip"
$ZabbixAgentUri = "https://cdn.zabbix.com/zabbix/binaries/stable/6.4/6.4.12/zabbix_agent-6.4.12-windows-amd64-openssl.zip"
write-host "." -noNewLine -ForegroundColor Green
$ZabbixInstallLoc = "c:\zabbix\"
$ZabbixConfigPath = "c:\zabbix\conf\"
$ZabbixDestConfigFile="c:\zabbix\conf\zabbix_agentd.win.conf"
write-host "." -noNewLine -ForegroundColor Green
$TLSPSKFile = "c:\zabbix\conf\zabbix_agentd.psk"
write-host "." -noNewLine -ForegroundColor Green
write-host "."  -ForegroundColor Green
write-host "Discovering IP Address" -noNewLine -ForegroundColor Green
$hostname=$env:computername.ToLower()
$TLSPSKIdentity=$env:HostIP = (
    Get-NetIPConfiguration |
    Where-Object {
        $_.IPv4DefaultGateway -ne $null -and
        $_.NetAdapter.Status -ne "Disconnected"
        }
).IPv4Address.IPAddress 
write-host "." -noNewLine  -ForegroundColor Green

switch($Domain){
    "B1" {$ZabbixServerIP="10.52.5.113";$ZabbixTLSPSK=$B1PSK;$ZabbixAgentUNC="\\b1terrace1\alxsw$\zabbix_agent-"+$ZabbixVersion+"-windows-amd64-openssl.zip";break}
    "B2" {$ZabbixServerIP="10.52.5.113";$ZabbixTLSPSK=$B2PSK;$ZabbixAgentUNC="\\b2terrace1\alxsw$\zabbix_agent-"+$ZabbixVersion+"-windows-amd64-openssl.zip";break}
    "P7" {$ZabbixServerIP="10.180.159.187";$ZabbixAgentUNC="\\p7adm1\c$\alxsw\zabbix_agent-"+$ZabbixVersion+"-windows-amd64-openssl.zip";break}
    "P2" {$ZabbixServerIP="10.216.234.141";$ZabbixTLSPSK=$P7PSK;$ZabbixAgentUNC="\\p2adm4\alxsw$\zabbix_agent-"+$ZabbixVersion+"-windows-amd64-openssl.zip";break}
    "A6" {$ZabbixServerIP="10.106.1.10";$ZabbixTLSPSK=$A6PSK;$ZabbixAgentUNC="\\a6terrace2\alxsw$\zabbix_agent-"+$ZabbixVersion+"-windows-amd64-openssl.zip";break}
    "P4" {$ZabbixServerIP="10.216.234.141";$ZabbixAgentUNC="\\a2terrace1\c$\alxsw\zabbix_agent-"+$ZabbixVersion+"-windows-amd64-openssl.zip";break}
    "A2" {$ZabbixServerIP="10.6.5.9";$ZabbixTLSPSK=$A2PSK;$ZabbixAgentUNC="\\a2terrace1\alxsw$\zabbix_agent-"+$ZabbixVersion+"-windows-amd64-openssl.zip";break}
    "A2D1" {$ZabbixServerIP="10.8.5.7";$ZabbixAgentUNC="\\a2terrace1\alxsw$\zabbix_agent-"+$ZabbixVersion+"-windows-amd64-openssl.zip";break}
    default {$ZabbixServerIP="10.6.5.9";$ZabbixTLSPSK=$A2PSK;$ZabbixAgentUNC="\\a2terrace1\alxsw$\zabbix_agent-"+$ZabbixVersion+"-windows-amd64-openssl.zip";break}
}
write-host "." -ForegroundColor Green

Set-Location -Path $ZabbixInstallLoc
$h=@{}
write-host "Checking Service..." -foregroundcolor green
If (Get-Service $ZabbixServiceName -ErrorAction SilentlyContinue) {
        $installedVersion = getZabbixAgentVersion
        if ([System.Version]$installedVersion -ge [System.Version]$ZabbixVersion) {
         Stop-Service $ZabbixServiceName
         write-host "Stopping Service..." -foregroundcolor green
         #get Zabbix config from service entry
         $ZabbixSourceConfigFile=((gwmi win32_service|?{$_.name -eq "Zabbix Agent"}|select pathname).pathname.split(" ")[2]  -replace '"', "")
         #delete zabbix agent service
         c:\zabbix\bin\zabbix_agentd.exe -d
         #assign all non-commented items in config file to variable '$h'
         Get-Content $ZabbixSourceConfigFile | Where { $_ -notmatch '^#.*' -and $_ -notmatch '^\s*$' }| foreach-object -begin {$h=@{}} -process { $k = [regex]::split($_,'='); if(($k[0].CompareTo("") -ne 0) -and ($k[0].StartsWith("#") -ne $True)) { $h.Add($k[0], $k[1]) } }
         Rename-Item -Path $ZabbixSourceConfigFile -NewName $ZabbixConfigPath"zabbix_agentd.win.conf.bak"
         write-host "Installing New Agent..." -foregroundcolor green
         Expand-Archive -Path $ZabbixAgentUNC -DestinationPath $ZabbixInstallLoc -force
         Rename-Item -Path "c:\zabbix\conf\zabbix_agentd.conf" -NewName "zabbix_agentd.win.conf"
         Rename-Item -Path "c:\zabbix\zabbix_agentd.log" -NewName "zabbix_agentd.previous.log"
         }
  }Else{
   #new install
    write-host "Zabbix Agent not detected" -foregroundcolor green
    Expand-Archive -Path $ZabbixAgentUNC -DestinationPath $ZabbixInstallLoc -force
    Rename-Item -Path "c:\zabbix\conf\zabbix_agentd.conf" -NewName "zabbix_agentd.win.conf"
    $ZabbixSourceConfigFile="C:\zabbix\conf\zabbix_agentd.win.conf"
    Get-Content $ZabbixSourceConfigFile | Where { $_ -notmatch '^#.*' -and $_ -notmatch '^\s*$' }| foreach-object -begin {$h=@{}} -process { $k = [regex]::split($_,'='); if(($k[0].CompareTo("") -ne 0) -and ($k[0].StartsWith("#") -ne $True)) { $h.Add($k[0], $k[1]) } }
}
#reassign config file variables
$h.Server = $ZabbixServerIP
$h.ServerActive = $ZabbixServerIP
$h.Hostname = $hostname
$h.TLSAccept = "psk,unencrypted"
$h.TLSConnect="psk"
$h.TLSPSKIdentity=$TLSPSKIdentity
$h.TLSPSKFile = "c:\zabbix\conf\zabbix_agentd.psk"
$h.TLSCipherPSK13="TLS_AES_128_GCM_SHA256"
$h.LogFile = "c:\zabbix\zabbix_agentd.log"
#$h.HostMetadata = "Windows 7bef7d10b1cb7ef6e394b33b52e54fe4f6bd429f8ced"
$h.HostMetadataItem= "system.uname"

write-host "Generating Config..." -foregroundcolor green
$h.GetEnumerator() | ForEach-Object {  $line = ($_.key+"="+$_.value) |add-Content -Path $ZabbixDestConfigFile}
#$ZabbixTLSPSK| Out-File -FilePath $TLSPSKFile
Set-Content -Path $h.TLSPSKFile -value $ZabbixTLSPSK
write-host "Adding Firewall Rules..." -foregroundcolor green
netsh advfirewall firewall add rule name="Open Zabbix agentd port 10050 inbound" dir=in action=allow protocol=TCP localport=10050
netsh advfirewall firewall add rule name="Open Zabbix trapper port 10051 outbound" dir=out action=allow protocol=TCP localport=10051
write-host "Installing Service..." -foregroundcolor green
c:\zabbix\bin\zabbix_agentd.exe -c $ZabbixDestConfigFile -i
write-host "Starting Service..." -foregroundcolor green
net start "Zabbix Agent" 


#$multiLineText = Get-Content "c:\zabbix\zabbix_agentd.log" | Select-Object -Last 15 
#write-host $multilineText
write-host "Displaying last 15 lines of the Zabbix_agentd.log..." -foregroundcolor yellow
Get-Content "c:\zabbix\zabbix_agentd.log" | Select-Object -Last 15 
Write-Host "Press any key to continue..."
$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
#|foreach-object { $_ -replace "`n",'`r`n'}
#Read-MultiLineInputBoxDialog -Message "zabbix_agentd.log" -WindowTitle "Zabbix_agentd.log" -DefaultText $multiLineText

