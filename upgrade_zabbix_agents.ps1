
$Domain=$Env:USERDOMAIN
$ZabbixServiceName = "Zabbix Agent"
$ZabbixVersion = "6.4.11"
$ZabbixAgentLocalArchive="c:\alxsw\zabbix_agent-6.4.11-windows-amd64-openssl.zip"
$ZabbixAgentUri = "https://cdn.zabbix.com/zabbix/binaries/stable/6.4/6.4.11/zabbix_agent-6.4.11-windows-amd64-openssl.zip"
$ZabbixInstallLoc = "c:\zabbix\"
$ZabbixConfigPath = "c:\zabbix\conf\"
$ZabbixDestConfigFile="c:\zabbix\conf\zabbix_agentd.win.conf"
$TLSPSKFile = "c:\zabbix\conf\zabbix_agentd.psk"

function Get-RandomHexString {
[int] $BitLength = 512
    
    $byteLength = $BitLength / 8
    $bytes = [byte[]]::new($byteLength)

    $rngCryptoProvider = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
    $rngCryptoProvider.GetBytes($bytes)

    # Properly dispose the crypto service provider
    $rngCryptoProvider.Dispose()

    # Convert bytes to hex string
    $hexString = ([BitConverter]::ToString($bytes) -replace '-').ToLower()
    return $hexString
 }
 $TLSPSK=Get-RandomHexString 

$hostname=$env:computername.ToLower()
$TLSPSKIdentity=$env:HostIP = (
    Get-NetIPConfiguration |
    Where-Object {
        $_.IPv4DefaultGateway -ne $null -and
        $_.NetAdapter.Status -ne "Disconnected"
       }
).IPv4Address.IPAddress


switch($Domain){
    "B1" {$ZabbixServerIP="10.52.5.113";$ZabbixAgentUNC="\\b1terrace1\alxsw$\zabbix_agent-"+$ZabbixVersion+"-windows-amd64-openssl.zip";break}
    "B2" {$ZabbixServerIP="10.52.5.113";$ZabbixAgentUNC="\\b2terrace1\alxsw$\zabbix_agent-"+$ZabbixVersion+"-windows-amd64-openssl.zip";break}
    "P7" {$ZabbixServerIP="10.180.159.187";$ZabbixAgentUNC="\\p7adm1\c$\alxsw\zabbix_agent-"+$ZabbixVersion+"-windows-amd64-openssl.zip";break}
    "P2" {$ZabbixServerIP="10.216.234.141";$ZabbixAgentUNC="\\p2adm4\alxsw$\zabbix_agent-"+$ZabbixVersion+"-windows-amd64-openssl.zip";break}
    "A6" {$ZabbixServerIP="10.106.1.10";$ZabbixAgentUNC="\\a6terrace2\alxsw$\zabbix_agent-"+$ZabbixVersion+"-windows-amd64-openssl.zip";break}
    "P4" {$ZabbixServerIP="10.216.234.141";$ZabbixAgentUNC="\\a2terrace1\c$\alxsw\zabbix_agent-"+$ZabbixVersion+"-windows-amd64-openssl.zip";break}
    "A2" {$ZabbixServerIP="10.6.5.9";$ZabbixAgentUNC="\\a2terrace1\alxsw$\zabbix_agent-"+$ZabbixVersion+"-windows-amd64-openssl.zip";break}
    default {$ZabbixServerIP="10.6.5.9";$ZabbixAgentUNC="\\a2terrace1\alxsw$\zabbix_agent-"+$ZabbixVersion+"-windows-amd64-openssl.zip";break}
}

$h=@{}
If (Get-Service $ZabbixServiceName -ErrorAction SilentlyContinue) {
        Stop-Service $ZabbixServiceName
        #get Zabbix config from service entry
        $ZabbixSourceConfigFile=((gwmi win32_service|?{$_.name -eq "Zabbix Agent"}|select pathname).pathname.split(" ")[2]  -replace '"', "")
        #delete zabbix agent service
        c:\zabbix\bin\zabbix_agentd.exe -d
        #assign all non-commented items in config file to variable '$h'
        Get-Content $ZabbixSourceConfigFile | Where { $_ -notmatch '^#.*' -and $_ -notmatch '^\s*$' }| foreach-object -begin {$h=@{}} -process { $k = [regex]::split($_,'='); if(($k[0].CompareTo("") -ne 0) -and ($k[0].StartsWith("#") -ne $True)) { $h.Add($k[0], $k[1]) } }
        Rename-Item -Path $ZabbixSourceConfigFile -NewName $ZabbixConfigPath"zabbix_agentd.win.conf.old"
        Expand-Archive -Path $ZabbixAgentUNC -DestinationPath $ZabbixInstallLoc -force
        Rename-Item -Path "c:\zabbix\conf\zabbix_agentd.conf" -NewName "zabbix_agentd.win.conf"
        Rename-Item -Path "c:\zabbix\zabbix_agentd.log" -NewName "zabbix_agentd.previous.log"
 }Else{
   #new install
    Expand-Archive -Path $ZabbixAgentUNC -DestinationPath $ZabbixInstallLoc -force
    Rename-Item -Path "c:\zabbix\conf\zabbix_agentd.conf" -NewName "zabbix_agentd.win.conf"
    $ZabbixSourceConfigFile="C:\zabbix\conf\zabbix_agentd.win.conf"
    Get-Content $ZabbixSourceConfigFile | Where { $_ -notmatch '^#.*' -and $_ -notmatch '^\s*$' }| foreach-object -begin {$h=@{}} -process { $k = [regex]::split($_,'='); if(($k[0].CompareTo("") -ne 0) -and ($k[0].StartsWith("#") -ne $True)) { $h.Add($k[0], $k[1]) } }
    #$ZabbixTLSPSK| Add-Content -Path $h.TLSPSKFile -value $TLSPSK
    #$var = Read-Host
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

$h.GetEnumerator() | ForEach-Object {  $line = ($_.key+"="+$_.value) |add-Content -Path $ZabbixDestConfigFile}
netsh advfirewall firewall add rule name="Open Zabbix agentd port 10050 inbound" dir=in action=allow protocol=TCP localport=10050
netsh advfirewall firewall add rule name="Open Zabbix trapper port 10051 outbound" dir=out action=allow protocol=TCP localport=10051

c:\zabbix\bin\zabbix_agentd.exe -c $ZabbixDestConfigFile -i
net start "Zabbix Agent" 
Get-Content "c:\zabbix\zabbix_agentd.log" | Select-Object -Last 15

