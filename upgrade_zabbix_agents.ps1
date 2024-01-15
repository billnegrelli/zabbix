
$Domain=$Env:USERDOMAIN
$ZabbixServiceName = "Zabbix Agent"
$ZabbixVersion = "6.4.10"
$ZabbixAgentLocalArchive="c:\alxsw\zabbix_agent-6.4.10-windows-amd64-openssl.zip"
$ZabbixAgentUri = "https://cdn.zabbix.com/zabbix/binaries/stable/6.4/6.4.10/zabbix_agent-6.4.10-windows-amd64-openssl.zip"
$ZabbixAgentUNC = "\\a2terrace1\alxsw$\zabbix_agent-6.4.10-windows-amd64-openssl.zip"
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
$TLSPSKIdentity=(Test-Connection -ComputerName $env:ComputerName -Count 1).IPV4Address.IPAddressToString
if (-not(Test-Path -Path $TLSPSKFile -PathType Leaf)) {
     try {add-Content -Path $TLSPSKFile -value  }
     catch {throw $_.Exception.Message}
    }else {$TLSPSK=(Get-Content $TLSPSKFile)}


#\\a2terrace1\c$\alxsw\zabbix_agent-6.4.9-windows-amd64-openssl.zip"
#\\p2adm4\alxsw$\zabbix_agent-6.4.10-windows-amd64-openssl.zip
#\\p4adm5\alxsw$\zabbix_agent-6.4.10-windows-amd64-openssl.zip
#\\p7adm1\c$\alxsw\zabbix_agent-6.4.9-windows-amd64-openssl.zip

switch($Domain){
    "P7" {$ZabbixServerIP="10.180.159.187";$ZabbixAgentUNC="\\p7adm1\c$\alxsw\zabbix_agent-$ZabbixVersion-windows-amd64-openssl.zip";break}
    "P2" {$ZabbixServerIP="10.216.234.141";$ZabbixAgentUNC="\\p2adm4\alxsw$\zabbix_agent-6.4.10-windows-amd64-openssl.zip";break}
    "A6" {$ZabbixServerIP="10.106.1.10";$ZabbixAgentUNC="\\p2adm4\alxsw$\zabbix_agent-6.4.10-windows-amd64-openssl.zip";break}
    "P4" {$ZabbixServerIP="10.216.234.141";$ZabbixAgentUNC="\\a2terrace1\c$\alxsw\zabbix_agent-6.4.10-windows-amd64-openssl.zip";break}
    "A2" {$ZabbixServerIP="10.6.5.9";$ZabbixAgentUNC="\\a2terrace1\alxsw$\zabbix_agent-6.4.10-windows-amd64-openssl.zip";break}
    "A2G1" {$ZabbixServerIP="10.6.5.9";$ZabbixAgentUNC="\\a2terrace1\alxsw$\zabbix_agent-6.4.10-windows-amd64-openssl.zip";break}
    default {$ZabbixServerIP="10.6.5.9";$ZabbixAgentUNC="\\a2terrace1\alxsw$\zabbix_agent-6.4.10-windows-amd64-openssl.zip";break}
}


If (Get-Service $ZabbixServiceName -ErrorAction SilentlyContinue) {
        If ((Get-Service $ZabbixServiceName).Status -eq 'Running') {
            Stop-Service $ZabbixServiceName
            #get Zabbix config from service entry
            $ZabbixSourceConfigFile=((gwmi win32_service|?{$_.name -eq "Zabbix Agent"}|select pathname).pathname.split(" ")[2]  -replace '"', "")
            #delete zabbix agent service
            c:\zabbix\bin\zabbix_agentd.exe -d
            if ($ZabbixSourceConfigFile -eq $ZabbixDestConfigFile) {
                Copy-Item $ZabbixSourceConfigFile -Destination $ZabbixConfigPath"zabbix_agentd.tmp"
                $ZabbixSourceConfigFile=$ZabbixConfigPath"zabbix_agentd.tmp"
            }
            #assign all non-commented items in config file to variable '$h'
            Get-Content $ZabbixSourceConfigFile | Where { $_ -notmatch '^#.*' -and $_ -notmatch '^\s*$' }| foreach-object -begin {$h=@{}} -process { $k = [regex]::split($_,'='); if(($k[0].CompareTo("") -ne 0) -and ($k[0].StartsWith("#") -ne $True)) { $h.Add($k[0], $k[1]) } }
            Expand-Archive -Path $ZabbixAgentUNC -DestinationPath $ZabbixInstallLoc -force
            }Else{
            $ZabbixSourceConfigFile="C:\zabbix\conf\zabbix_agentd.conf"
            Get-Content $ZabbixSourceConfigFile | Where { $_ -notmatch '^#.*' -and $_ -notmatch '^\s*$' }| foreach-object -begin {$h=@{}} -process { $k = [regex]::split($_,'='); if(($k[0].CompareTo("") -ne 0) -and ($k[0].StartsWith("#") -ne $True)) { $h.Add($k[0], $k[1]) } }
            Expand-Archive -Path $ZabbixAgentUNC -DestinationPath $ZabbixInstallLoc -force
        }
    }Else{
    #new install
    Expand-Archive -Path $ZabbixAgentUNC -DestinationPath $ZabbixInstallLoc -force
    $ZabbixSourceConfigFile="C:\zabbix\conf\zabbix_agentd.conf"
    #Get-Content $ZabbixSourceConfigFile | Where { $_ -notmatch '^#.*' -and $_ -notmatch '^\s*$' }| foreach-object -begin {$h=@{}} -process { $k = [regex]::split($_,'='); if(($k[0].CompareTo("") -ne 0) -and ($k[0].StartsWith("#") -ne $True)) { $h.Add($k[0], $k[1]) } }
    $h=@{}
    $ZabbixTLSPSK| Add-Content -Path $h.TLSPSKFile -value $TLSPSK
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

