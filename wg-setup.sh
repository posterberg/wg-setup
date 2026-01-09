#!/bin/bash

set -euo pipefail

# WireGuard Server and Client Configuration Generator
# Generates keypairs and complete configuration files

SCRIPT_NAME=$(basename "$0")
VERSION="1.0.0"

# Default values
OUTPUT_DIR="wg-configs"
SERVER_INTERFACE="wg0"
ALLOWED_IPS=""
ALLOWED_IPS_SET=false
USE_PSK=false
DNS=""
NUM_CLIENTS=0
SERVER_IP=""
SERVER_PORT=""
SUBNET=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

usage() {
    cat << EOF
${SCRIPT_NAME} v${VERSION} - WireGuard Configuration Generator

USAGE:
    ${SCRIPT_NAME} [OPTIONS] -n <num_clients> -ip <address> -port <port> -subnet <cidr>

REQUIRED OPTIONS (for new configuration):
    -n <number>         Number of client configurations to generate
    -ip <address>       Public IP/hostname clients connect to
    -port <port>        Port the WireGuard server listens on
    -subnet <cidr>      VPN subnet in CIDR notation (e.g., 10.0.0.0/24)
                        Server gets highest usable IP, clients get IPs from low end

ADDING CLIENTS:
    When config exists, only -n and -o are required. Other parameters are
    loaded from the saved configuration (.wg-setup.conf in output directory).

OPTIONAL:
    -psk                Generate pre-shared keys for each client (enhanced security)
    -dns <server>       DNS server(s) for clients
                        Can be specified multiple times: -dns 1.1.1.1 -dns 8.8.8.8
                        Or as comma-separated: -dns "1.1.1.1, 8.8.8.8"
    -allowed-ips <ips>  AllowedIPs for clients (default: 0.0.0.0/0, ::/0 for full tunnel)
                        Can be specified multiple times: -allowed-ips 10.0.0.0/24 -allowed-ips 192.168.1.0/24
                        Or as comma-separated: -allowed-ips "10.0.0.0/24, 192.168.1.0/24"
    -o <directory>      Output directory (default: ${OUTPUT_DIR})
    -h, --help          Show this help message

EXAMPLES:
    # Generate server + 5 clients with PSK
    ${SCRIPT_NAME} -n 5 -ip vpn.example.com -port 51820 -subnet 10.100.0.0/24 -psk

    # With custom DNS and split tunnel
    ${SCRIPT_NAME} -n 3 -ip 203.0.113.1 -port 51820 -subnet 10.0.0.0/24 \\
        -dns "1.1.1.1, 8.8.8.8" -allowed-ips "10.0.0.0/24, 192.168.1.0/24"

    # Add 2 more clients to existing setup (parameters loaded automatically)
    ${SCRIPT_NAME} -n 2 -o wg-configs

OUTPUT STRUCTURE:
    ${OUTPUT_DIR}/
    ├── .wg-setup.conf                        # Saved parameters (for adding clients)
    ├── server/
    │   ├── ${SERVER_INTERFACE}.conf          # Server configuration
    │   ├── privatekey                        # Server private key
    │   └── publickey                         # Server public key
    └── clients/
        ├── client_1.conf                     # Client 1 full config
        ├── client_1_privatekey
        ├── client_1_publickey
        ├── client_1_psk (if -psk)
        └── ...

EOF
    exit 0
}

error() {
    echo -e "${RED}ERROR: $1${NC}" >&2
    exit 1
}

warn() {
    echo -e "${YELLOW}WARNING: $1${NC}" >&2
}

info() {
    echo -e "${GREEN}$1${NC}"
}

# Check if wg command is available
check_dependencies() {
    if ! command -v wg &> /dev/null; then
        error "WireGuard tools (wg) not found. Please install wireguard-tools."
    fi
}

# Parse CIDR subnet and calculate IPs
# Sets: NETWORK_ADDR, NETMASK_BITS, SERVER_VPN_IP, FIRST_CLIENT_IP, MAX_CLIENTS
parse_subnet() {
    local subnet="$1"
    
    # Validate CIDR format
    if [[ ! "$subnet" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]{1,2})$ ]]; then
        error "Invalid subnet format. Use CIDR notation (e.g., 10.0.0.0/24)"
    fi
    
    local ip="${subnet%/*}"
    NETMASK_BITS="${subnet#*/}"
    
    if [[ "$NETMASK_BITS" -lt 8 || "$NETMASK_BITS" -gt 30 ]]; then
        error "Netmask must be between /8 and /30"
    fi
    
    # Parse IP octets
    IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
    
    # Validate octets
    for octet in $o1 $o2 $o3 $o4; do
        if [[ "$octet" -lt 0 || "$octet" -gt 255 ]]; then
            error "Invalid IP octet: $octet"
        fi
    done
    
    # Calculate network address and host count
    local ip_int=$(( (o1 << 24) + (o2 << 16) + (o3 << 8) + o4 ))
    local mask=$(( 0xFFFFFFFF << (32 - NETMASK_BITS) & 0xFFFFFFFF ))
    local network_int=$(( ip_int & mask ))
    local broadcast_int=$(( network_int | (0xFFFFFFFF >> NETMASK_BITS) ))
    
    # Number of usable hosts (excluding network and broadcast)
    local num_hosts=$(( (1 << (32 - NETMASK_BITS)) - 2 ))
    
    if [[ "$num_hosts" -lt 2 ]]; then
        error "Subnet too small. Need at least 2 usable addresses."
    fi
    
    MAX_CLIENTS=$(( num_hosts - 1 ))  # Reserve one for server
    
    # First usable IP (network + 1) - for first client
    local first_ip=$(( network_int + 1 ))
    
    # Last usable IP (broadcast - 1) - for server
    local server_ip_int=$(( broadcast_int - 1 ))
    
    # Convert back to dotted notation
    NETWORK_ADDR="$(( (network_int >> 24) & 255 )).$(( (network_int >> 16) & 255 )).$(( (network_int >> 8) & 255 )).$(( network_int & 255 ))"
    SERVER_VPN_IP="$(( (server_ip_int >> 24) & 255 )).$(( (server_ip_int >> 16) & 255 )).$(( (server_ip_int >> 8) & 255 )).$(( server_ip_int & 255 ))"
    FIRST_CLIENT_IP_INT=$first_ip
}

# Get client IP by index (1-based)
get_client_ip() {
    local index="$1"
    local ip_int=$(( FIRST_CLIENT_IP_INT + index - 1 ))
    echo "$(( (ip_int >> 24) & 255 )).$(( (ip_int >> 16) & 255 )).$(( (ip_int >> 8) & 255 )).$(( ip_int & 255 ))"
}

# Find the next available client number
get_next_client_number() {
    local max=0
    if [[ -d "${OUTPUT_DIR}/clients" ]]; then
        shopt -s nullglob
        for f in "${OUTPUT_DIR}/clients"/client_*.conf; do
            if [[ -f "$f" ]]; then
                local num=$(basename "$f" | sed 's/client_\([0-9]*\)\.conf/\1/')
                if [[ "$num" =~ ^[0-9]+$ && "$num" -gt "$max" ]]; then
                    max=$num
                fi
            fi
        done
        shopt -u nullglob
    fi
    echo $(( max + 1 ))
}

# Generate server configuration
generate_server_config() {
    local server_dir="${OUTPUT_DIR}/server"
    mkdir -p "$server_dir"
    
    info "Generating server keypair..."
    
    # Generate server keys
    wg genkey | tee "${server_dir}/privatekey" | wg pubkey > "${server_dir}/publickey"
    chmod 600 "${server_dir}/privatekey"
    
    local server_privkey=$(cat "${server_dir}/privatekey")
    SERVER_PUBKEY=$(cat "${server_dir}/publickey")
    
    # Create server config
    cat > "${server_dir}/${SERVER_INTERFACE}.conf" << EOF
# WireGuard Server Configuration
# Generated: $(date -Iseconds)

[Interface]
Address = ${SERVER_VPN_IP}/${NETMASK_BITS}
ListenPort = ${SERVER_PORT}
PrivateKey = ${server_privkey}

# Uncomment below for NAT/forwarding (adjust eth0 to your external interface)
# PostUp = iptables -A FORWARD -i %i -j ACCEPT
# PostUp = iptables -A FORWARD -o %i -j ACCEPT
# PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
# PostDown = iptables -D FORWARD -i %i -j ACCEPT
# PostDown = iptables -D FORWARD -o %i -j ACCEPT
# PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

EOF
    
    chmod 600 "${server_dir}/${SERVER_INTERFACE}.conf"
    info "Server configuration created: ${server_dir}/${SERVER_INTERFACE}.conf"
}

# Generate a single client configuration
generate_client_config() {
    local client_num="$1"
    local client_dir="${OUTPUT_DIR}/clients"
    mkdir -p "$client_dir"
    
    local client_name="client_${client_num}"
    local client_ip=$(get_client_ip "$client_num")
    
    info "Generating ${client_name} (${client_ip})..."
    
    # Generate client keys
    wg genkey | tee "${client_dir}/${client_name}_privatekey" | wg pubkey > "${client_dir}/${client_name}_publickey"
    chmod 600 "${client_dir}/${client_name}_privatekey"
    
    local client_privkey=$(cat "${client_dir}/${client_name}_privatekey")
    local client_pubkey=$(cat "${client_dir}/${client_name}_publickey")
    
    # Generate PSK if requested
    local psk=""
    if [[ "$USE_PSK" == true ]]; then
        wg genpsk > "${client_dir}/${client_name}_psk"
        chmod 600 "${client_dir}/${client_name}_psk"
        psk=$(cat "${client_dir}/${client_name}_psk")
    fi
    
    # Build client config with proper formatting
    {
        echo "# WireGuard Client Configuration: ${client_name}"
        echo "# Generated: $(date -Iseconds)"
        echo ""
        echo "[Interface]"
        echo "Address = ${client_ip}/${NETMASK_BITS}"
        echo "PrivateKey = ${client_privkey}"
        [[ -n "$DNS" ]] && echo "DNS = ${DNS}"
        echo ""
        echo "# Uncomment below for NAT/forwarding (adjust eth0 to your external interface)"
        echo "# PostUp = iptables -A FORWARD -i %i -j ACCEPT"
        echo "# PostUp = iptables -A FORWARD -o %i -j ACCEPT"
        echo "# PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE"
        echo "# PostDown = iptables -D FORWARD -i %i -j ACCEPT"
        echo "# PostDown = iptables -D FORWARD -o %i -j ACCEPT"
        echo "# PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE"
        echo ""
        echo "[Peer]"
        echo "PublicKey = ${SERVER_PUBKEY}"
        [[ "$USE_PSK" == true ]] && echo "PresharedKey = ${psk}"
        echo "Endpoint = ${SERVER_IP}:${SERVER_PORT}"
        echo "AllowedIPs = ${ALLOWED_IPS}"
        echo "PersistentKeepalive = 25"
    } > "${client_dir}/${client_name}.conf"
    
    chmod 600 "${client_dir}/${client_name}.conf"
    
    # Add peer to server config
    {
        echo ""
        echo "# ${client_name}"
        echo "[Peer]"
        echo "PublicKey = ${client_pubkey}"
        [[ "$USE_PSK" == true ]] && echo "PresharedKey = ${psk}"
        echo "AllowedIPs = ${client_ip}/32"
    } >> "${OUTPUT_DIR}/server/${SERVER_INTERFACE}.conf"
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                usage
                ;;
            -n)
                [[ -z "${2:-}" ]] && error "-n requires a number"
                NUM_CLIENTS="$2"
                shift 2
                ;;
            -ip)
                [[ -z "${2:-}" ]] && error "-ip requires an address"
                SERVER_IP="$2"
                shift 2
                ;;
            -port)
                [[ -z "${2:-}" ]] && error "-port requires a port number"
                SERVER_PORT="$2"
                shift 2
                ;;
            -subnet)
                [[ -z "${2:-}" ]] && error "-subnet requires CIDR notation"
                SUBNET="$2"
                shift 2
                ;;
            -psk)
                USE_PSK=true
                shift
                ;;
            -dns)
                [[ -z "${2:-}" ]] && error "-dns requires server address(es)"
                if [[ -z "$DNS" ]]; then
                    DNS="$2"
                else
                    DNS="${DNS}, $2"
                fi
                shift 2
                ;;
            -allowed-ips)
                [[ -z "${2:-}" ]] && error "-allowed-ips requires IP ranges"
                ALLOWED_IPS_SET=true
                if [[ -z "$ALLOWED_IPS" ]]; then
                    ALLOWED_IPS="$2"
                else
                    ALLOWED_IPS="${ALLOWED_IPS}, $2"
                fi
                shift 2
                ;;
            -o)
                [[ -z "${2:-}" ]] && error "-o requires a directory path"
                OUTPUT_DIR="$2"
                shift 2
                ;;
            *)
                error "Unknown option: $1. Use -h for help."
                ;;
        esac
    done
}

# Validate required arguments
validate_args() {
    local missing=()
    
    [[ "$NUM_CLIENTS" -eq 0 ]] && missing+=("-n <num_clients>")
    [[ -z "$SERVER_IP" ]] && missing+=("-ip <address>")
    [[ -z "$SERVER_PORT" ]] && missing+=("-port <port>")
    [[ -z "$SUBNET" ]] && missing+=("-subnet <cidr>")
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        error "Missing required arguments: ${missing[*]}\nUse -h for help."
    fi
    
    # Validate port
    if ! [[ "$SERVER_PORT" =~ ^[0-9]+$ ]] || [[ "$SERVER_PORT" -lt 1 || "$SERVER_PORT" -gt 65535 ]]; then
        error "Invalid port number: ${SERVER_PORT}"
    fi
    
    # Validate number of clients
    if ! [[ "$NUM_CLIENTS" =~ ^[0-9]+$ ]] || [[ "$NUM_CLIENTS" -lt 1 ]]; then
        error "Number of clients must be a positive integer"
    fi
}

# Check if existing configuration exists
has_existing_config() {
    [[ -f "${OUTPUT_DIR}/server/publickey" && -f "${OUTPUT_DIR}/server/${SERVER_INTERFACE}.conf" && -f "${OUTPUT_DIR}/.wg-setup.conf" ]]
}

# Save parameters to config file for future use
save_config() {
    cat > "${OUTPUT_DIR}/.wg-setup.conf" << EOF
# WireGuard Setup Configuration
# Generated: $(date -Iseconds)
# Do not edit manually

SERVER_IP="${SERVER_IP}"
SERVER_PORT="${SERVER_PORT}"
SUBNET="${SUBNET}"
USE_PSK="${USE_PSK}"
DNS="${DNS}"
ALLOWED_IPS="${ALLOWED_IPS}"
EOF
}

# Load parameters from existing config file
load_config() {
    local config_file="${OUTPUT_DIR}/.wg-setup.conf"
    if [[ -f "$config_file" ]]; then
        # Source the config file to load variables
        # Only load if not already set by command line
        local saved_server_ip saved_server_port saved_subnet saved_use_psk saved_dns saved_allowed_ips
        
        saved_server_ip=$(grep "^SERVER_IP=" "$config_file" | cut -d'"' -f2)
        saved_server_port=$(grep "^SERVER_PORT=" "$config_file" | cut -d'"' -f2)
        saved_subnet=$(grep "^SUBNET=" "$config_file" | cut -d'"' -f2)
        saved_use_psk=$(grep "^USE_PSK=" "$config_file" | cut -d'"' -f2)
        saved_dns=$(grep "^DNS=" "$config_file" | cut -d'"' -f2)
        saved_allowed_ips=$(grep "^ALLOWED_IPS=" "$config_file" | cut -d'"' -f2)
        
        # Use saved values if not specified on command line
        [[ -z "$SERVER_IP" ]] && SERVER_IP="$saved_server_ip"
        [[ -z "$SERVER_PORT" ]] && SERVER_PORT="$saved_server_port"
        [[ -z "$SUBNET" ]] && SUBNET="$saved_subnet"
        [[ "$USE_PSK" == false && "$saved_use_psk" == "true" ]] && USE_PSK=true
        [[ -z "$DNS" ]] && DNS="$saved_dns"
        [[ "$ALLOWED_IPS_SET" == false ]] && ALLOWED_IPS="$saved_allowed_ips" && ALLOWED_IPS_SET=true
        
        return 0
    fi
    return 1
}

# Main execution
main() {
    parse_args "$@"
    
    # Show help if no arguments
    if [[ $# -eq 0 ]]; then
        usage
    fi
    
    # Try to load existing config (before validation, so we can fill in missing params)
    local config_loaded=false
    if [[ -f "${OUTPUT_DIR}/.wg-setup.conf" ]]; then
        load_config && config_loaded=true
    fi
    
    # Set default for ALLOWED_IPS if not specified and not loaded (full tunnel)
    if [[ "$ALLOWED_IPS_SET" == false ]]; then
        ALLOWED_IPS="0.0.0.0/0, ::/0"
    fi
    
    # Detect mode based on existing configuration
    local mode="new"
    if has_existing_config; then
        mode="add"
    fi
    
    # For add mode with loaded config, only -n is required
    if [[ "$mode" == "add" && "$config_loaded" == true ]]; then
        # Only validate -n for add mode
        if [[ "$NUM_CLIENTS" -eq 0 ]]; then
            error "Missing required argument: -n <num_clients>\nUse -h for help."
        fi
        if ! [[ "$NUM_CLIENTS" =~ ^[0-9]+$ ]] || [[ "$NUM_CLIENTS" -lt 1 ]]; then
            error "Number of clients must be a positive integer"
        fi
    else
        validate_args
    fi
    
    check_dependencies
    parse_subnet "$SUBNET"
    
    echo ""
    echo "================================================"
    echo "  WireGuard Configuration Generator"
    echo "================================================"
    echo ""
    echo "Configuration:"
    echo "  Subnet:        ${SUBNET}"
    echo "  Server VPN IP: ${SERVER_VPN_IP}"
    echo "  Endpoint:      ${SERVER_IP}:${SERVER_PORT}"
    echo "  PSK:           ${USE_PSK}"
    echo "  DNS:           ${DNS:-<not set>}"
    echo "  AllowedIPs:    ${ALLOWED_IPS}"
    echo "  Output:        ${OUTPUT_DIR}/"
    
    if [[ "$mode" == "add" ]]; then
        echo "  Mode:          Adding to existing configuration"
        [[ "$config_loaded" == true ]] && echo "  Config:        Loaded from ${OUTPUT_DIR}/.wg-setup.conf"
        echo ""
        
        SERVER_PUBKEY=$(cat "${OUTPUT_DIR}/server/publickey")
        
        local start_num=$(get_next_client_number)
        local end_num=$(( start_num + NUM_CLIENTS - 1 ))
        
        # Check if we have enough IPs
        if [[ "$end_num" -gt "$MAX_CLIENTS" ]]; then
            error "Not enough IP addresses in subnet. Max clients: ${MAX_CLIENTS}, trying to create client #${end_num}"
        fi
        
        info "Adding clients ${start_num} to ${end_num}..."
        
        for i in $(seq "$start_num" "$end_num"); do
            generate_client_config "$i"
        done
    else
        echo "  Mode:          Creating new configuration"
        echo ""
        
        # Check client count against available IPs
        if [[ "$NUM_CLIENTS" -gt "$MAX_CLIENTS" ]]; then
            error "Requested ${NUM_CLIENTS} clients but subnet only supports ${MAX_CLIENTS}"
        fi
        
        # Backup existing directory if present
        if [[ -d "$OUTPUT_DIR" ]]; then
            warn "Output directory exists but no valid config found. Backing up to ${OUTPUT_DIR}.bak"
            rm -rf "${OUTPUT_DIR}.bak" 2>/dev/null || true
            mv "$OUTPUT_DIR" "${OUTPUT_DIR}.bak"
        fi
        
        mkdir -p "$OUTPUT_DIR"
        
        # Save parameters for future use
        save_config
        
        generate_server_config
        
        info "Generating ${NUM_CLIENTS} client configuration(s)..."
        for i in $(seq 1 "$NUM_CLIENTS"); do
            generate_client_config "$i"
        done
    fi
    
    echo ""
    echo "================================================"
    info "Configuration complete!"
    echo "================================================"
    echo ""
    echo "Files created in: ${OUTPUT_DIR}/"
    echo ""
    echo "Server config:  ${OUTPUT_DIR}/server/${SERVER_INTERFACE}.conf"
    echo "Client configs: ${OUTPUT_DIR}/clients/client_*.conf"
    echo ""
    echo "Next steps:"
    echo "  1. Copy server config to /etc/wireguard/${SERVER_INTERFACE}.conf"
    echo "  2. Enable IP forwarding: sysctl -w net.ipv4.ip_forward=1"
    echo "  3. Start server: wg-quick up ${SERVER_INTERFACE}"
    echo "  4. Distribute client configs securely"
    echo ""
}

main "$@"
