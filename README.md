# wg-setup
WireGuard Server and Client Configuration Generator.
It generates keypairs and complete configuration files.


## USAGE:
```bash
wg-setup.sh [OPTIONS] -n <num_clients> -ip <address> -port <port> -subnet <cidr>
```

### REQUIRED OPTIONS:
```
    -n <number>         Number of client configurations to generate
                        - If no existing config: creates server + n clients
                        - If config exists: adds n more clients to existing setup
    -ip <address>       Public IP/hostname clients connect to
    -port <port>        Port the WireGuard server listens on
    -subnet <cidr>      VPN subnet in CIDR notation (e.g., 10.0.0.0/24)
                        Server gets highest usable IP, clients get IPs from low end
```

### OPTIONAL:
```
    -psk                Generate pre-shared keys for each client (enhanced security)
    -dns <server>       DNS server(s) for clients
                        Can be specified multiple times: -dns 1.1.1.1 -dns 8.8.8.8
                        Or as comma-separated: -dns "1.1.1.1, 8.8.8.8"
    -allowed-ips <ips>  AllowedIPs for clients (default: 0.0.0.0/0, ::/0 for full tunnel)
                        Can be specified multiple times: -allowed-ips 10.0.0.0/24 -allowed-ips 192.168.1.0/24
                        Or as comma-separated: -allowed-ips "10.0.0.0/24, 192.168.1.0/24"
    -o <directory>      Output directory (default: wg-configs)
    -h, --help          Show this help message
```

## EXAMPLES:
### Generate server and five clients with PSK
```bash
wg-setup.sh -n 5 -ip vpn.example.com -port 51820 -subnet 10.100.0.0/24 -psk
```

### Generate server and three clients with custom DNS and split tunnel
```bash
wg-setup.sh -n 3 -ip 203.0.113.1 -port 51820 -subnet 10.0.0.0/24 \
        -dns "1.1.1.1, 8.8.8.8" -allowed-ips "10.0.0.0/24, 192.168.1.0/24"
```

### Add two more clients to existing setup (parameters loaded automatically)
```bash
wg-setup.sh -n 2 -o wg-configs
```


## OUTPUT STRUCTURE:
```
    wg-configs/
    ├── server/
    │   ├── wg0.conf                      # Server configuration
    │   ├── privatekey                    # Server private key
    │   └── publickey                     # Server public key
    └── clients/
        ├── client_1.conf                 # Client 1 full config
        ├── client_1_privatekey           # Client 1 private key
        ├── client_1_publickey            # Client 1 public key
        ├── client_1_psk (if -psk)        # Client 1 PSK
        └── ...
```
