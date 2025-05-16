# VPN IP Whitelister

A service to dynamically whitelist client IPs in `iptables` for VPN access via an HTTP API.

## Prerequisites

*   Docker installed and running.
*   The `iptables-agent.sh` script running on the Docker host with `sudo` access for `iptables` commands.
*   The main `vpn-whitelister` application container does not require special privileges.

## Build the Image

```bash
docker build -t vpn-whitelister .
```

## Required Environment Variables

*   `SECRET_TOKEN`: **(Required)** Authentication token for API requests.
*   `VPN_PORT`: **(Required)** VPN destination port for `iptables` rules (e.g., `1194`).

## Optional Environment Variables (Defaults Provided)

*   `PORT`: Service listening port (default: `5000`).
*   `INTERNAL_PORT`: VPN server internal port (default: `8443`).
*   `EXTERNAL_PORT`: Public VPN port for whitelisting (default: `41872`).
*   `IPTABLES_NAT_CHAIN`: Custom NAT chain name (default: `VPN-NAT`).
*   `IPTABLES_FILTER_CHAIN`: Custom filter chain name (default: `VPN-FILTER`).

## Run the Container

```bash
docker run -d \
  --name vpn-whitelister-app \
  -p 8080:5000 \
  -e SECRET_TOKEN="your_secret_token" \
  -e VPN_PORT="1194" \
  -e INTERNAL_PORT="8443" \
  -e EXTERNAL_PORT="41872" \
  --restart unless-stopped \
  vpn-whitelister
```

## API Endpoints

Requires `?token=YOUR_SECRET_TOKEN` query parameter.

*   `GET /`: Health check.
*   `GET /list`: Lists whitelisted IPs.
*   `POST /whitelist`: Adds your public IP to the whitelist.
*   `POST /cleanup`: Removes all rules added by this service.
