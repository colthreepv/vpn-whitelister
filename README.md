# VPN IP Whitelister

A simple service to dynamically whitelist client IPs in `iptables` for VPN access, managed via an HTTP API and secured by a secret token.

## Prerequisites

*   Docker installed and running.
*   A Linux host system (or a Docker environment that can manage `iptables`, typically requiring `--cap-add=NET_ADMIN --cap-add=NET_RAW` or similar for the container).

## Building the Docker Image

1.  Clone this repository (if you haven't already).
2.  Navigate to the project's root directory (where the `Dockerfile` is located).
3.  Build the Docker image:

    ```bash
    docker build -t vpn-whitelister .
    ```
    (You can replace `vpn-whitelister` with your preferred image name).

## Environment Variables

The following environment variables are used to configure the application:

### Required:

*   `SECRET_TOKEN`: **(Required)** A secret string used to authenticate API requests. Choose a strong, unique token.
*   `VPN_PORT`: **(Required)** The VPN destination port number that `iptables` rules will be created for (e.g., `1194` for OpenVPN).

### Optional:

*   `PORT`: The internal port on which the whitelister service will listen inside the container.
    *   Default: `5000`
*   `INTERNAL_PORT`: The internal port where the VPN service (that traffic is forwarded to) is listening.
    *   Default: `8443`
*   `EXTERNAL_PORT`: The external port exposed to the internet for VPN connections, which will be whitelisted.
    *   Default: `41872`
*   `IPTABLES_NAT_CHAIN`: The name for the custom `iptables` NAT chain.
    *   Default: `VPN-NAT`
*   `IPTABLES_FILTER_CHAIN`: The name for the custom `iptables` filter chain used for whitelisting.
    *   Default: `VPN-FILTER`

## Chain Management

This service creates and manages two dedicated `iptables` chains:
*   **`IPTABLES_NAT_CHAIN` (default: `VPN-NAT`):** Used in the `nat` table for port forwarding rules (DNAT/REDIRECT). It redirects traffic from `EXTERNAL_PORT` to `INTERNAL_PORT`.
*   **`IPTABLES_FILTER_CHAIN` (default: `VPN-FILTER`):** Used in the `filter` table for managing whitelist access rules to the `EXTERNAL_PORT`.

These chains are automatically created, linked to `PREROUTING` (for NAT) and `INPUT` (for filter) respectively, and cleaned up when the service stops gracefully.

## Running the Container

To run the container, you need to provide the required environment variables and map the internal application port (`PORT`) to a host port for API access. You also need to map the `EXTERNAL_PORT` for VPN traffic. Crucially, grant the container capabilities to modify `iptables`.

**Example (running the service, mapping API port 5000 to host 8080, and exposing external VPN port 41872):**

```bash
docker run -d \
  --name vpn-whitelister-app \
  -p 8080:5000 \                  # API port mapping (host:container)
  -e SECRET_TOKEN="your_super_secret_token" \
  -e INTERNAL_PORT="8443" \       # Port your VPN server listens on internally
  -e EXTERNAL_PORT="41872" \     # Public port for VPN
  -e IPTABLES_NAT_CHAIN="VPN-NAT" \         # Optional: custom NAT chain name
  -e IPTABLES_FILTER_CHAIN="VPN-FILTER" \   # Optional: custom filter chain name
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  --restart unless-stopped \
  vpn-whitelister
```

**Explanation of Docker run options:**

*   `-d`: Run in detached mode.
*   `--name vpn-whitelister-app`: Assign a name to the container.
*   `-p 8080:5000`: Map API port `8080` on the host to port `5000` (or your configured `PORT`) inside the container.
*   `-e SECRET_TOKEN="..."`: Set the secret token.
*   `-e INTERNAL_PORT="..."`: Set the internal VPN service port.
*   `-e EXTERNAL_PORT="..."`: Set the public VPN port.
*   `-e IPTABLES_NAT_CHAIN="..."`: (Optional) Set the custom NAT chain name.
*   `-e IPTABLES_FILTER_CHAIN="..."`: (Optional) Set the custom filter chain name.
*   `--cap-add=NET_ADMIN --cap-add=NET_RAW`: **Crucial for `iptables`**. Grants the container necessary privileges to manage network rules.
*   `--restart unless-stopped`: Policy to restart the container if it stops.
*   `vpn-whitelister`: The name of the image you built.

## Exposed Port

The application inside the container listens on the port specified by the `PORT` environment variable (defaulting to `5000`). You need to map this internal port to a port on your Docker host using the `-p` flag when running the container (e.g., `-p <host_port>:<container_port>`).

## API Endpoints

The service provides the following API endpoints. All endpoints require authentication via a `token` query parameter (`?token=YOUR_SECRET_TOKEN`).

*   **`GET /`**:
    *   Lists all currently whitelisted IP addresses for the configured `VPN_PORT`.
    *   Returns a JSON array of IPs.

*   **`POST /whitelist`**:
    *   Adds the public IP address of the client making the request to the `iptables` whitelist for the `VPN_PORT`.
    *   Returns a JSON response indicating success or failure.

*   **`POST /cleanup`**:
    *   Removes *all* `iptables` rules previously added by this service for the configured `VPN_PORT` and `IPTABLES_CHAIN`.
    *   Returns a JSON response indicating success and the number of rules removed.

## Remote Deployment and Testing (Example Workflow)

This section outlines a general workflow. **Please replace placeholders with your actual values.**

**Prerequisites for Remote Server:**
*   Docker installed and running on the remote server.
*   SSH access to the remote server.

**Steps:**

1.  **Build the image locally:**
    ```bash
    docker build -t vpn-whitelister:latest .
    ```

2.  **Save the image to a tarball:**
    ```bash
    docker save vpn-whitelister:latest > vpn-whitelister.tar
    ```

3.  **Transfer the tarball to the remote server:**
    (Replace `user@remote-host` and path)
    ```bash
    scp vpn-whitelister.tar user@remote-host:/path/to/destination/vpn-whitelister.tar
    ```

4.  **SSH into the remote server:**
    ```bash
    ssh user@remote-host
    ```

5.  **On the remote server, load the image:**
    ```bash
    docker load < /path/to/destination/vpn-whitelister.tar
    ```

6.  **On the remote server, run the container (adjust parameters as needed):**
    (Replace `your_host_api_port`, `your_secret_token`, `your_external_vpn_port`, `your_internal_vpn_port`)
    ```bash
    docker run -d \
      --name vpn-whitelister-remote \
      -p your_host_api_port:5000 \        # API port
      -p your_external_vpn_port:your_external_vpn_port/tcp \ # External VPN port - adjust protocol
      -e SECRET_TOKEN="your_secret_token" \
      -e INTERNAL_PORT="your_internal_vpn_port" \
      -e EXTERNAL_PORT="your_external_vpn_port" \
      # -e IPTABLES_NAT_CHAIN="VPN-NAT" \        # Optional
      # -e IPTABLES_FILTER_CHAIN="VPN-FILTER" \  # Optional
      --cap-add=NET_ADMIN \
      --cap-add=NET_RAW \
      --restart unless-stopped \
      vpn-whitelister:latest
    ```

7.  Test the container on the remote server:
    (Replace `your_host_api_port` and `your_secret_token`. This example tests the GET / endpoint.)
    ```bash
    curl "http://localhost:your_host_api_port/?token=your_secret_token"
    ```
    You should see a JSON response listing whitelisted IPs (likely an empty array initially).

    To test adding an IP, you would typically make a POST request from a machine *outside* the remote server, targeting the remote server's public IP and `your_host_api_port`.
    ```bash
    # From a different machine (not the remote server itself)
    # Replace <remote_server_ip>, <your_host_api_port>, <your_secret_token>
    curl -X POST "http://<remote_server_ip>:<your_host_api_port>/whitelist?token=<your_secret_token>"
    ```

---

This `README.md` provides a starting point. You can expand it further as needed.
