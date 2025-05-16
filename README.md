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
*   `IPTABLES_CHAIN`: The `iptables` chain to which the rules will be added/deleted.
    *   Default: `INPUT`
    *   Ensure this chain exists on your system.

## Running the Container

To run the container, you need to provide the required environment variables and map the internal application port (`PORT`) to a host port. You also need to grant the container capabilities to modify `iptables`.

**Example (running the service and mapping internal port 5000 to host port 8080):**

```bash
docker run -d \
  --name vpn-whitelister-app \
  -p 8080:5000 \
  -e SECRET_TOKEN="your_super_secret_token" \
  -e VPN_PORT="1194" \
  -e IPTABLES_CHAIN="INPUT" \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  --restart unless-stopped \
  vpn-whitelister
```

**Explanation of Docker run options:**

*   `-d`: Run in detached mode.
*   `--name vpn-whitelister-app`: Assign a name to the container.
*   `-p 8080:5000`: Map port `8080` on the host to port `5000` (or your configured `PORT`) inside the container.
*   `-e SECRET_TOKEN="..."`: Set the secret token.
*   `-e VPN_PORT="..."`: Set the VPN port.
*   `-e IPTABLES_CHAIN="..."`: (Optional) Set the iptables chain.
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
    (Replace `your_host_port`, `your_secret_token`, `your_vpn_port`)
    ```bash
    docker run -d \
      --name vpn-whitelister-remote \
      -p your_host_port:5000 \
      -e SECRET_TOKEN="your_secret_token" \
      -e VPN_PORT="your_vpn_port" \
      --cap-add=NET_ADMIN \
      --cap-add=NET_RAW \
      --restart unless-stopped \
      vpn-whitelister:latest
    ```

7.  **Test the container on the remote server:**
    (Replace `your_host_port` and `your_secret_token`. This example tests the GET / endpoint.)
    ```bash
    curl "http://localhost:your_host_port/?token=your_secret_token"
    ```
    You should see a JSON response listing whitelisted IPs (likely an empty array initially).

    To test adding an IP, you would typically make a POST request from a machine *outside* the remote server, targeting the remote server's public IP and `your_host_port`.
    ```bash
    # From a different machine (not the remote server itself)
    # Replace <remote_server_ip>, <your_host_port>, <your_secret_token>
    curl -X POST "http://<remote_server_ip>:<your_host_port>/whitelist?token=<your_secret_token>"
    ```

---

This `README.md` provides a starting point. You can expand it further as needed.
