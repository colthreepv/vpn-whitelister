#!/bin/bash

AGENT_PORT="${IPTABLES_AGENT_PORT:-12821}"

echo "iptables-agent: Listening on localhost:$AGENT_PORT" >&2

if ! command -v socat &> /dev/null; then
    echo "Error: socat is not installed. Please install it (e.g., sudo apt-get install socat)." >&2
    exit 1
fi

# This scriptlet will be executed by socat for each incoming connection
# All its output (echo) goes back to the client via socat
HANDLER_SCRIPT=$(cat <<'EOF'
read -r CMD_ARGS

# Execute the command, capturing stdout and stderr separately
STDERR_FILE=$(mktemp)
# Ensure STDERR_FILE is removed on exit, SIGINT, SIGTERM
trap 'rm -f "$STDERR_FILE"' EXIT SIGINT SIGTERM

STDOUT_OUTPUT=$(sudo iptables $CMD_ARGS 2> "$STDERR_FILE")
EXIT_CODE=$?
STDERR_OUTPUT=$(cat "$STDERR_FILE")
# rm -f "$STDERR_FILE" # Handled by trap

echo "EXIT_CODE:$EXIT_CODE"
echo "---STDOUT---"
# Ensure STDOUT_OUTPUT is printed, even if empty, to maintain structure
echo "$STDOUT_OUTPUT"
echo "---STDERR---"
# Ensure STDERR_OUTPUT is printed, even if empty
echo "$STDERR_OUTPUT"
echo "---END---"
EOF
)

# Main loop to listen for connections
# socat will fork a new process for each connection, which then executes bash -c "$HANDLER_SCRIPT"
# reuseaddr allows socat to restart and bind to the port quickly if it crashes/restarts
while true; do
  socat TCP-LISTEN:"$AGENT_PORT",fork,reuseaddr EXEC:"bash -c '${HANDLER_SCRIPT//$'''/'\''}'"
  # If socat fails to bind or has other fatal errors, it might exit.
  # Adding a small sleep can prevent a fast spinning loop in such error cases.
  sleep 1
done 
