#!/bin/bash

AGENT_PORT="${IPTABLES_AGENT_PORT:-12821}"
HANDLER_SCRIPT_PATH="./agent-handler.sh" # Path to the new handler script

echo "iptables-agent: Listening on localhost:$AGENT_PORT" >&2
echo "iptables-agent: Using handler script: $HANDLER_SCRIPT_PATH" >&2

if ! command -v socat &> /dev/null; then
  echo "Error: socat is not installed. Please install it (e.g., sudo apt-get install socat)." >&2
  exit 1
fi

if [ ! -f "$HANDLER_SCRIPT_PATH" ]; then
  echo "Error: Handler script '$HANDLER_SCRIPT_PATH' not found." >&2
  exit 1
fi

if [ ! -x "$HANDLER_SCRIPT_PATH" ]; then
  echo "Error: Handler script '$HANDLER_SCRIPT_PATH' is not executable. Please run: chmod +x $HANDLER_SCRIPT_PATH" >&2
  exit 1
fi

# Main loop to listen for connections
# socat will fork a new process for each connection, which then executes the handler script.
while true; do
  socat TCP-LISTEN:"$AGENT_PORT",fork,reuseaddr EXEC:"bash $HANDLER_SCRIPT_PATH"
  # If socat fails to bind or has other fatal errors, it might exit.
  # Adding a small sleep can prevent a fast spinning loop in such error cases.
  sleep 1
done 
