#!/bin/bash

# This script is called by socat for each connection.
# Input (iptables args) comes from stdin. Output (structured response) goes to stdout.

# Read the command arguments sent by the client (vpn-whitelister app)
read -r CMD_ARGS

# For debugging on the agent's console (optional):
# echo "Agent Handler: Received CMD_ARGS: [$CMD_ARGS]" >&2

# Create a temporary file to capture stderr
STDERR_FILE=$(mktemp)

# Ensure the temporary file is removed when the script exits or is interrupted
trap 'rm -f "$STDERR_FILE"' EXIT SIGINT SIGTERM

# Execute the iptables command.
# $CMD_ARGS is intentionally not quoted here to allow shell word splitting,
# as the client sends a single string of space-separated arguments.
# stderr is redirected to the temporary file.
STDOUT_OUTPUT=$(sudo iptables $CMD_ARGS 2> "$STDERR_FILE")
EXIT_CODE=$?

# Read the captured stderr
STDERR_OUTPUT=$(cat "$STDERR_FILE")

# Output the results in the structured format expected by the client
echo "EXIT_CODE:$EXIT_CODE"
echo "---STDOUT---"
echo "$STDOUT_OUTPUT"
echo "---STDERR---"
echo "$STDERR_OUTPUT"
echo "---END---" 
