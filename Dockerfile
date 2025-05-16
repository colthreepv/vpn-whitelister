FROM oven/bun:1.2.13-debian
WORKDIR /app

# Install iptables and sudo, and configure bun user for passwordless sudo
USER root
RUN apt-get update && \
    apt-get install -y iptables sudo && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    echo "bun ALL=(ALL) NOPASSWD: /usr/sbin/iptables" > /etc/sudoers.d/bun-iptables && \
    chmod 0440 /etc/sudoers.d/bun-iptables

RUN chown -R bun:bun /app # Ensure bun user owns the app directory

# Switch back to bun user if it exists and was intended.
# If your application or iptables commands need root, you might need to stay as root
# or handle sudo within your application.
# For now, we assume the 'bun' user exists in the base image and we switch to it.
# If not, this line might cause issues or you might need to create the user.
USER bun

COPY package.json bun.lock ./
RUN bun install --frozen-lockfile
COPY src ./src
# You might need USER root if iptables requires it and bun user doesn't have sudo
# USER root 
# Or use FORWARD if you are routing through the container
# Ensure iptables is installed in the base image, oven/bun should have it.
CMD ["bun", "run", "src/index.ts"]
