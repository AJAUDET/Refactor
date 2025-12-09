#!/bin/bash

# Ensure Docker daemon directory exists
mkdir -p /var/run/docker
mkdir -p /var/lib/docker

# Start Docker daemon in background
dockerd &

# Wait a few seconds for Docker socket to appear
sleep 3

# Ensure docker group exists and socket has correct permissions
groupadd docker 2>/dev/null || true
chown root:docker /var/run/docker.sock 2>/dev/null || true
chmod 660 /var/run/docker.sock 2>/dev/null || true

# Make sure SSH privilege separation directory exists
mkdir -p /run/sshd
chmod 755 /run/sshd

# Start SSH server in foreground
exec /usr/sbin/sshd -D