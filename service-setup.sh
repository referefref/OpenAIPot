#!/bin/bash

# This script installs the LLM API Honeypot Gateway

set -e

# Create directories
echo "Creating directories..."
sudo mkdir -p /opt/openaipot
sudo mkdir -p /var/log/openaipot

# Setup user
echo "Setting up service user..."
sudo useradd -r -s /bin/false llmgw || true
sudo chown -R llmgw:llmgw /var/log/openaipot

# Copy files
echo "Copying files..."
sudo cp openaipot /opt/openaipot/
sudo cp config.yaml /opt/openaipot/
sudo chown -R llmgw:llmgw /opt/openaipot

# Setup systemd service
echo "Setting up systemd service..."
sudo cp openaipot.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable openaipot.service

echo "Installation complete!"
echo "You can start the service with: sudo systemctl start openaipot"
echo "Check service status with: sudo systemctl status openaipot"