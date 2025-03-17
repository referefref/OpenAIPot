#!/bin/bash

# Setup script for OpenAIPot with Docker Compose

set -e

# Create necessary directories
mkdir -p logs

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Check if config.yaml exists, create from template if not
if [ ! -f config.yaml ]; then
    echo "Config file not found. Creating from template..."
    cp config.yaml.example config.yaml
    echo "Please edit config.yaml to add your API keys and customize settings."
    exit 0
fi

# Build and start the containers
echo "Building and starting OpenAIPot..."
docker-compose up -d

# Check if the container is running
if docker-compose ps | grep -q "openaipot"; then
    echo "OpenAIPot is now running!"
    echo "You can check logs with: docker-compose logs -f"
    echo "The service is available at: http://localhost:8080"
else
    echo "Failed to start OpenAIPot. Please check the logs: docker-compose logs"
    exit 1
fi