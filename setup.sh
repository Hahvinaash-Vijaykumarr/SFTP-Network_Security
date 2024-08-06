#!/bin/bash

# Print a message
echo "Starting system setup..."

# Update package lists
sudo apt-get update

# Install some packages
sudo apt-get install -y git curl vim

# Print a success message
echo "System setup completed successfully!"
