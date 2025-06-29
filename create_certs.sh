#!/bin/bash

# Set up directories
mkdir -p myCA
cd myCA

# Step 1: Create CA key and certificate
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.crt -subj "/CN=My Custom CA"

# Step 2: Create server key and CSR
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=localhost"

# Step 3: Sign the server certificate with the CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256

# Step 4: Clean up
rm server.csr ca.srl

echo "CA and server certificates created in $(pwd)"
