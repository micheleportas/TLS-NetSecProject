#!/bin/bash

echo "Genereting self-signed certificate..."
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=server-lab"
echo
echo "Generated files:"
ls -l "server.key" "server.crt"
