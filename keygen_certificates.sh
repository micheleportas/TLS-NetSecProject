#!/bin/bash

openssl genrsa -traditional -out RSA_key_client_client.pem 2048
openssl req -new -key RSA_key_client_client.pem -out signreq_client_client.csr
openssl x509 -req -days 365 -in signreq_client_client.csr -signkey RSA_key_client_client.pem -out client_certificate.pem

openssl genrsa -traditional -out RSA_key_server_server.pem 2048
openssl req -new -key RSA_key_server_server.pem -out signreq_server_server.csr
openssl x509 -req -days 365 -in signreq_server_server.csr -signkey RSA_key_server_server.pem -out server_certificate.pem
openssl x509 -outform der -in server_certificate.pem -out server_certificate.der

openssl genrsa -traditional -out RSA_key_attacker_server.pem 2048
openssl req -new -key RSA_key_attacker_server.pem -out signreq_attacker_server.csr
openssl x509 -req -days 365 -in signreq_attacker_server.csr -signkey RSA_key_attacker_server.pem -out attacker_server_certificate.pem
openssl x509 -outform der -in attacker_server_certificate.pem -out attacker_server_certificate.der

# in the end we use only: 
# attacker_server_certificate.der
# client_certificate.pem
# RSA_key_attacker_server.pem
# RSA_key_client_client.pem
# RSA_key_server_server.pem
# server_certificate.der
# server_certificate.pem

# remove:
# signreq_client_client.csr
# signreq_server_server.csr
# signreq_attacker_server.csr
# attacker_server_certificate.pem

rm -f -- signreq_client_client.csr signreq_server_server.csr signreq_attacker_server.csr attacker_server_certificate.pem
