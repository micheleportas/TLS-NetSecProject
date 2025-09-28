#!/bin/bash

# RSA_key_machine_role.pem
openssl genrsa -traditional -out RSA_key_client_client.pem 2048
openssl genrsa -traditional -out RSA_key_attacker_client.pem 2048
openssl genrsa -traditional -out RSA_key_attacker_server.pem 2048
openssl genrsa -traditional -out RSA_key_server_server.pem 2048


openssl req -new -key RSA_key_client_client.pem -out signreq_client_client.csr
openssl x509 -req -days 365 -in signreq_client_client.csr -signkey RSA_key_client_client.pem -out client_certificate.pem

openssl req -new -key RSA_key_attacker_server.pem -out signreq_attacker_server.csr
openssl x509 -req -days 365 -in signreq_attacker_server.csr -signkey RSA_key_attacker_server.pem -out attacker_server_certificate.pem

openssl req -new -key RSA_key_server_server.pem -out signreq_server_server.csr
openssl x509 -req -days 365 -in signreq_server_server.csr -signkey RSA_key_server_server.pem -out server_certificate.pem

# i can't be bothered to try to do this conversion via python, let's do it here and right now!
openssl x509 -outform der -in client_certificate.pem -out client_certificate.der
openssl x509 -outform der -in server_certificate.pem -out server_certificate.der
openssl x509 -outform der -in attacker_server_certificate.pem -out attacker_server_certificate.der