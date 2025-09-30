# Downgrade Attack

## Downgrade (NO FALLBACK_SCSV)

For this scenario we consider a client and a server that support TLS 1.2 and 1.1, and we apply the downgrade mechanism but not the FALLBACK_SCSV protection.

Start the server:
```
/usr/local/ssl-1.0.1j/bin/openssl s_server -accept 4433 -cert server.crt -key server.key
```

Start Wireshark on the attacker side:
```
sudo wireshark
```

Start the attacker using the script `downgrade_attacker.py` in 'DOWNGRADE' mode.

Start the client using the script `downgrade_client.py` in 'NO FALLBACK_SCSV' mode.


## Downgrade (FALLBACK_SCSV)

For this case we again consider a client and a server that support TLS 1.2 and 1.1, but we apply the downgrade mechanism and also the FALLBACK_SCSV protection to show how the vulnerability is mitigated.

Start the server:
```
/usr/local/ssl-1.0.1j/bin/openssl s_server -accept 4433 -cert server.crt -key server.key
```

Start Wireshark on the attacker side:
```
sudo wireshark
```

Start the attacker using the script `downgrade_attacker.py` in 'DOWNGRADE' mode.

Start the client using the script `downgrade_client.py` in 'FALLBACK_SCSV' mode.


## Downgrade Sentinel

For this case we only show that TLS 1.3 introduced the sentinel inside the Random field in the ServerHello. 

We want to start a server that accepts TLS 1.3 and TLS 1.2, and a client that uses TLS 1.2 to simulate a downgrade from TLS 1.3. We will not start the attacker, since no traffic analyzer that automatically drops packets when the sentinel is detected has been implemented.

Start the server:
```
openssl s_server -accept 4433 -cert server.crt -key server.key
```

Start the client 
```
openssl s_client -connect <ip_server>:4433 -tls1_2
```


## Results

For the case without FALLBACK_SCSV, we can observe from the attacker’s log that it correctly intercepted the client’s ClientHello, detected TLS 1.2, and sent an error message to the client. From the client’s log we can see that this error message was correctly received and that the client then attempted to establish a new connection by falling back to TLS 1.1. From the server and client logs, or by analyzing the version fields in Wireshark, we can confirm that the negotiation with TLS 1.1 was successful.

For the case with FALLBACK_SCSV, we can again see that the attacker forces the downgrade from TLS 1.2 to TLS 1.1. However, since FALLBACK_SCSV is enabled, we can observe in Wireshark that the field `TLS_FALLBACK_SCSV (0x5600)` was included in the list of Cipher Suites proposed by the client in its ClientHello. Thanks to the presence of this field, we can see from the server log that the server rejected the connection.  
In Wireshark we can also notice that the handshake was not successfully completed, since no ServerHello is sent.

Finally, for the case that uses the downgrade sentinel, we can observe in Wireshark that the ServerHello contains the following bytes in the Random field:  
`44 4F 57 4E 47 52 44 01` ("DOWNGRD\x01").


## Code description

### downgrade_client.py

The client can operate in two modes: without downgrade protection enabled, or with it enabled.  
In the first mode it uses the function `try_openssl`, passing the TLS version to negotiate which will then be used as a parameter for OpenSSL. Inside `try_openssl` the client will start the OpenSSL client service specifying the IP address and port to connect to. In this case the client connects to the attacker because we assume the attacker is positioned as a Man-in-the-Middle (MITM) between the client and the server.  
If the communication fails, the client assumes the server does not accept the proposed version and falls back to the previous TLS version. In this script the client works with TLS 1.2 and falls back to 1.1.

In the second mode, in addition to passing the version to negotiate, it also includes the `-fallback_scsv` parameter which signals to the server that the negotiation attempt is the result of a fallback from a later TLS version.

To be complete, this is the command run by the client:
```
/usr/local/ssl-1.0.1j/bin/openssl s_client -connect <ip_attacker>:4433 -fallback_scsv
```


### downgrade_attacker.py

The attacker’s code presents two selectable options:
- `NO DOWNGRADE`, where the attacker only forwards packets between client and server
- `DOWNGRADE ATTACK`, where the attacker detects if the ClientHello is attempting to negotiate TLS 1.2 and then sends an error message to the client, causing the connection between client and server to be dropped.

The attacker will use the `relay_server` function, which receives the chosen option, the port the attacker should listen on, and the IP address and port of the server to which the client’s packets should be forwarded.  
Thus the attacker opens a socket and listens for incoming connections.  
When the client connects, the attacker receives the data sent by the client and analyzes it with the `parse_clienthello_tls_version` function. Inside that function it checks whether a ClientHello was sent by reading the bytes that make up the packet header.

All TLS 1.2 messages start with a 5-byte Record Layer Header:
- 1 byte ContentType (`0x16` identifies the handshake)
- 2 bytes ProtocolVersion (identifies a legacy/previous version)
- 2 bytes Length (the length of the following payload, i.e., the handshake message)

Next there is the 4-byte Handshake Header which is present only in handshake-type packets:
- 1 byte HandshakeType (`0x01` identifies a ClientHello)
- 3 bytes Length (length of the ClientHello body)

Finally, the function reads the ClientHello body:
- 2 bytes legacy_version (`0x302` is TLS 1.1, `0x0303` is TLS 1.2, `0x0304` is TLS 1.3)

In summary, the function checks the ContentType to know if it’s a handshake, the HandshakeType to recognize a ClientHello, and finally the legacy_version to determine whether TLS 1.2 is being negotiated.

If TLS 1.2 is detected, it sends an error message intended to make the client believe the server doesn’t support TLS 1.2; otherwise it forwards the packets to the server.  
If it receives data from the server, it forwards it directly to the client.