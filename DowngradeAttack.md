# Downgrade Attack

## Introduction

A downgrade attack involves forcing the client to use a lower TLS version than the maximum supported. The reason is that older versions are less secure, for example they may use weak cipher suites or have vulnerabilities present in that version.

This type of vulnerability exists in both TLS 1.3 and TLS 1.2, but a downgrade from TLS 1.3 to 1.2 is less impactful than a downgrade from TLS 1.3/1.2 to TLS 1.1/1.0.  
TLS 1.1 and earlier have known, serious weaknesses:
- Obsolete cryptographic primitives
- No support for AEAD (e.g., AES-GCM)
- Less robust handshake mechanisms, more exposed to message manipulation

TLS 1.2, if configured correctly, is still considered secure (using only modern cipher suites such as AES-GCM or ChaCha20-Poly1305 with SHA-256/384). Therefore, downgrading only reduces robustness (losing mandatory modern ciphers, shorter handshake) but does not immediately expose known vulnerabilities, unlike TLS 1.1/1.0.

The attack is executed as follows:
1. The client sends a ClientHello to the server to negotiate the TLS version.
2. A MITM attacker intercepts the message to generate an error and make the client believe its message was invalid because the server supports only a lower TLS version.
3. The client then attempts to establish a connection using earlier TLS versions.  
Note: those versions must be acceptable to both the server and the client.

It is important to note that the retry handshake is implemented in the client code: we can think of it as `if error then connect_using_another_version`.

The way to mitigate this vulnerability is to use TLS_FALLBACK_SCSV.  
The FALLBACK_SCSV (Signaling Cipher Suite Value) works as follows:
1. It is included in the Cipher Suite field of the ClientHello when the client retries using a lower version.
2. The server notices this field and can reject the connection if its negotiable version is higher than the version negotiated in the client’s retry, because it detects that this is a client retry that could have communicated using a higher version but failed for some reason.

TLS 1.3 introduces an additional default protection mechanism on servers: the downgrade sentinel.
The server inserts a sentinel value in the Random field of the ServerHello if it is forced to negotiate a lower acceptable version. This signals to the client that higher versions are supported and that the current ServerHello has been downgraded. The client then inspects this field.
- If a TLS 1.3 server downgrades to TLS 1.2, the last 8 bytes of Random are: `44 4F 57 4E 47 52 44 01` (`"DOWNGRD\x01"`).
- If a TLS 1.3 server downgrades to TLS 1.1 or lower, the bytes are: `44 4F 57 4E 47 52 44 00` (`"DOWNGRD\x00"`).

In this project, this mechanism is only shown for informational purposes because the OpenSSL client processes the handshake automatically, so there is no way to inspect the Random field before the connection is established. A solution would be to analyze packets before they reach the client and make a decision.

The main difference between TLS_FALLBACK_SCSV and the sentinel is:
- TLS_FALLBACK_SCSV is a cooperative mechanism inserted by the client, meaning it works only if both endpoints (client and server) support it (the client sends it and the server reads it to accept or reject the connection).
- Random sentinel (or “downgrade sentinel”) is inserted by the server and is a unilateral mechanism; the server inserts the sentinel, and the client simply checks its presence to detect a downgrade, making a decision afterward.

The reason for this design is that SCSV had backward compatibility issues: some older servers that did not understand SCSV could not detect downgrades.  
The sentinel adds robustness and universality because only the server needs to implement it; the client just reads the sentinel bytes in the packet. The sentinel eliminates dependency on explicit support from the other side, which SCSV alone could not achieve.


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


## Experiments

### Downgrade (NO FALLBACK_SCSV)

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


### Downgrade (FALLBACK_SCSV)

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


### Downgrade Sentinel

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

