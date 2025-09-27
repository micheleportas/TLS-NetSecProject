# Heartbleed Attack

## Introduction

This vulnerability is not inherent to TLS itself but rather to its implementation. TLS is a protocol that defines rules for secure communication, but these rules can be implemented in various ways. OpenSSL is a widely used open-source software that provides its own implementation of TLS. The reason for this brief explanation is that even if the TLS protocol itself has no flaws, malicious actors can still exploit vulnerabilities in its implementation. In fact, Heartbleed was a highly publicized bug that made about 17% of public HTTPS servers (roughly half a million) vulnerable.

In this project, we frequently used OpenSSL to simulate and demonstrate vulnerabilities, making it important to address this aspect as well.

Heartbleed is a vulnerability in the Heartbeat implementation present by default in `OpenSSL ≤1.0.1f`. The TLS Heartbeat extension is a feature designed to verify that a TLS connection is still active without repeating the entire handshake process; it essentially functions as a keep-alive mechanism.

Heartbeat messages are identified by the `ContentType` field, which has a value of `0x18` within the TLS message. The messages contain the following fields:
- `HeartbeatMessageType` (1 byte: 1 = request sent by the client; 2 = response sent by the server)
- `payload_length` (2 bytes max, indicating the length of the payload declared by the client)
- `payload` (the actual data sent by the client, which is expected to match the declared length)

Heartbeat Request/Response messages are exchanged after the handshake as separate TLS records. Each request can return up to 64 KB of memory.

The keep-alive mechanism works as follows:
- **Client → Server:** the client sends a heartbeat message with a payload and its size.
- **Server → Client:** the server responds with its own heartbeat message, echoing the same payload received by reading the number of bytes indicated.

The payload can be arbitrary random data and is not intended to carry meaningful information, its purpose is solely to keep the connection alive.

An attacker could exploit this by sending a payload smaller than the declared length. The server, trusting the declared length, would attempt to return all the bytes, reading beyond the actual payload from its internal memory, potentially exposing keys, credentials, cookies, etc.

This vulnerability was fixed in `OpenSSL 1.0.1g`, which disabled the Heartbeat extension by default.


## Experiments

For Heartbleed we can assume only one server and one malicious client (attacker).

Start the OpenSSL server using version 1.0.1f:
```
/usr/local/ssl-1.0.1f/bin/openssl s_server -accept 4433 -cert server.crt -key server.key -tlsextdebug -www
```
Where `-tlsextdebug` displays the TLS extensions, including Heartbeat.
The option `-www` makes the server behave like a simple HTTP server.

With the attacker first start Wireshark:
```
sudo wireshark
```

To check whether the server is vulnerable to Heartbleed we use nmap with the attacker:
```
nmap -p 4433 --script ssl-heartbleed <ip_server> -v
```
The server will respond with output that confirms whether it is vulnerable or not.

To demonstrate this vulnerability, we use a tool called Metasploit.  
The choice of this tool in this case is due to its ability to communicate directly at a low level with the OpenSSL library, constructing valid Heartbeat packets for the server. Essentially, it performs very complex operations, including building TLS records while managing the entire framing (headers, versions, payload length, etc.).
Metasploit also maintains consistency in sequence numbers, correctly handles IVs and encryption state, and preserves the context of the SSL session.

Start Metasploit:
```
msfconsole
```

Then use the `openssl_heartbleed` module and configure it with the correct parameters:
```
use auxiliary/scanner/ssl/openssl_heartbleed
set RHOSTS <ip_server>
set RPORT 4433
set action KEYS
set VERBOSE true
```
The action `KEYS` configures Metasploit to retrieve the server's private key.

Start the scan and exploit with:
```
run
```


### Results

From the nmap log we can read that it detects the Heartbleed vulnerability on the server.

Analyzing what Metasploit does, in Wireshark we can see that the client sends the heartbeat request with a length of 65,535 bytes but actually sends a payload of 19 bytes. The server responds with a heartbeat response echoing the payload, it also returns the extra bytes that the server read from its memory and several separate messages called Encrypted Heartbeat. This happens because TLS imposes a maximum of 164,384 bytes for a plaintext record. The heartbeat message already uses 3 bytes (1 for type and 2 for payload length), so the maximum payload is 16,381 bytes. Those bytes are sent in the first heartbeat message. But the client requested 65,535 bytes, so the vulnerable server tries to satisfy the request by fragmenting the data across multiple TLS records. Metasploit analyzes those fragments and returns them in its shell. Since we set Metasploit to the `KEYS` action, we can observe in its shell that it successfully returned the server’s private key.



