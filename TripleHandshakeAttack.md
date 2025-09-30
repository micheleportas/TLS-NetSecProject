# Triple Handshake Attack

The file `script.py` is a single script and contains the logic to execute the correct code for each of the three hosts, so all three run the same file.

Enable IP forwarding on the attacker:
```
sudo sysctl -w net.ipv4.ip_forward=1
```
Note: this change resets if you reboot the VM.

Run Wireshark on the attacker machine:
```
sudo wireshark
```

Run the `script.py` file on all three hosts:
```
sudo venv/bin/python3 script.py
```


## Results

The server waits for the client to connect and performs its side of the handshake. It then receives messages/commands (which it displays on screen). It simulates a failed renegotiation by tearing down the connection because the attacker does not have the client's certificate. It then waits for the real client to reconnect.

The client simply connects to the server and starts the handshake. It then disconnects and attempts to reconnect using the old session in order to simulate a session resumption.

The attacker performs ARP spoofing to position themselves as a MITM between the client and the server. They analyze the packet data, modify it, and then retransmit it. The behavior of the client, server, and attacker can be seen in the logs of the three hosts.

In Wireshark, you can observe the complete absence of TLS Encrypted Alert records and that the retransmitted packets are indeed different from how they should have been originally because of the attacker's modifications. For example, you can see the certificates that were transmitted.
If the resumption successfully completes, the client and server see different handshake (and hence see different client_finished and server_finished) messages.


## Notes

The tlslite-ng library does not provide a way to configure and simulate a renegotiation, so it was simulated at the application level in the code.

The attacker executes the following command to carry out the arp spoofing attack:
`arpspoof -i <INTERFACE> -t <IP_GATEWAY> <IP_CLIENT>` 
This is applied to tell:
- the gateway that the attacker is the client and the server
- the client that the attacker is the gateway and the server
- the server that the attacker is the gateway and the client





