# Triple Handshake Attack

The file `script.py` is a single script and contains the logic to execute the correct code for each of the three hosts, so all three run the same file.

Enable IP forwarding on the attacker:
```
sudo sysctl -w net.ipv4.ip_forward=1
```
Note: this change resets if you reboot the VM.

Run the `script.py` file on all three hosts:
```
sudo venv/bin/python3 script.py
```

## Notes

The attacker executes the following command to carry out the arp spoofing attack:
`arpspoof -i <INTERFACE> -t <IP_GATEWAY> <IP_CLIENT>` 
This is applied to tell:
- the gateway that the attacker is the client and the server
- the client that the attacker is the gateway and the server
- the server that the attacker is the gateway and the client









