### GENERAL INFO
This is an implementation of an TLS 1.1 triple handshake attack, enacted on the tlslite-ng library.

You can see the key_points file to see some "soft knowledge" gained from this experiment.

The keygen_for_testing.sh file was used to generate the key material needed for this project... see the last paragraph of 
the "HOW TO RUN THE PROJECT" section for a warning.

The script.py file is unique and implements the needed logic for the demo of each Docker container.

### HOW TO RUN THE PROJECT
To run this project just first create the docker images with the dockerfile_base_system file.

it will build the ubuntu container with all the dependencies useful to all three
containers (client, attacker and server), especially those needed to sniff and arp poison (attacker)!


Then, run the compose.yaml file for the demo. It will spawn three containers, first that of the attacker, 
which will begin with arppoisoning the virtual docker bridge... you can even look at packets if you have Wireshark!

The other two containers's Python scripts will sleep for a while (the client will ping continuously just to see if the
connection is working and so you can see how packets gets redirected through the attacker's machine), to let the arppoisoning have effect on their arp caches,
next, they will begin their communications (and get their packets mangled by the attacker)...

The full attack simulation should take about 27 seconds, at which point you'll see that the session resumption completes successfully...
at about the 11 seconds mark you can instead see the first TLS handshake and how it gets mangled.

The attack deals with a lot of TLS 1.1 and its library implementation's intricacies,
so you need to manage higher's versions changes if you want it to work (E.G. you'll have to deal with TCP length fields
since TLS 1.2 ADDS some cipher suites to the list of supported cipher suites, and since this attack is specialized on decrypting
and encrypting only RSA PKCS v1.5 with AES256 CBC TLS message flow)

I suggest NOT to create a new share of certificates and private keys, as the attack relies a lot on the fact that the
attacker's certificate must be shorter than the server's one, to not deal with TCP length fields and padding.