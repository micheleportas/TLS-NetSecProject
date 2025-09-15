# TLS-NetSecProject
Network Security Project about TLS vulnerabilities for the Network Security exam.


This project is meant to run with Linux.



---

'create_certificates.sh' makes the self-signed certificate for the server.  
It generates the private key server.key e the certificate server.crt.

```
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=server-lab"
```

Explaination:
- -x509 → Specifies the self-signed certificate.  
- -newkey rsa:2048 → Creates a RSA key 2048 bits.  
- -keyout server.key → Saves the private key as server.key.  
- -out server.crt → Saves the certificate as server.crt.  
- -days 365 → The certificate is valid for 365 days.  
- -nodes → No passphrase.  
- -subj "/CN=server-lab" → Set the certificate “Common Name”.  


# Installation guide
1) Generate the certificate running the following commands:
```
chmod +x make_simple_cert.sh
./create_certificate.sh
```


2) Create the virtual environment and install the requirements:
```
python -m venv venv
source ./venv/bin/activate
pip install -r requirements.txt
```

---

## Note
tlslite-ng consente di configurare quasi completamente un server TLS, però non ha parametri che mostrino direttamente la versione tls negoziata. Per quello usare Wireshark.  

Il server tlslite-ng usa la negoziazione automatica, accetta TLS 1.0, 1.1 e 1.2, ma non 1.3 (per quello si dovrà per forza usare OpenSSL o altro). Inoltre è il client a far partire la negoziazione, non possiamo forzarlo dal server.

Per usare wireshark su linux devi avviarlo con sudo, perché le interfacce su linux richiedono privilegi sudo. Poi selezionare local interface: lo.  
Il filtro da applicare è tcp.port == 4443.  
Il pacchetto Client Hello contiene la versione massima supportata dal client, mentre il Server Hello indica la versione TLS scelta dal server.
Se apri il pkt Server Hello ed espandi i campi puoi vedere nella voce Version la versione TLS negoziata; in Cypher Suite invece la cipher suite scelta dal server tra quelle proposte dal client.
Per vedere i certificati guarda il pkt Certificate.
NB: su wireshark a prima vista ti dice che è TLS 1.3, ma devi leggere la versione dentro il Server Hello.

Comandi openssl (non provati): 
```
openssl s_client -connect 127.0.0.1:4443

openssl s_client -connect <IP_SERVER>:4443 -CAfile server.crt -tls1_2

openssl s_server -accept 4443 -cert server.crt -key server.key

openssl s_server -accept 4443 -cert server.crt -key server.key -tls1_2

openssl s_server -accept 4443 -cert server.crt -key server.key -tls1_3

openssl s_server -accept 4443 -cert server.crt -key server.key -tls1_2 -debug -msg

openssl s_server -accept 4443 -cert server.crt -key server.key -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256

openssl s_server -accept 4443 -cert server.crt -key server.key -tls1

openssl s_client -connect 192.168.56.101:4443 -tls1_2 -CAfile server.crt
```

