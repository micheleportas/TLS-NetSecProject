# Vulnerabilità nel protocollo TLS e nelle sue implementazioni

Network Security Project about TLS vulnerabilities for the Network Security exam.

This project is tested on Linux.

## Strumenti

- Hypervisor VM usato: VMware Workstation 17 Pro 17.6.1 build-24319023
- Distro Linux usata: Linux Mint 22.1 64-bit

3 VM linux distinte sulla stessa subnet:
- Server: 192.168.91.xxx
- Client: 192.168.91.xxx
- Attacker: 192.168.91.xxx

- Porta usata per la comunicazione con il server: 4433

* Wireshark Version 4.2.2 per analizzare il traffico TLS e la struttura dei pacchetti.

Tools di simulazione TLS: OpenSSL.
OpenSSL è una libreria open-source che fornisce strumenti e implementazioni per crittografia, TLS/SSL e gestione di certificati digitali.
Versioni di OpenSSL usate:
* OpenSSL 3.0.13 (preinstallato su Linux). Questa versione supporta nativamente solo TLS 1.3 e TLS 1.2.
* OpenSSL 1.0.1f, usata per simulare l'heartbleed. Questa versione supporta TLS 1.2, TLS 1.1 e TLS 1.0.
* OpenSSL 1.0.1j, usata per simulare il downgrade attack in quanto supporta TLS 1.2, TLS 1.1 e TLS 1.0 e il meccanismo di protezione FALLBACK_SCSV.

* Nmap, per scansionare la presenza della vulnerabilità heartbleed nel server.
- Metasploit Version 6.4.85 per simulare l'heartbleed attack dal punto di vista dell'attacker.

* VisualStudioCode version 1.103.2 per programmare e avviare codice Python 
* Python versione 3.13.4.

Script Python:
- downgrade_client.py (è necessario impostare l'IP dell'attacker all'interno del file)
- downgrade_attacker.py (è necessario impostare l'IP del server all'interno del file)


---
## Installation guide

1) Download this repository manually on Github or using the following command:
```
git clone https://github.com/micheleportas/TLS-NetSecProject.git
```

2) Move inside the project folder:
```
cd TLS-NetSecProject
```

3) Generate the server certificate running the following command:
```
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=network-security"
```
This will generate a self-signed certificate for the server (server.crt) and its private key (server.key).
Avviare sempre il server nella stessa directory dove produci il certificato e la chiave.
Command explaination:
- -x509: specifies the self-signed certificate.  
- -newkey rsa:2048: creates a RSA key 2048 bits.  
- -keyout server.key: saves the private key as server.key.  
- -out server.crt: saves the certificate as server.crt.  
- -days 365: the certificate is valid for 365 days.  
- -nodes: no passphrase.  
- -subj "/CN=server-lab": set the certificate “Common Name”.  

4) Create the virtual environment and install the requirements:
```
python -m venv venv & \
source ./venv/bin/activate & \
pip install -r requirements.txt
```

In order to use OpenSSL with your clients and server, you need to deactivate your firewall or add a rule to allow the traffic on port 4433:
```
sudo ufw allow 4433/tcp

sudo ufw disable
```

At this point you can follow the instructions related to the vulnerability written on each markdown file:
- DowngradeAttack.md
- EarlyDataAttack.md
- HeartbleedAttack.md
- TripleHandshakeAttack.md


---

## Notes

Per usare wireshark su linux devi avviarlo con sudo perché le interfacce su linux richiedono privilegi sudo:
```
sudo wireshark
```
Selezionare poi l'interfaccia di rete da usare.

Filtri TLS su wireshark: 
* tls, per filtrare solo il traffico TLS
* tls.heartbeat, per filtrare solo i messaggi di tipo heartbeat

I messaggi TLS hanno tanti campi al suo interno, indicheremo qui una lista dei campi più importanti trattati dal nostro progetto e dove leggerli su Wireshark:
- ClientHello, è il messaggio TLS relativo all'handshake mandato dal client, puoi leggerlo dalle Info del pacchetto.
- ServerHello, è il messaggio TLS relativo all'handshake mandato in risposta dal server, puoi leggerlo dalle info del pacchetto.
- Su Handshake Protocol > Version, questo è il campo legacy version ed è usato solo durante la comunicazione con TLS 1.2 o inferiore per motivi di retrocompatibilità.
- Su Handshake Protocol > Extension: supported_version, qui è dove il client elenca al server le sue versioni utilizzate, e dove il server decide quale accettare. Viene usato solo per TLS 1.3.
- Su Handshake Procolol > Random, si può trovare il downgrade sentinel.
- Su Handshake Protocol > Cipher Suites, puoi trovare il FALLBACK_SCSV se l'opzione è abilitata nel client.
- Heartbeat Request, è il messaggio di tipo heartbeat, puoi leggerlo dalle info del pacchetto.
- L'Early data è mandato insieme al ClientHello, puoi vedere nelle info Application Data, e poi in Application Data Protocol ci sono tutti i dati mandati con l'early data.


---
## Fonti

Transport Layer Security:
https://hpbn.co/transport-layer-security-tls

TLS 1.3:
https://datatracker.ietf.org/doc/html/rfc8446

TLS 1.2:
https://datatracker.ietf.org/doc/html/rfc5246

TLS 1.1:
https://datatracker.ietf.org/doc/rfc4346

OpenSSL 1.0.1:
https://openssl-library.org/source/old/1.0.1

OpenSSL 3.0.13:
https://mta.openssl.org/pipermail/openssl-announce/2024-January/000293.html

Random sentinel TLS 1.3:
https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.3

FALLBACK_SCSV:
https://datatracker.ietf.org/doc/html/rfc7507

Early Data:
https://datatracker.ietf.org/doc/html/rfc8470

Heartbleed:
https://www.heartbleed.com/


