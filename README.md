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

