# Vulnerabilities in the TLS protocol and its implementations

Network Security Project about TLS vulnerabilities for the Network Security exam.


## Tools

Hypervisor VM used: **VMware Workstation 17 Pro** 17.6.1 build-24319023
- Linux distro used: Linux Mint 22.1 64-bit

3 distinct Linux virtual machines on the same subnet:
- Server: 192.168.91.xxx/24
- Client: 192.168.91.xxx/24
- Attacker: 192.168.91.xxx/24
Port used for TLS communication between client and server: **4433/443**
 
 **Wireshark** version 4.2.2 used to analyze the TLS traffic and packet structure.
 Wireshark is a network analyzer that allows you to capture and inspect packets traveling across a network in real time.

TLS simulation tools: **OpenSSL**.  and **tlslite-ng**
**OpenSSL** is an open-source library that provides tools and implementations for cryptography, TLS/SSL, and digital certificate management. Instead, **tlslite-ng** is a Python library that implements TLS and SSL in a lightweight and flexible way, designed to simplify the creation and management of secure connections.
OpenSSL versions used:
- **OpenSSL 3.0.13** (preinstalled on Linux). This version natively supports only TLS 1.3 and TLS 1.2.
- **OpenSSL 1.0.1f**, used to simulate Heartbleed. This version supports TLS 1.2, TLS 1.1 and TLS 1.0 and the heartbeat messages.
- **OpenSSL 1.0.1j**, used to simulate the downgrade attack as it supports TLS 1.2, TLS 1.1 and TLS 1.0 and the FALLBACK_SCSV protection mechanism.
 
**Nmap**, to scan for the presence of the Heartbleed vulnerability on the server.
Nmap is a network scanning tool used to discover active hosts and services by analyzing ports and potential vulnerabilities.

**Metasploit** version 6.4.85 to simulate the Heartbleed attack from the attacker’s point of view.
Metasploit is a penetration testing framework that enables developing, testing, and executing exploits and payloads against remote systems to facilitate security assessments.

**Visual Studio Code** version 1.103.2 to write and run Python code.
- Python version 3.13.4.

**OpenSSH** version 9.6p1.
This service is used by the attacker to steal the session file from the client.

Python scripts:
- **downgrade_client.py** (the attacker’s IP must be set inside the file)
- **downgrade_attacker.py** (the server’s IP must be set inside the file)
- **script.py** (set the server, client and gateway IP address inside the file)


## Installation guide and preparation

You can follow this guide to install everything in a single Virtual Machine and then clone it twice in order to obtain a client, a server and an attacker.

Update your system:
```
sudo apt-get update
```

Install a server SSH and activate the service:
```
sudo apt install openssh-server -y
sudo systemctl enable ssh
sudo systemctl start ssh
```

Install the virtual environment manager for Python 3 if not already installed:
```
sudo apt install python3-venv
```

Install nmap:
```
sudo apt install nmap
```

Install git:
```
sudo apt install git
```

Install Wireshark:
```
sudo apt install wireshark
```

Download Visual Studio Code downloading the '.deb' package from the original website: 
`https://code.visualstudio.com/Download`.  
Then install the software using the following command:
```
sudo apt install ./<vscode_installer.deb>
```


Install Metasploit running this command:
```
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
  chmod 755 msfinstall && \
  ./msfinstall
```

Install the following modules useful to simulate the triple handshake attack:
```
sudo apt-get install python3-pip libnfnetlink0 python3 python3-dev libnetfilter-queue1 libnetfilter-queue-dev dsniff net-tools iptables iputils-ping gcc
```

Since OpenSSL 1.0.1f is not available by default on modern systems, download it from the official website and compile it. Below are all the commands required to correctly install this version of OpenSSL without causing conflicts with the more recent version already installed by default on the system:
```
wget https://www.openssl.org/source/old/1.0.1/openssl-1.0.1f.tar.gz
tar -xzf openssl-1.0.1f.tar.gz
cd openssl-1.0.1f

./config --prefix=/usr/local/ssl-1.0.1f
make
sudo make install_sw
cd ..
```
This will install OpenSSL 1.0.1f in `/usr/local/ssl-1.0.1f`, so to use it safely without compatibility issues you just need to call it with the path `/usr/local/ssl-1.0.1f/bin/openssl`.

To verify the installed version:
```
/usr/local/ssl-1.0.1f/bin/openssl version
```

Since OpenSSL 1.0.1j is not available by default on modern systems, download it from the official website and compile it:
```
wget https://www.openssl.org/source/old/1.0.1/openssl-1.0.1j.tar.gz
tar -xzf openssl-1.0.1j.tar.gz
cd openssl-1.0.1j

./config --prefix=/usr/local/ssl-1.0.1j
make
sudo make install_sw
cd ..
```
This will install OpenSSL 1.0.1j in `/usr/local/ssl-1.0.1j`, so to use it safely without compatibility issues you just need to call it with the path `/usr/local/ssl-1.0.1j/bin/openssl`. 

To verify the installed version:
```
/usr/local/ssl-1.0.1j/bin/openssl version
```

Download this repository manually on Github or using the following command:
```
git clone https://github.com/micheleportas/TLS-NetSecProject.git
```

Move inside the project folder:
```
cd TLS-NetSecProject
```

Generate the server certificate running the following command:
```
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=network-security"
```
This will generate a self-signed certificate for the server (server.crt) and its private key (server.key).
Always start the server in the same directory where you create the certificate and private key.
Command explaination:
- -x509: specifies the self-signed certificate.  
- -newkey rsa:2048: creates a RSA key 2048 bits.  
- -keyout server.key: saves the private key as server.key.  
- -out server.crt: saves the certificate as server.crt.  
- -days 365: the certificate is valid for 365 days.  
- -nodes: no passphrase.  
- -subj "/CN=server-lab": set the certificate “Common Name”.  

Change the permission to the following files:
```
chmod 777 script.py downgrade_attacker.py downgrade_client.py keygen_certificates.sh
```

We want also to generate the keys and certificates used by the libraries that carry out the triple handshake, in this case simply run this bash file:
```
./keygen_certificates.sh
```
You will be asked to input some fields: just press enter.

Create the virtual environment and install the requirements:
```
python3 -m venv venv
source ./venv/bin/activate
pip install -r requirements.txt
```

In order to use OpenSSL with your clients and server, you need to deactivate your firewall or add a rule to allow the traffic on port 4433/443 (for our example we prefer to disable it):
```
sudo ufw allow 4433/tcp
or
sudo ufw disable
```

Generation of early data to be used by the client:
```
printf 'EARLY-DATA\n' > early.txt
```
The content is not important; it is only meant to demonstrate data to be sent.

At this point you can clone the Virtual Machine.  

Start each VM e look at their IP addresses, interface and the gateway IP address using these commands:
```
ifconfig
ip route
```

In the `script.py` file, modify for each VM your IP addresses, port, and the interface used by the attacker.  
When you'll run `script.py`, remember to run it in the same path where the certificates are located.
For it to work, `script.py` expects the following hostnames for the client, server, and attacker: respectively `client`, `server`, `attacker`.  
The file is a single script and contains the logic to execute the correct code for each of the three hosts, so all three run the same file.
If you need to change the VM's hostname use the following command:
```
sudo hostnamectl set-hostname <new_hostname>
```
Wireshark may need to be reconfigured, run the following commands:
```
sudo usermod -aG wireshark $USER
sudo dpkg-reconfigure wireshark-common
```
Restart all your the VMs.

Now you can start the client, server, and attacker VMs and follow the instructions related to the vulnerability written on each markdown file:
- DowngradeAttack.md
- EarlyDataAttack.md
- HeartbleedAttack.md
- TripleHandshakeAttack.md

Remember to stay inside the virtual environment activated, otherwise you can always activate it with:
```
source ./venv/bin/activate
```

## Notes

TLS filters in Wireshark:
- `tls` to filter only TLS traffic
- `tls and tcp.port==4433` to filter TLS traffic on port 4433
- `tls.heartbeat` to filter only heartbeat messages

TLS messages contain many fields. Here is a list of the most important fields relevant to our project and where to find them in Wireshark:
- **ClientHello**: the TLS handshake message sent by the client; can be read in the Packet Info.
- **ServerHello**: the TLS handshake message sent by the server in response; can be read in the Packet Info.
- **Handshake Protocol > Version**: the legacy version field, used only during communication with TLS 1.2 or lower for backward compatibility.
- **Handshake Protocol > Extension: supported_version**: where the client lists its supported versions and the server chooses which one to accept; used only for TLS 1.3.
- **Handshake Protocol > Random**: the location of the downgrade sentinel.
- **Handshake Protocol > Cipher Suites**: contains the `FALLBACK_SCSV` if this option is enabled on the client.
- **Heartbeat Request**: the heartbeat-type message; can be read in Packet Info.
- **Early Data**: sent together with ClientHello; visible in Packet Info under Application Data, and all early data contents appear in the Application Data Protocol section.


