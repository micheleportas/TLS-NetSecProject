# Heartbleed attack

## Introduzione

Un'altra vulnerabilità di cui vogliamo trattare è chiamata heartbleed. Questa vulnerabilità non è relativa a TLS in sé ma alla sua implementazione. Infatti TLS è un protocollo che definisce regole di implementazione, ma tali protocolli vengono implementati in vari modi. OpenSSL è un software open source parecchio utilizzo che da la sua implementazione di TLS.
Il motivo di questa piccola parentesi sta nel fatto che anche se il protocollo TLS non ha falle, attori maligni possono comunque provare a sfruttare le vulnerabilità nella sua implementazione. Infatti Heartbleed fu un bug parecchio famoso che rese vulnerabili parecchi server.
Inoltre in questo progetto abbiamo più volte preso in considerazione e usato OpenSSL per simulare e mostrare le vulnerabilità, per cui riteniamo importante aprire una piccola parentesi pure su questo aspetto della sicurezza.

Heartbleed è una vulnerabilità del heartbeat TLS in OpenSSL ≤1.0.1f in quanto il server deve supportare l'estensione TLS Heartbeat, che è una funzionalità in cui viene verificata se la connessione TLS sia ancora attiva senza fare un nuovo handshake.
Permette a un attaccante di leggere fino a 64 KB di memoria del server senza autenticazione.
E' stato patchato dalle versioni di OpenSSL >1.0.1g
In pratica prevede che il client e il server si rimbalzino un pacchetto heartbeat.
La vulnerabilità Heartbleed nasce quando il server risponde più dati di quelli ricevuti, leggendo memoria arbitraria, infatti In OpenSSL, il server non controllava che la lunghezza dichiarata fosse corretta rispetto ai dati reali inviati.

In OpenSSL ≤1.0.1f, l’estensione Heartbeat è abilitata di default, quindi basta semplicemente avviare il server.

TLS (Transport Layer Security) è lo standard, definito da RFC, che descrive come stabilire una connessione sicura (handshake, cifratura, autenticazione, ecc.).
OpenSSL è solo una delle librerie che implementano TLS.
Il bug stava nel codice di OpenSSL, non nella specifica TLS.

L’estensione Heartbeat è definita nella RFC 6520 come un’estensione per TLS/DTLS che fornisce una meccanismo di keep-alive (cioè per verificare che il peer sia ancora attivo) senza dover rifare tutto il processo di handshake.

Funziona così:
Client → Server: il client invia un messaggio con un payload e la sua dimensione.
Server → Client: il server risponde ripetendo lo stesso payload ricevuto leggendo quel numero di byte indicato.

L’attaccante poteva quindi inviare un payload associato a una lunghezza maggiore di quanto stesse effettivamente inviando.
Il server, fidandosi della lunghezza dichiarata, cerca di restituire tutti quei byte, ma visto che il client aveva mandato meno byte di quanti ne aveva il payload allora completava la risposta leggendo dalla sua memoria interno.

Il messaggio Heartbeat (RFC 6520) ha formato semplice:
- Prima di tutto viene riconosciuto dal ContentType TLS che ha valore 0x24.
- il campo `HeartbeatMessageType` (1 byte,  `1` = request, `2` = response.)
- Il campo `payload_length` (2 byte max ed è lunghezza del payload dichiarata dal client)
- Il campo `payload` (dati effettivi inviati dal client, ci si aspetta che coincida con la lunghezza dichiarata)
Il bug: OpenSSL non controllava se il valore di `payload_length` fosse maggiore della lunghezza reale dei dati inviati con payload. 

Dimensione totale del Heartbeat message (payload + header): 1 (type) + 2 (payload_length) + payload_length

Ogni richiesta può restituire fino a 64 KB di memoria.
Ripetendo l’attacco, si possono raccogliere pezzi di memoria contenenti come chiavi, credenziali, cookie etc.

Ha colpito una parte enorme di Internet: si stima che circa il 17% dei server HTTPS pubblici (circa mezzo milione) fosse vulnerabile al momento della scoperta.
Heartbleed ha mostrato quanto un singolo bug in una libreria fondamentale possa mettere a rischio la sicurezza di gran parte di Internet.

I messaggi Heartbeat sono di due tipi principali:
HeartbeatRequest, mandato dal client;
HeartbeatResponse, mandato dal server; 

Il payload può essere semplicemente dati random arbitrari, ma non è usato per trasmettere dati significativi, solo per mantenere viva la connessione.

E' stata risolta aggiornando OpenSSL a versioni successive o disabilitando l’estensione Heartbeat se non necessaria.


## Operazioni preliminari

Dato che OpenSSL 1.0.1 non è una versione disponibile di default nei sistemi moderni, ho optato per scaricarla dal sito ufficiale e compilarla. Di seguito riporto tutti i comandi necessari per installare correttamente questa versione di OpenSSL senza causare conflitto con la versione più recente installata di default nel sistema:

```
wget https://www.openssl.org/source/old/1.0.1/openssl-1.0.1f.tar.gz
tar -xzf openssl-1.0.1f.tar.gz
cd openssl-1.0.1f

./config --prefix=/usr/local/ssl-1.0.1f
make
sudo make install_sw
```

>Questo installerà OpenSSL 1.0.1f in `/usr/local/ssl-1.0.1f`, per cui per usarlo in modo safe senza avere incompatibilità basta richiamarlo con il path `/usr/local/ssl-1.0.1f/bin/openssl`.

Per verificare la versione installata:
```
/usr/local/ssl-1.0.1f/bin/openssl version
```

Quindi crea i certificati self-signed per il server OpenSSL:
```
/usr/local/ssl-1.0.1f/bin/openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=heartbleed"
```

Avviare wireshark lato client:
```
sudo wireshark
```
E impostare il filtro `tls` per filtrare solo i pacchetti TLS.

## Esperimenti

Per l'Heartbleed possiamo assumere solo un server e un client malevolo.

Avviare il server OpenSSL usando la versione 1.0.1f:
```
/usr/local/ssl-1.0.1f/bin/openssl s_server -accept <port> -cert server.crt -key server.key -tlsextdebug -www
```
Dove `-tlsextdebug` mostra le estensioni TLS, incluso Heartbeat.

Per vedere se il server è vulnerabile all'heartbleed:
```
nmap -p <port> --script ssl-heartbleed <ip_server> -v
```
Il server risponderà con un output che confermerà se è vulnerabile o no.

Per mostrare questa vulnerabilità utilizziamo il tool chiamato Metasploit.
La scelta di questo tool su questo caso ricade sul fatto che è un potente tool che comunica direttamente a basso livello con la libreria OpenSSL, costruendo pacchetti Heartbeat validi per il server. In pratica esegue operazioni molto complesse che comprendono la costruzione dei record TLS gestendo il framing nella sua interezza (headers, versioni, payload length etc.).
Metasploit mantiene inoltre la coerenza negli sequence number, gestisce correttamente gli IV e lo stato di cifratura e preserva il contesto della sessione SSL, cioè segue esattamente il CVE-2014-0160.

Avviare Metasploit:
```
msfconsole
```

Poi usare il modulo openssl_heartbleed e configurarlo con i parametri corretti:
```
use auxiliary/scanner/ssl/openssl_heartbleed
set RHOSTS <ip_server>
set RPORT <port>
set VERBOSE true
```

Avviare lo scan ed exploit con:
```
run
```

### Risultati

Possiamo osservare i pacchetti heartbeat prima tenendo il server attivo e catturando i pacchetti mandati da nmap. Infatti normalmente il client non li può mandare, l'unico modo per inviarli in questo esperimento è usare tool come nmap, metasploit o altri tool a basso livello in grado di costruire pacchetti heartbeat e inviarli.

Dal log stdout del server OpenSSL, usando nmap, possiamo notare che il client sta indicando che supporta l'estensione Heartbeat e che può usarlo.
Su Wireshark invece possiamo notare che dopo l'handshake (client hello e server hello) il client manda l'heartbeat request malforme, infatti chiede un payload length di 16384 byte ma manda un payload di 19 byte.
Nell'heartbeat response possiamo invece vedere che oltre a ripetere il payload, restituisce anche altri dati.
In questo caso non restituisce alcun elemento significativo o sensibile, ma nelle giuste condizione l'attacker potrebbe.

Analizzando invece cosa fa metasploit, dal log del server continuiamo a vedere che il client usa l'estensione heartbeat.
Su wireshark possiamo vedere che il client manda l'heartbeat request con una length di 65535 byte. E il server risponde con un heartbeat response e diversi pkt separati chiamati encrypted heartbeat.
Questo perché TLS impone un massimo di 164384 byte di plaintext record.
Il messaggio heartbeat usa già 3 byte (1 di type e 2 di payload length), quindi il payload massimo è di 16381 byte.
Questi dati vengono mandati nel primo messaggio heartbeat.
Ma il client aveva chiesto 65535 byte, quindi il server vulnerabile cerca di soddisfare la request frammentando i dati in più record TLS.
Tali dati vengono analizzati da metasploit e restituiti nella sua shell.
Per mostare le potenzialità di questo attacco, metasploit di default fa uno scan generico di 65535 byte, ma impostanto metasploit, prima del `run`:
```
set action KEYS
```
Possiamo dire di recuperare le chiavi private del server dalla memoria, operazione che riesce a fare senza problemi.



---

## Note

l ContentType per Heartbeat è `24` in decimale, cioè `0x18` in esadecimale.  
Esempio: 18 03 02 00 10 significa che il content type è un Heartbeat, 03 02 è la versione TLS1.1 mentre 03 03 è TLS 1.2, infine 00 10 è la lunghezza del record in byte.
Poi byte successivi sono il messaggio heartbeat, il cui schema è stato specificato precedentemente. 

I messaggi Heartbeat reali (Request/Response) si scambiano dopo l'handshake, come record TLS separati.


## Fonti

