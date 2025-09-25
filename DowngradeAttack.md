# Downgrade Attack

## Introduzione

Il downgrade attack prevede di forzare il client a usare una versione TLS inferiore a quella massima consentita.  Il motivo di ciò è che versioni precedenti sono meno sicure, per esempio uso di cypher suite deboli o vulnerabilità presenti nella versione.

Questo tipo di vulnerabilità è presente sia in TLS 1.3 che in TLS 1.2, ma un downgrade da TLS 1.3 a 1.2 è meno impattante rispetto a uno da  TLS1.2 a 1.1 o 1.0.
TLS 1.1 e precedenti hanno debolezze note e gravi:
- Primitive crittografiche obsolete
- Nessun supporto per AEAD (es. AES-GCM).
- Meccanismi di handshake meno robusti, più esposti a downgrade o a manipolazioni dei messaggi.

TLS 1.2, se configurato correttamente, rimane considerato sicuro (quando si usano solo cipher suite moderne, come AES-GCM o ChaCha20-Poly1305, con SHA-256/384, e forward secrecy).  
Quindi, il downgrade riduce la robustezza (si perde la semplificazione e le protezioni built-in di TLS 1.3, come 0-RTT replay protection, cifrari obbligatori moderni, handshake più ridotto ma non espone immediatamente a vulnerabilità note, a differenza di TLS 1.1 o 1.0.

L'esecuzione di questo attacco avviene in questo modo:
1) il client manda l'handshake al server per concordare la versione TLS.  
2) un attacker MITM si mette in mezzo per generare un errore e far credere al client che il suo messaggio non andava bene perché il server supporta una versione inferiore di TLS.  
3) Quindi il client cercherà di instaurare una connessione con versioni di TLS precedenti.  
NB: tali versioni devono essere accettabili dal server oltre che dal client.

E' importante inoltre specificare che il tentativo di ri-handshake è implementato nel client lato codice, possiamo vederlo come un: if errore then connect_using_another_version.

Normalmente, senza protezioni attive, queste richieste downgradate possono portare vantaggi all'attacker e non c'è modo che il client riesca a proteggersi.
Il modo per mitigarlo è usare TLS_FALLBACK_SCSV. 
Il FALLBACK_SCSV (Signaling Cipher Suite Value) è stato definito in RFC 7507 (2015).
Il TLS_FALLBACK_SCSV funziona così:  
1) quando il client fa il retry a una versione inferiore, inserisce nel client hello questo campo speciale.  
2) il server nota questo campo e può rifiutare la connessione se la sua versione negoziabile è maggiore di quella negoziata dal retry del client, perché capisce che si tratta di un retry del client che avrebbe potuto comunicare a versione maggiore ma per qualche motivo non è riuscito.

TLS 1.3 introduce un ulteriore meccanismo di protezione che non va attivato ed esiste di default nei server: byte sentinel.
Il server inserisce una sentinel value nel campo Random del ServerHello se è costretto a negoziare una versione più vecchia.  Specifica in RFC 8446, §4.1.3
Se un server TLS 1.3 fa downgrade a TLS 1.2, gli 8 byte finali di ServerHello.random saranno:
`44 4F 57 4E 47 52 44 01` cioè ("DOWNGRD\x01").
Se un server TLS 1.3 fa downgrade a TLS 1.1 o inferiore, i byte saranno:
`44 4F 57 4E 47 52 44 00` cioè ("DOWNGRD\x00").
In questo caso è il server a gestire la situazione. Quando riceve una richiesta downgradata e può accettarla, il server risponde al client inserendo nel campo Random dei byte del server hello che indicano al client che può accettare versioni superariori e che la richiesta attuale è stata downgradata. Sta quindi al client poi decidere se accettarla o meno guardando il contenuto di questo campo.
Questo caso verrà solo mostrato come dettaglio in quanto openssl client elabora automaticamente l'handshake e non c'è modo di analizzare il campo Random prima che la connessione venga stabilita.
La soluzione a questo problema sarebbe implementare un'applicazione che analizzi i pacchetti prima che arrivino al client.


## Operazioni preliminari

OpenSSL 3.0.13 usa di default  TLS 1.3 e 1.2 bloccando qualsiasi utilizzo o richiesta da versioni TLS precedenti, rendendo quindi il downgrade a versioni 1.1 o 1.1 impossibili da simulare.
Per cui, per simulare un downgrade da 1.2 a 1.1 abbiamo optato nell'installare una versione di OpenSSL abbastanza vecchia da consentire tale downgrade e che implementi il FALLBACK_SCSV.
la soluzione era compilare e installare una vecchia versione di OpenSSL.

Dato che OpenSSL 1.0.1j non è una versione disponibile di default nei sistemi moderni, ho optato per scaricarla dal sito ufficiale e compilarla. Di seguito riporto tutti i comandi necessari per installare correttamente nel server e nel client questa versione di OpenSSL senza causare conflitto con la versione più recente installata di default nel sistema:
```
wget https://www.openssl.org/source/old/1.0.1/openssl-1.0.1j.tar.gz
tar -xzf openssl-1.0.1j.tar.gz
cd openssl-1.0.1j

./config --prefix=/usr/local/ssl-1.0.1j
make
sudo make install_sw
```

>Questo installerà OpenSSL 1.0.1j in `/usr/local/ssl-1.0.1j`, per cui per usarlo in modo safe senza avere incompatibilità basta richiamarlo con il path `/usr/local/ssl-1.0.1j/bin/openssl`.

Per verificare la versione installata:
```
/usr/local/ssl-1.0.1j/bin/openssl version
```

Quindi crea i certificati self-signed per il server OpenSSL:
```
/usr/local/ssl-1.0.1j/bin/openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=downgrade"
```

Per accedere a questa versione di OpenSSL basterà richiamare il programma da questo path: `/usr/local/ssl/bin/openssl`. Ciò ci consente di intercambiare facilmente con la versione più recente di OpenSSL che invece verrà richiamata usando semplicemente `openssl`.

Avviare wireshark lato attacker:
```
sudo wireshark
```
E impostare il filtro `tls` per filtrare solo i pacchetti TLS.


## Esperimenti

### Caso A -No Downgrade

Per questo caso consideriamo un server e un client che supportano solo TLS 1.2 e 1.1 e non applichiamo alcun downgrade in modo da mostrare la comunicazione normale.

Avviare il server:
```
/usr/local/ssl-1.0.1j/bin/openssl s_server -accept <port> -cert server.crt -key server.key
```

Avviare l'attacker dallo script `downgrade_attacker.py` in modalità 'NO DOWNGRADE'.

Avviare il client dallo script `downgrade_client.py` in modalità 'NO FALLBACK_SCSV'.

#### Risultati

Possiamo notare dal log del client e del server che la connessione viene stabilita correttamente, anche il log dell'attacker ci segnala correttamente l'inoltro dei messaggi.
Su wireshark invece possiamo vedere che l'handshake avviene correttamente e che negoziano TLS 1.2 in quanto è la versione massima consentita sia dal client che dal server.


### Caso B - Downgrade (no FALLBACK_SCSV)

Per questo caso consideriamo sempre un client e un server che supportano TLS 1.2 e 1.1 ma applichiamo il downgrade ma non il meccanismo di protezione FALLBACK_SCSV per mostare cosa succede.

Avviare il server:
```
/usr/local/ssl-1.0.1j/bin/openssl s_server -accept <port> -cert server.crt -key server.key
```

Avviare l'attacker dallo script `downgrade_attacker.py` in modalità 'DOWNGRADE'.

Avviare il client dallo script `downgrade_client.py` in modalità 'NO FALLBACK_SCSV'.

#### Risultati

Il downgrade avviene e possiamo infatti notare che l'attacker intercetta il ClientHello del client, rileva la versione TLS 1.2 e manda un messaggio che viene ricevuto dal client.
Tale messaggio non viene interpretato correttamente dal client, il che genera un errore e pensa che che il server comunica solo con TLS 1.1. Il client quindi contatta il server facendo un fallback alla versione 1.1.
Tutte queste azioni sono documentate nel log dell'attacker e del client.

Possiamo inoltre vedere dal log del client e del server e da wireshark che hanno negoziato correttamente TLS 1.1.


### Caso C - Downgrade (FALLBACK_SCSV)

Per questo caso consideriamo sempre un client e un server che supportano TLS 1.2 e 1.1 ma applichiamo il downgrade e il meccanismo di protezione FALLBACK_SCSV per mostare come la vulnerabilità viene mitigata.

Avviare il server:
```
/usr/local/ssl-1.0.1j/bin/openssl s_server -accept <port> -cert server.crt -key server.key
```

Avviare l'attacker dallo script `downgrade_attacker.py` in modalità 'DOWNGRADE'.

Avviare il client dallo script `downgrade_client.py` in modalità 'FALLBACK_SCSV'.
All'interno dello script, il client esegue praticamente questo comando:
```
/usr/local/ssl-1.0.1j/bin/openssl s_client -connect <ip_attacker>:<port> -fallback_scsv
```
Dove il parametro `-fallback_scsv` serve a segnalare al server del fallback.

#### Risultati

Il downgrade avviene anche in questo caso e possiamo infatti notare che l'attacker intercetta il ClientHello del client, rileva la versione TLS 1.2 e manda un messaggio che viene ricevuto dal client come nel caso precedente.
Tale messaggio non viene interpretato correttamente dal client, il che genera un errore e pensa che che il server comunica solo con TLS 1.1. A sto giro il client fa il fallback a 1.1 ma inserisce il parametro di FALLBACK_SCSV.
Tutte queste azioni sono documentate nel log dell'attacker e del client.

Grazie all'inserimento di FALLBACK_SCSV il server rifiuta la comunicazione, causando quindi una chiusura della connessione, come possiamo notare dal log del client e del server.
Anche su wireshark possiamo notare che l'handshake non si concluso correttamente.


### Caso D - Downgrade Sentinel

Per questo caso mostriamo solo che TLS 1.3 ha introdotto il sentinel all'interno del campo Random nel ServerHello. Non avvieremo neanche l'attacker in quanto non è stato implementato alcun analizzatore di traffico collegato ad operazioni di rifiuto dei pacchetti nel caso in cui il sentinel venisse rilevato.
In un caso reale se il client supporta TLS 1.3 potrebbe rifiutare la connessione del server leggendo il sentinel. Se invece il client supporta effettivamente solo TLS 1.2 allora accetterà la connessione.

Vogliamo simulare un server che accetta TLS 1.3 e 1.2.
Invece il client userà TLS 1.2.

Avviare il server:
```
openssl s_server -accept <port> -cert server.crt -key server.key
```

Avviare il client:
```
openssl s_client -connect <ip_server>:<port> -tls1_2
```

Su wireshark possiamo notare nel ServerHello il campo Random, e i suoi ultimi 8 byte corrispondono esattamente a `44 4F 57 4E 47 52 44 01` cioè ("DOWNGRD\x01").

Se invece dovessimo avviare il client in modalità da accettare TLS 1.3 e 1.2:
```
openssl s_client -connect <ip_server>:<port>
```

Possiamo notare l'assenza del sentinel, e possiamo anche notare che la versione negoziata non è più sul legacy version ma sul supported_version, in pratica il legacy version esiste ancora per negoziare con versioni precedenti a TLS 1.3.


## Descrizione codice

### downgrade_client.py

Il client consente di lavorare in 2 modalità:
senza abilitare la protezione al downgrade oppure attivandola.
Nella prima modalità usa la funzione try_openssl passando la versione di TLS da negoziare come parametro a openssl. Dentro questa funzione il client avvierà il servizio client di OpenSSL specificando l'indirizzo IP e la porta da usare per connettersi. In questo caso il client si connette all'attacker in quanto ipotizziamo sia inserito come Man in the Middle (MITM) tra lui e il server.
Se la comunicazione fallisce allora pensa che il server non accetti la versione proposta e allora prova un fallback con la versione precedente.
In questo caso lavora con TLS 1.2 e fa il fallback a 1.1.
Nella seconda modalità invece, oltre a passare la versione da negoziare, inserirà pure il parametro -fallback_scsv che segnalerà al server che sta provando a negoziare a seguito di un fallback da una versione successiva.

Il TLS_FALLBACK_SCSV (0x5600) è inserito nella lista delle CipherSuites che il client propone al server.
Il campo cipher_suites del ClientHello contiene l’elenco delle suite crittografiche che il client è disposto a usare, in ordine di preferenza.


### downgrade_attacker.py

Il codice dell'attacker presenta due opzioni selezionabili: 
- NO DOWNGRADE, in cui l'attacker si occuperà solo di inoltrare i pacchetti tra client e server
- DOWNGRADE ATTACK, in cui l'attacker rileverà se il ClientHello cerca di negoziare la versione TLS 1.2 per poi inviare un messaggio di errore al client e far quindi interrompere la connessione tra client e server.

L'attacker quindi userà la funzione relay_server in cui viene passata l'opzione scelta, la porta su cui l'attacker deve restare in ascolto, l'indirizzo IP e la porta usata dal server a cui mandare i pacchetti del client. 
Quindi l'attacker aprirà un socket e rimarrà in ascolto di possibili connessioni.
Quando il client si connette, riceve i dati da lui inviati e li analizza con la funzione parse_clienthello_tls_version.
All'interno di tale funzione verifica che gli sia mandato un clienthello TLS leggendo i byte che costituiscono l'header del pacchetto. Per esempio controlla il campo content_type che corrisponda al valore 0x16 (cioè indicativo dell'handshake), poi controlla che sia un handshake di tipo ClientHello (identificato dal valore 0x01), e infine legge il campo legacy version che inizia dopo 9 byte dall'inizio dell'header TLS.
Se il campo legacy version vale 0x303 allora rileva che sta negoziando TLS 1.2 (infatti 0x303 è il code per TLS 1.2, 0x302 è TLS 1.1, 0x304 è TLS 1.3).
Se viene rilevato TLS 1.2 allora manda un messaggio di errore che serve a far credere al client che il server non supporta TLS 1.2, altrimenti inoltra i pacchetti al server o viceversa li inoltra al client.

Struttura del record layer ed handshake layer del TLS 1.2 (RFC 5246):
Tutti i messaggi TLS iniziano con un Record Layer Header di 5 byte:
- 1 byte di ContentType (0x16 identifica l'handshake)
- 2 byte di ProcolVersion (spesso identifica una versione legacy)
- 2 byte di Length (la lunghezza del payload che segue, e cioè dell'handshake message)

Quindi poi abbiamo l'Handshake Header di 4 byte che è contenuto solo nei pacchetti di tipo handshake:
* 1 byte di HandshakeType (0x01 identifica un ClientHello)
* 3 byte di Length (lunghezza del body del ClientHello)

Quindi poi abbiamo il body del ClientHello:
- 2 byte di legacy_version (0x0303 = TLS 1.2)

Quindi complessivamente per leggere la legacy version dobbiamo leggere il byte 10 e 11.
L'offset è 9 perché gli indici per accede ad un array iniziano da 0.

---

## Note

La differenza sostanziale tra TLS_FALLBACK e il Sentinel è questa:
- TLS_FALLBACK_SCSV è un meccanismo cooperativo, cioè funziona solo se entrambi gli endpoint (client e server) lo supportano e lo rispettano, e viene inserito dal client.
- Sentinel random (o “downgrade sentinel” inserito dal server) è invece un meccanismo unilaterale, cioè funziona anche se il server non ha mai sentito parlare dell’SCVS.

In pratica con l'SCSV c'era il problema della compatibilità retroattiva, cioè alcuni server vecchi che non conoscevano l’SCVS non potevano rilevare i downgrade.
Grazie al sentinel invece basta che solo il server lo implementi, il client non ha bisogno di sapere altro oltre a fare il check del sentinel. 
Cioè l’esistenza del sentinel aggiunge la robustezza e universalità, eliminando la dipendenza dal supporto esplicito dell’altra parte, cosa che l’SCVS non poteva fare da solo.

Regola del sentinel (TLS 1.3, RFC 8446 §4.1.3):
Il server aggiunge il downgrade sentinel solo se:
- il server supporta TLS 1.3,
- ma la connessione è stata negoziata a una versione inferiore (1.2 o 1.1),



