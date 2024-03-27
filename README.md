> # Mariano 
> 
> Test
---

Questo set di progeammi consente di cifrare/decifrare file in man
Utilizzo:

* Con certificato PKI + chiave privata locale ( crt + key )
* Con certificato PKI online + chiave privata locale ( key )
* Con certificato PKI online + chiave privata online

Nel terzo caso :

il client invia un post al server che deve fornire la chiave privata, per farlo 
il post deve contenere il codice TOTP corretto per il client.

Il server verifica se il TOTP è corretto ed invia come risposta al POST un blocco 
dati cifrato contenente la chiave privata richiesta. 

Il blocco verrà cifrato dal server utilizzando una chiave derivata dalla chiave pubblica PKI 
ma non fornirà al client, nella risposta, questa chiave ma solo il "salt" utilizzato per derivare la chiave stessa.

Ciò significa che un potenziale attaccante non potrà derivare la chiave poichè mancano elementi indispensabili al suo calcolo ( Chiave pubblica PKI e ID CLIENT )

Dkey = HKDF (  chiave pubblica PKI , salt casuale 16 Bytes , info -> IDCLIENT )

Nel blocco inviato dal server ci sarà disponibile il salt non crittografato.

Il ricevitore: 

1. Estrae la chiave pubblica dal certificato
2. Estrae dal blocco ricevuto dal server la parte realtiva al salt
3. Estrae il suo ID dalla configurazione 
4. Deriva la chiave del blocco tramite HKDF
5. Con questa chiave decifra il blocco e ottiene la chiave privata richiesta
6. con la password del punto 5 si può decifrare la password AES GCM utilizzata nella crittazione del file. 
7. Decritta il file


Nota: lato server tutte le chiavi private disponibili devono essere cifrate in pcks#8 con password 
in modo che nel caso di furto delle stesse esse siano inutili.