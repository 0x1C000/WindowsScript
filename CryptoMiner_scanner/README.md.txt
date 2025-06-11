# Full Anti-Miner Kit v2 + Chrome Process Scanner
Author: Ox1C

---

## Descrizione

Questa repository contiene due script PowerShell avanzati, progettati per aiutare l'utente a:

- Rilevare e rimuovere eventuali crypto-miner nascosti o persistenti nel sistema Windows
- Analizzare e monitorare in tempo reale i processi di Google Chrome per individuare eventuali attività sospette (miner in esecuzione tramite il browser)

---

## Contenuto

- `full_anti_miner_kit_v2.ps1`  
  Script completo che esegue una scansione approfondita del sistema:

  - Verifica e pulisce le chiavi di registro Run e RunOnce
  - Analizza e rimuove Scheduled Tasks sospetti
  - Analizza e disabilita servizi di sistema sospetti
  - Esegue la scansione delle cartelle TEMP e AppData per rilevare file potenzialmente malevoli
  - Controlla eventuali manipolazioni dei collegamenti (.lnk) di Chrome
  - Log dettagliato e report in CSV generati sul Desktop

- `chrome_process_scanner.ps1`  
  Script leggero e autonomo che analizza tutti i processi chrome.exe attivi:

  - Stampa per ogni processo: PID, RAM usata, command line completa
  - Evidenzia eventuali flag sospetti (--headless, --disable-gpu, ecc.)
  - Evidenzia eventuali keyword riconducibili a mining
  - Permette un'analisi rapida di attività anomale via Chrome

---

## Sistema operativo di destinazione

- Windows 10
- Windows 11

Richiede PowerShell versione 5 o superiore.

---

## Come usare gli script

1. Clonare la repository o scaricare i singoli file `.ps1`.

2. Avviare PowerShell come Amministratore.

3. Eseguire i seguenti comandi per permettere l'esecuzione temporanea degli script:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force

4. Eseguire lo script desiderato:

Per eseguire il kit completo:

.\full_anti_miner_kit_v2.ps1

Per eseguire solo lo scanner dei processi Chrome:


.\chrome_process_scanner.ps1

Note
Gli script non richiedono moduli esterni: tutto è integrato e in chiaro.

I log e i report CSV vengono salvati automaticamente sul Desktop dell'utente.

Gli script sono stati progettati per un utilizzo manuale e consapevole: nessun automatismo invasivo viene applicato senza che l'utente possa visualizzarlo (tranne la rimozione automatica di servizi e task chiaramente sospetti).

La lista di keyword e flag sospetti è modificabile all'interno degli script: può essere personalizzata e aggiornata.

Autore
Ox1C


Utilizzare gli script con consapevolezza e solo su sistemi personali o autorizzati.
Non è garantita la compatibilità su versioni di Windows precedenti a Windows 10 o su sistemi non standardizzati.
