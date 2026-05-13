# E5_5OSATTK — Projet Pentest Active Directory

**Etudiant :** CACCIATORE Vincent 

**Binôme :** GRECO Clément

**Date :** 13/05/2026  

**Module :** 5OSATTK - ESTIAM Metz - E5

**Cible :** Lab GOAD-Light

## Structure du repo

- 5OSATTK_CACCIATORE_Rapport.md — Rapport complet de pentest
- img/ — Screenshots
- logs/ — Sorties de commandes (preuves d'exécution)
- wordlists/ — Dictionnaires construits pour l'attaque
- loot/ — Données extraites (hashs filtrés du repo, voir .gitignore)
- tools/ — Outils utilisés (voir .gitignore)

## Frameworks utilisés

- **Reconnaissance** : Nmap, NetExec
- **Énumération** : Impacket, ldapsearch, BloodHound CE
- **Exploitation** : Impacket, Responder, Certipy
- **C2 Red Team** : Sliver (Bishop Fox)
- **Crackage** : Hashcat

## Comment lire ce repo

Commencer par 5OSATTK_CACCIATORE_Rapport.md, puis consulter logs/ pour les preuves de chaque phase.