# E5_5OSATTK — Projet Pentest Active Directory

**Étudiant :** CACCIATORE Vincent  
**Date :** 13/05/2026  
**Module :** 5OSATTK  
**Cible :** Lab GOAD-Light

## Structure du repo

- Rapport-CV-13-05-2026.md — Rapport complet de pentest
- docs/ — Schémas et journal de bord
- infra/ — Setup attaquant (docker-compose Sliver/BloodHound)
- logs/ — Sorties de commandes (preuves d'exécution)
- screenshots/ — Captures d'écran du TP
- wordlists/ — Dictionnaires construits pour l'attaque
- loot/ — Données extraites (hashs filtrés du repo, voir .gitignore)

## Frameworks utilisés

- **Reconnaissance** : Nmap, NetExec
- **Énumération** : Impacket, ldapsearch, BloodHound CE
- **Exploitation** : Impacket, Responder, Certipy
- **C2 Red Team** : Sliver (Bishop Fox)
- **Crackage** : Hashcat

## Comment lire ce repo

Commencer par Rapport-CV-13-05-2026.md, puis consulter logs/ pour les preuves de chaque phase.

## Convention de nommage

Tous les composants portent le suffixe \CV-13-05-2026\ (initiales + date).