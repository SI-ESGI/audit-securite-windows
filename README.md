# SCRIPT AUDIT SECURITÉ WINDOWS

Le script d'audit de sécurité Windows est un utilitaire
PowerShell modulaire et complet conçu pour eectuer une
évaluation approfondie des paramètres de sécurité Windows.
Il examine systématiquement les paramètres de sécurité
critiques dans plusieurs domaines, notamment la
configuration système, les mécanismes d'authentification, la
gestion des utilisateurs, les paramètres réseau, et plus
encore.
Le script génère des rapports détaillés dans plusieurs
formats (HTML, JSON et TXT), fournissant à la fois des détails
techniques pour les professionnels de la sécurité et des
résumés exécutifs pour la direction. Chaque domaine d'audit
est examiné en profondeur avec des indicateurs de sécurité
codés par couleur dans la sortie HTML.


## Pré-requis :

- Windows PowerShell 5.1 ou supérieur
- Privilèges administratifs (-RunAsAdministrator)
- Compatible avec Windows 10/11 et Windows Server
2016/2019/2022
- Optionnel: Outils d'administration de serveur distant (RSAT)
pour une analyse GPO améliorée

## Architecture du script 

Le script suit une architecture modulaire basée sur ces
principes de conception:
1. Initialisation: Configure l'environnement et prépare les
structures de données
2. Audit modulaire: Chaque domaine de sécurité a une
fonction module dédiée
3. Collecte de données: Chaque module collecte des
informations de sécurité spécifiques
4. Génération de rapports: Crée des rapports détaillés à
partir des données collectées



## EQUIPE :  Enzo FALANDRY, Nawel BERRICHI, Eduardo PINA
