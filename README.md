# Analyse et enrichissement de vulnérabilités CVE

## Présentation

Ce projet a été réalisé dans le cadre d'une mission autour du traitement et de l'analyse de données de cybersécurité.

L'objectif est d'automatiser le traitement d'alertes de sécurité afin d'identifier les vulnérabilités CVE mentionnées dans les différents fichiers, puis d'enrichir ces informations avec des données provenant d'API externes.

Le programme permet ensuite de regrouper les informations obtenues dans un tableau structuré pouvant être utilisé pour effectuer des analyses complémentaires.

## Objectifs

Les principaux objectifs du projet sont les suivants :

- Lire et traiter automatiquement des fichiers JSON contenant des alertes de sécurité.
- Identifier les références CVE présentes dans les alertes.
- Extraire les principales informations associées aux vulnérabilités.
- Identifier les éditeurs, produits et versions concernés.
- Récupérer des informations complémentaires sur les CVE à partir d'API externes.
- Ajouter les scores CVSS et EPSS aux données collectées.
- Regrouper les informations dans un DataFrame Pandas.
- Exporter les résultats dans un fichier CSV.

## Fonctionnement

Le programme commence par parcourir les fichiers JSON contenant les alertes de sécurité.

Les références CVE sont ensuite recherchées dans plusieurs champs des fichiers afin de récupérer le maximum d'informations disponibles.

Pour chaque CVE identifiée, le programme récupère des informations complémentaires à partir de différentes sources :

- MITRE CVE pour les informations relatives aux vulnérabilités et au score CVSS.
- FIRST EPSS pour obtenir le score EPSS associé à la vulnérabilité.

Les données sont ensuite nettoyées et regroupées dans un DataFrame Pandas avant d'être exportées sous forme de fichier CSV.

## Extraction des CVE

Les références CVE sont identifiées automatiquement à l'aide d'une expression régulière.

Le programme recherche notamment des références ayant le format :

CVE-YYYY-NNNN

La recherche est effectuée dans plusieurs champs des fichiers JSON, notamment le titre, le résumé, le contenu et les informations relatives aux vulnérabilités.

## Enrichissement des données

L'enrichissement des données permet d'obtenir des informations supplémentaires qui ne sont pas nécessairement présentes dans les alertes initiales.

Les principales informations récupérées sont :

- Identifiant CVE
- Score CVSS
- Score EPSS
- Éditeur concerné
- Produit concerné
- Versions affectées
- Description de la vulnérabilité
- Référence de l'alerte
- Date de publication
- Lien vers l'alerte

## Résultats

Les données finales sont regroupées dans un DataFrame Pandas afin de faciliter leur analyse et leur exploitation.

Un fichier CSV est ensuite généré avec les informations collectées et enrichies.

Cette approche permet notamment de centraliser les informations provenant de plusieurs sources et de disposer d'un format homogène pour effectuer des analyses ultérieures.

## Technologies utilisées

- Python
- Pandas
- Requests
- JSON
- Expressions régulières
- API REST
- MITRE CVE
- FIRST EPSS

## Organisation du projet

```text
anssi-vulnerability-analysis/
│
├── README.md
├── src/
│   └── anssi_pipeline.py
├── data/
│   └── sample/
├── outputs/
│   └── exemple_resultat.csv
├── requirements.txt
└── .gitignore
