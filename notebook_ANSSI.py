# -*- coding: utf-8 -*-
"""
Created on Sat Jan 17 23:07:45 2026

@author: steev
"""

import os
import json
import re
import os
import json
import re
import pandas as pd
from datetime import datetime
import requests
import time

DOSSIER_ALERTES = r"C:\Users\steev\Downloads\data_pour_TD_final_2026\alertes"
def lister_tous_les_fichiers(dossier):
    print(f"Recherche dans: {dossier}")
    print("=" * 60)
    if not os.path.exists(dossier):
        print("ERREUR: dossier non trouve")
        return []
        
    fichiers = []
    for item in os.listdir(dossier):
        chemin = os.path.join(dossier, item)
        if os.path.isfile(chemin):
            fichiers.append(chemin)
    print(f"OK: {len(fichiers)} fichiers trouves (tous types)")

    if fichiers:
        print("\n10 premiers fichiers:")
        for i, f in enumerate(fichiers[:10], 1):
            nom = os.path.basename(f)
            taille = os.path.getsize(f) // 1024  # Taille en Ko
            print(f"  {i:2d}. {nom} ({taille:,} Ko)")
        if len(fichiers) > 10:
            print(f"  ... et {len(fichiers) - 10} autres")
    return fichiers

def charger_fichier_json(chemin_fichier):
    nom_fichier = os.path.basename(chemin_fichier)
    try:
        with open(chemin_fichier, 'r', encoding='utf-8') as f:
            contenu = f.read().strip()
        print(f"  Lecture: {nom_fichier} ({len(contenu):,} caracteres)")
        try:
            data = json.loads(contenu)
            return data
        except json.JSONDecodeError as e:
            print(f"  Erreur JSON: {e}")
            return None
    except Exception as e:
        print(f"  Erreur lecture: {e}")
        return None

def extraire_cves_robuste(data):
    """Extrait les CVE de maniere robuste"""
    
    cves_trouvees = set()
    pattern = r'CVE-\d{4}-\d{4,7}'
    if "cves" in data and data["cves"]:
        for item in data["cves"]:
            if isinstance(item, dict) and "name" in item:
                cves_trouvees.add(item["name"])
    
    if "summary" in data and data["summary"]:
        texte = str(data["summary"])
        found = re.findall(pattern, texte)
        cves_trouvees.update(found)
        
    if "content" in data and data["content"]:
        texte = str(data["content"])
        found = re.findall(pattern, texte)
        cves_trouvees.update(found)

    if "title" in data and data["title"]:
        texte = str(data["title"])
        found = re.findall(pattern, texte)
        cves_trouvees.update(found)
    
    if not cves_trouvees:
        texte_complet = json.dumps(data)
        found = re.findall(pattern, texte_complet)
        cves_trouvees.update(found)
    
    return list(cves_trouvees)
def extraire_infos_fichier(data, nom_fichier):
    cves = extraire_cves_robuste(data)
    if not cves:
        print(f"    Aucune CVE trouvee")
        return []
    print(f"    OK: {len(cves)} CVE: {', '.join(cves[:3])}{'...' if len(cves) > 3 else ''}")
    titre = data.get('title', 'N/A')
    reference = data.get('reference', 'N/A')
    if 'ALE' in reference:
        type_bulletin = 'Alerte'
    elif 'AVI' in reference:
        type_bulletin = 'Avis'
    else:
        type_bulletin = 'Bulletin'

    date_pub = 'N/A'
    if 'revisions' in data and data['revisions']:
        date_pub = data['revisions'][0].get('revision_date', 'N/A')

    lien_web = f"https://www.cert.ssi.gouv.fr/alerte/{reference}/"

    resume = data.get('summary', 'N/A')
    if len(resume) > 300:
        resume = resume[:300] + "..."
    
    editeur = 'N/A'
    produit = 'N/A'
    versions = 'N/A'
    
    if 'affected_systems' in data and data['affected_systems']:
        premier_systeme = data['affected_systems'][0]
        if isinstance(premier_systeme, dict):
            vendor_info = premier_systeme.get('product', {}).get('vendor', {})
            if isinstance(vendor_info, dict):
                editeur = vendor_info.get('name', 'N/A')
            product_info = premier_systeme.get('product', {})
            if isinstance(product_info, dict):
                produit = product_info.get('name', 'N/A')
            versions = premier_systeme.get('description', 'N/A')
    resultats = []
    for cve in cves:
        ligne = {
            'Titre_ANSSI': titre,
            'Type': type_bulletin,
            'Date': date_pub,
            'CVE': cve,
            'CVSS': None,
            'Base_Severity': None,
            'CWE': None,
            'EPSS': None,
            'Lien': lien_web,
            'Description': resume,
            'Editeur': editeur,          
            'Produit': produit,
            'Versions_Affectees': versions, 
            'Reference_ANSSI': reference,
            'Fichier_Source': nom_fichier
        }
        resultats.append(ligne)
    return resultats

def traiter_fichiers(fichiers, limite=None):  
    if limite:
        fichiers = fichiers[:limite]
        print(f"\nMODE TEST: Limite a {limite} fichiers")
    print(f"\nTRAITEMENT DE {len(fichiers)} FICHIERS")
    print("=" * 60)
    toutes_lignes = []
    succes = 0
    echecs = 0
    
    for i, chemin in enumerate(fichiers, 1):
        nom_fichier = os.path.basename(chemin)
        print(f"\n[{i:3d}/{len(fichiers)}] {nom_fichier}")
        data = charger_fichier_json(chemin)
        if data is None:
            echecs += 1
            continue
        resultats = extraire_infos_fichier(data, nom_fichier)
        if resultats:
            toutes_lignes.extend(resultats)
            succes += 1
        else:
            echecs += 1
    if toutes_lignes:
        df = pd.DataFrame(toutes_lignes)
        
        print("\n" + "="*60)
        print("EXTRACTION REUSSIE")
        print("="*60)
        print(f"\nRESULTATS:")
        print(f"- Fichiers: {len(fichiers)}")
        print(f"- Succes: {succes}")
        print(f"- Echecs: {echecs}")
        print(f"- Lignes: {len(df)}")
        print(f"- Alertes: {df['Reference_ANSSI'].nunique()}")
        print(f"- CVE uniques: {df['CVE'].nunique()}")
        return df
    else:
        print("\nAucune donnee extraite")
        return pd.DataFrame()
def get_cvss_score(cve_id):
    time.sleep(1.5)
    try:
        url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            metrics = data.get('containers', {}).get('cna', {}).get('metrics', [])
            for metric in metrics:
                if 'cvssV3_1' in metric:
                    return metric['cvssV3_1'].get('baseScore', 'N/A')
                elif 'cvssV3_0' in metric:
                    return metric['cvssV3_0'].get('baseScore', 'N/A')
    except:
        pass
    return 'N/A'
def get_epss_score(cve_id):
    time.sleep(1.5)
    try:
        url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get('data'):
                return data['data'][0].get('epss', 'N/A')
    except:
        pass
    return 'N/A'

def enrichir_api_rapide(df):
    print("\nENRICHISSEMENT API")
    print("=" * 60)
    
    if df.empty or 'CVE' not in df.columns:
        print("Rien a enrichir")
        return df
    df_enrichi = df.copy()
    for col in ['CVSS', 'Base_Severity', 'CWE', 'EPSS']:
        if col not in df_enrichi.columns:
            df_enrichi[col] = 'N/A'
    cves_uniques = df_enrichi['CVE'].unique()
    print(f"{len(cves_uniques)} CVE a enrichir")
    cache = {}
    for i, cve in enumerate(cves_uniques, 1):
        print(f"[{i}/{len(cves_uniques)}] {cve}", end=' ')
        cvss = get_cvss_score(cve)
        epss = get_epss_score(cve)
        cache[cve] = {'CVSS': cvss, 'EPSS': epss}
        print(f"-> CVSS: {cvss}, EPSS: {epss}")

    for cve, valeurs in cache.items():
        mask = df_enrichi['CVE'] == cve
        df_enrichi.loc[mask, 'CVSS'] = valeurs['CVSS']
        df_enrichi.loc[mask, 'EPSS'] = valeurs['EPSS']
    print("\nENRICHISSEMENT TERMINE")
    return df_enrichi

def sauvegarder(df, nom_base):  
    if df.empty:
        print("Rien a sauvegarder")
        return
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    csv_file = f"{nom_base}_{timestamp}.csv"
    df.to_csv(csv_file, index=False, encoding='utf-8')
    print(f"CSV sauvegarde: {csv_file}")
    print(f"\nAPERÇU (3 lignes):")
    print(df[['CVE', 'Titre_ANSSI', 'CVSS', 'EPSS', 'Editeur']].head(3))
# PP
if __name__ == "__main__":
    
    print("=" * 70)
    print("PROJET ANSSI - FICHIERS SANS EXTENSION")
    print("=" * 70)
    fichiers = lister_tous_les_fichiers(DOSSIER_ALERTES)
    if not fichiers:
        print("\nAucun fichier trouve")
        exit()
    print(f"\n{len(fichiers)} fichiers disponibles")
    
    if len(fichiers) > 20:
        reponse = input(f"Traiter tous les {len(fichiers)} fichiers ? (o/n): ")
        if reponse.lower() != 'o':
            try:
                limite = int(input(f"Combien traiter (1-{len(fichiers)})? "))
                fichiers = fichiers[:limite]
            except:
                fichiers = fichiers[:10]
    df_base = traiter_fichiers(fichiers)
    if df_base.empty:
        print("\nArret: aucune donnee")
        exit()
    print("\nSAUVEGARDE BASE")
    sauvegarder(df_base, "anssi_base")
    print("\n" + "="*60)
    print("ENRICHISSEMENT API")
    print("="*60)
    cves_count = df_base['CVE'].nunique()
    print(f"\n{cves_count} CVE uniques trouvees")
    if cves_count > 0:
        print(f"Temps estime: ~{cves_count * 3 / 60:.1f} minutes")
        
        reponse = input("\nEnrichir avec API ? (o/n): ")
        if reponse.lower() == 'o':
            df_final = enrichir_api_rapide(df_base)
            
            print("\nSAUVEGARDE FINALE")
            sauvegarder(df_final, "anssi_final")
            
            print("\nSTATISTIQUES FINALES:")
            print(f"- Alertes: {df_final['Reference_ANSSI'].nunique()}")
            print(f"- CVE: {df_final['CVE'].nunique()}")
            
            if 'CVSS' in df_final.columns:
                try:
                    cvss_vals = pd.to_numeric(df_final['CVSS'], errors='coerce')
                    print(f"- CVSS moyen: {cvss_vals.mean():.2f}")
                    print(f"- CVSS max: {cvss_vals.max():.2f}")
                except:
                    pass
        else:
            print("\nExtraction sans enrichissement")
    else:
        print("Aucune CVE a enrichir")
    
    print("\n" + "="*70)
    print("PROGRAMME TERMINE !")
    print("="*70)
#%%  
df = pd.read_csv('anssi_final_20260107_2019.csv')
df
#%%
import smtplib
expediteur = "steeven.arnaud279@gmail.com"
destinataire = "steeven.arnaud972@gmail.com"
mot_de_passe_app = "rbuw fmkf gcvy dttc"

try:
    serveur = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    serveur.login(expediteur, mot_de_passe_app)
    message = f"""From: {expediteur}
To: {destinataire}
Subject: Security Alert Test

Hello,
This is a test from my Python program.
Does it work?
"""
    serveur.sendmail(expediteur, destinataire, message)
    serveur.quit()
    print("SUCCESS: Email envoye!")
except Exception as error:
    print(f"ERROR: {error}")