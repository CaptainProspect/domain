import datetime
import requests
import whois
import pandas as pd
import time
import os
import re
import schedule  # <--- On importe la librairie schedule

WHOIS_FOLDER = "whois_project2"

def get_yesterday_afnic_url():
    """
    Calcule la date d'hier au format YYYYMMDD,
    puis construit l'URL AFNIC correspondante.
    Ex: 20250317_CREA_fr.txt pour le 17 mars 2025.
    """
    yesterday = datetime.datetime.today() - datetime.timedelta(days=1)
    date_str = yesterday.strftime('%Y%m%d')
    url = f"https://www.afnic.fr/wp-media/ftp/domaineTLD_Afnic/{date_str}_CREA_fr.txt"
    return url, date_str

def download_afnic_file():
    """
    Télécharge le fichier AFNIC d'hier et l'enregistre
    sous whois_project2/afnic_domains.txt
    """
    url, date_str = get_yesterday_afnic_url()
    print(f"Téléchargement du fichier AFNIC : {url}")
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        os.makedirs(WHOIS_FOLDER, exist_ok=True)
        afnic_path = os.path.join(WHOIS_FOLDER, "afnic_domains.txt")
        with open(afnic_path, "wb") as f:
            f.write(response.content)
        print("Fichier AFNIC téléchargé avec succès.")
    except Exception as e:
        print(f"Erreur lors du téléchargement : {e}")

def get_domains_after_bof():
    """
    Lit whois_project2/afnic_domains.txt et ignore toutes les lignes
    jusqu'à #BOF. Ensuite, récupère TOUS les noms de domaine valides.
    """
    afnic_path = os.path.join(WHOIS_FOLDER, "afnic_domains.txt")
    valid_domains = []
    start_collecting = False

    if not os.path.exists(afnic_path):
        print(f"Erreur : Le fichier {afnic_path} n'existe pas.")
        return valid_domains

    with open(afnic_path, "r") as f:
        for line in f:
            line = line.strip()

            if line == "#BOF":
                start_collecting = True
                continue

            if not start_collecting:
                continue

            if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", line):
                valid_domains.append(line)

    return valid_domains

def get_titulaire_info(domain):
    """
    Fait un WHOIS sur le domaine et récupère UNIQUEMENT
    les NIC-HDL qui commencent par 'CTC'.
    Filtre pour garder uniquement les téléphones
    qui commencent par +33.6 / +33.06 / +33.7 / +33.07.
    Retourne un dict si OK, ou None sinon.
    """
    try:
        w = whois.whois(domain)
        raw_text = w.text if w.text else ""

        creation_date = w.creation_date if w.creation_date else "Non disponible"
        expiration_date = w.expiration_date if w.expiration_date else "Non disponible"

        # Trouver tous les NIC-HDL
        nic_hdl_list = re.findall(r"nic-hdl:\s+([A-Z0-9-]+)", raw_text)

        name_set = set()
        email_set = set()
        phone_set = set()

        for nic_hdl in nic_hdl_list:
            if not nic_hdl.startswith("CTC"):
                continue

            match = re.search(rf"nic-hdl:\s+{nic_hdl}.*?(?=nic-hdl:|$)", raw_text, re.DOTALL)
            if not match:
                continue
            block = match.group(0)

            name_m = re.search(r"contact:\s+(.*)", block)
            email_m = re.search(r"e-mail:\s+(.*)", block)
            phone_m = re.search(r"phone:\s+(.*)", block)

            if name_m:
                name_set.add(name_m.group(1))
            if email_m:
                email_set.add(email_m.group(1))

            # Vérifier +33.6 / +33.06 / +33.7 / +33.07
            if phone_m:
                phone_number = phone_m.group(1)
                if re.match(r"^\+33\.?0?(6|7)", phone_number):
                    phone_set.add(phone_number)

        # Besoin d'au moins un Nom et un Téléphone
        if not name_set or not phone_set:
            return None

        row = {
            "Domaine": domain,
            "Date de création": creation_date,
            "Date d'expiration": expiration_date,
            "Nom du titulaire": " | ".join(name_set),
            "Mail du titulaire": " | ".join(email_set) if email_set else "Non disponible",
            "Téléphone du titulaire": " | ".join(phone_set)
        }

        return row

    except Exception as e:
        return None

def run_whois_scraper():
    """
    1. Télécharge le fichier AFNIC (date d'hier)
    2. Récupère tous les domaines après #BOF
    3. Pour chaque domaine, extrait le titulaire (CTC)
    4. Filtre tel +33.6/+33.7
    5. Sauvegarde dans whois_project2/Lead_<dateStr>.csv
    """
    # 1. Télécharger
    download_afnic_file()

    # 2. Extraire les domaines
    domains = get_domains_after_bof()
    if not domains:
        print("Erreur : Aucun domaine valide après #BOF.")
        return

    # 3. Récupérer infos
    results = []
    for domain in domains:
        info = get_titulaire_info(domain)
        if info:
            results.append(info)
            print(f"Processed: {domain}")
        else:
            print(f"Skipped: {domain} (pas de titulaire ou tel valide)")
        time.sleep(1)

    if not results:
        print("Aucun domaine ne correspond aux critères.")
        return

    # 4. Nom de fichier : Lead_YYYYMMDD.csv (hier)
    yesterday = datetime.datetime.today() - datetime.timedelta(days=1)
    date_str = yesterday.strftime('%Y%m%d')
    output_file = os.path.join(WHOIS_FOLDER, f"Lead_{date_str}.csv")

    df = pd.DataFrame(results)
    df.to_csv(output_file, index=False, encoding="utf-8")
    print(f"Fichier créé : {output_file}")

def daily_job():
    # Fonction appelée chaque jour à 04:00
    run_whois_scraper()

if __name__ == "__main__":
    # On programme l'exécution quotidienne à 04:00
    schedule.every().day.at("04:00").do(daily_job)

    print("Script démarré. Le scraping s'exécutera chaque jour à 04:00.")
    # Boucle infinie pour exécuter la tâche planifiée
    while True:
        schedule.run_pending()
        time.sleep(60)
