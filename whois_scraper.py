import datetime
import requests
import whois
import pandas as pd
import time
import os
import re
# import schedule  # seulement si tu l'utilises vraiment

WHOIS_FOLDER = "whois_project2"

def get_yesterday_afnic_url():
    print("Calcul de la date d'hier pour construire l'URL AFNIC...")
    yesterday = datetime.datetime.today() - datetime.timedelta(days=1)
    date_str = yesterday.strftime('%Y%m%d')
    url = f"https://www.afnic.fr/wp-media/ftp/domaineTLD_Afnic/{date_str}_CREA_fr.txt"
    print(f"URL calculée : {url}")
    return url, date_str

def download_afnic_file():
    print("Téléchargement du fichier AFNIC d'hier...")
    url, date_str = get_yesterday_afnic_url()
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        os.makedirs(WHOIS_FOLDER, exist_ok=True)
        afnic_path = os.path.join(WHOIS_FOLDER, "afnic_domains.txt")
        with open(afnic_path, "wb") as f:
            f.write(response.content)
        print(f"Fichier AFNIC téléchargé avec succès dans {afnic_path}.")
    except Exception as e:
        print(f"Erreur lors du téléchargement : {e}")

def get_domains_after_bof():
    print("Lecture du fichier et récupération des domaines après #BOF...")
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
            # Regex pour valider un nom de domaine
            if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", line):
                valid_domains.append(line)

    print(f"{len(valid_domains)} domaines trouvés après #BOF.")
    return valid_domains

def get_titulaire_info(domain):
    try:
        print(f"WHOIS pour le domaine : {domain}")
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

        if not name_set or not phone_set:
            print(f"Pas de titulaire ou téléphone valide pour {domain}")
            return None

        return {
            "Domaine": domain,
            "Date de création": creation_date,
            "Date d'expiration": expiration_date,
            "Nom du titulaire": " | ".join(name_set),
            "Mail du titulaire": " | ".join(email_set) if email_set else "Non disponible",
            "Téléphone du titulaire": " | ".join(phone_set)
        }
    except Exception as e:
        print(f"Erreur WHOIS pour {domain} : {e}")
        return None

def run_whois_scraper():
    print("=== Début de run_whois_scraper() ===")
    download_afnic_file()

    domains = get_domains_after_bof()
    if not domains:
        print("Aucun domaine valide après #BOF.")
        return

    results = []
    for domain in domains:
        info = get_titulaire_info(domain)
        if info:
            results.append(info)
            print(f"Processed: {domain}")
        else:
            print(f"Skipped: {domain}")
        time.sleep(1)  # Petit délai pour éviter tout blocage WHOIS

    if not results:
        print("Aucun domaine ne correspond aux critères.")
        return

    # Créer le CSV
    yesterday = datetime.datetime.today() - datetime.timedelta(days=1)
    date_str = yesterday.strftime('%Y%m%d')
    output_file = os.path.join(WHOIS_FOLDER, f"Lead_{date_str}.csv")

    df = pd.DataFrame(results)
    df.to_csv(output_file, index=False, encoding="utf-8")
    print(f"Fichier créé : {output_file}")
    print("=== Fin de run_whois_scraper() ===")

if __name__ == "__main__":
    # Lancement direct
    print("Script whois_scraper.py lancé...")
    run_whois_scraper()
