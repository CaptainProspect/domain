import datetime
import requests
import whois
import pandas as pd
import time
import os
import re

WHOIS_FOLDER = "whois_project2"

def get_yesterday_afnic_url():
    yesterday = datetime.datetime.today() - datetime.timedelta(days=1)
    date_str = yesterday.strftime('%Y%m%d')
    url = f"https://www.afnic.fr/wp-media/ftp/domaineTLD_Afnic/{date_str}_CREA_fr.txt"
    return url, date_str

def download_afnic_file():
    url, date_str = get_yesterday_afnic_url()
    print(f"[INFO] Téléchargement du fichier AFNIC : {url}")
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        os.makedirs(WHOIS_FOLDER, exist_ok=True)
        afnic_path = os.path.join(WHOIS_FOLDER, "afnic_domains.txt")
        with open(afnic_path, "wb") as f:
            f.write(response.content)
        print(f"[SUCCESS] Fichier téléchargé : {afnic_path}")
    except Exception as e:
        print(f"[ERROR] Échec du téléchargement : {e}")

def get_domains_after_bof():
    afnic_path = os.path.join(WHOIS_FOLDER, "afnic_domains.txt")
    valid_domains = []
    start_collecting = False

    if not os.path.exists(afnic_path):
        print(f"[ERROR] Fichier introuvable : {afnic_path}")
        return valid_domains

    with open(afnic_path, "r") as f:
        for line in f:
            line = line.strip()
            if line == "#BOF":
                start_collecting = True
                continue
            if start_collecting and re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", line):
                valid_domains.append(line)
            if len(valid_domains) >= 50:  # Limite à 50 domaines
                break

    print(f"[INFO] {len(valid_domains)} domaines trouvés (limite 50).")
    return valid_domains

def get_titulaire_info(domain):
    """
    Récupère les informations WHOIS et formate correctement les données.
    """
    try:
        print(f"[INFO] WHOIS lookup pour : {domain}")
        w = whois.whois(domain)
        raw_text = w.text if w.text else ""

        creation_date = str(w.creation_date[0]) if isinstance(w.creation_date, list) else str(w.creation_date)
        expiration_date = str(w.expiration_date[0]) if isinstance(w.expiration_date, list) else str(w.expiration_date)

        nic_hdl_list = re.findall(r"nic-hdl:\s+([A-Z0-9-]+)", raw_text)

        name_set, email_set, phone_set = set(), set(), set()

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
                name_set.add(name_m.group(1).strip())
            if email_m:
                email_set.add(email_m.group(1).strip())
            if phone_m and re.match(r"^\+33\.?0?(6|7)", phone_m.group(1).strip()):
                phone_set.add(phone_m.group(1).strip())

        if not name_set and not phone_set:
            print(f"[WARNING] {domain} ignoré (pas de titulaire ou tel valide)")
            return None

        return {
            "Nom de domaine": domain,
            "Titulaire": " | ".join(name_set) if name_set else "Non disponible",
            "Email": " | ".join(email_set) if email_set else "Non disponible",
            "Téléphone": " | ".join(phone_set) if phone_set else "Non disponible",
            "Date de création": creation_date if creation_date != "None" else "Non disponible",
            "Date d'expiration": expiration_date if expiration_date != "None" else "Non disponible"
        }

    except Exception as e:
        print(f"[ERROR] Échec WHOIS {domain} : {e}")
        return None

def run_whois_scraper():
    print("🔄 [START] Lancement du scraping AFNIC...")
    download_afnic_file()

    domains = get_domains_after_bof()
    if not domains:
        print("[ERROR] Aucun domaine trouvé après #BOF.")
        return

    results = []
    for domain in domains:
        info = get_titulaire_info(domain)
        if info:
            results.append(info)
            print(f"✅ {domain} ajouté")
        time.sleep(1)

    if not results:
        print("[ERROR] Aucun domaine ne correspond aux critères.")
        return

    yesterday = datetime.datetime.today() - datetime.timedelta(days=1)
    date_str = yesterday.strftime('%Y%m%d')
    output_file = os.path.join(WHOIS_FOLDER, f"Lead_{date_str}.csv")

    df = pd.DataFrame(results)

    print("\n📊 [INFO] Aperçu des 5 premières lignes :")
    print(df.head())

    df.to_csv(output_file, index=False, encoding="utf-8")
    print(f"✅ [SUCCESS] Fichier CSV sauvegardé : {output_file}")
    print("🎉 [END] Scraping terminé.")

if __name__ == "__main__":
    run_whois_scraper()
