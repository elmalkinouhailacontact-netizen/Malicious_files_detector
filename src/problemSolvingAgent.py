from pathlib import Path
import hashlib
import requests

#Analyse statique

#Extraction des données d'analyse
    
chemain = "data/exercices_ch1-2.pdf.exe"
file_info = {
    "name": "",
    "extension": "",
    "suffixes": [],
    "size": "",
    "hash": "",
    "signature": ""
}

file_path = Path(chemain)
file_info['name'] =  file_path.name
file_info['extension'] = file_path.suffix
file_info['suffixes'] = file_path.suffixes # -- List of extensions
file_info['size'] = file_path.stat().st_size


#Hash du fichier
def hash_file(chemain):
    sha256 = hashlib.sha256()
    
    with open(chemain, "rb") as f:
        while True:
            ligne = f.read(4096)
            
            if not ligne:
                break
            
            sha256.update(ligne)
            
    return sha256.hexdigest()


def check_hash(api_key):
    url = f"https://www.virustotal.com/api/v3/files/{hash_file("data/exercices_ch1-2.pdf")}"

    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        vt_data = response.json()
        report = vt_data['data']['attributes']['last_analysis_stats']

        #Classifier le rapport
        malicious = report['malicious']
        suspicious = report['suspicious']
        if malicious >= 5:
            print("absolute malicious")
        elif malicious >= 1 or   suspicious >= 1:
            print('needs further reveiw')
        else:
            print("Clean")


    elif response.status_code == 404:
        print("This hash was never seen")   

# test check hash
# check_hash("3ccb40f0ecb8ea129aa97b89c33cd690294baaf87dae2b13021184a76b6eca0c")

#Double extension check
danger_extensions = {".exe", ".bat", ".cmd", ".scr", ".vbs", ".js", ".ps1", ".msi"}
camouflage_extensions = {".pdf", ".docx", ".xlsx", ".txt", ".jpg", ".png", ".mp4", ".zip"}
def double_extension():
    suffixes = [s.lower() for s in file_info['suffixes']]
    print(suffixes)

    if len(suffixes) >= 2:
        extension_reel = suffixes[-1]
        secondary_extension = suffixes[len(suffixes)-1]
            


double_extension()

#Analyse heuristique
# def heuristic_analysis():
#     risk_score = 0
#     reasons = []

#     return risk_score, reasons

