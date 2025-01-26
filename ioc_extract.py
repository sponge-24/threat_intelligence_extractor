import iocextract
import requests
from dotenv import load_dotenv
import os
load_dotenv()

def extract_and_analyze_iocs(content, api_key):
    """
    Extract IOCs from text, analyze hashes with VirusTotal, and attach metadata to malicious hashes.

    :param content: A string containing the text to extract IOCs from.
    :param api_key: VirusTotal API key.
    :return: A dictionary containing IOCs with metadata for malicious hashes.
    """
    # Step 1: Extract IOCs
    iocs = {
        "urls": list(set(iocextract.extract_urls(content, refang=True))),
        "md5": [{"hash": md5} for md5 in set(iocextract.extract_md5_hashes(content))],
        "sha1": [{"hash": sha1} for sha1 in set(iocextract.extract_sha1_hashes(content))],
        "sha256": [{"hash": sha256} for sha256 in set(iocextract.extract_sha256_hashes(content))],
        "sha512": [{"hash": sha512} for sha512 in set(iocextract.extract_sha512_hashes(content))],
        "emails": list(set(iocextract.extract_emails(content, refang=True))),
        "IP addresses": list(set(iocextract.extract_ipv4s(content, refang=True)))
    }

    # Step 2: Analyze hashes with VirusTotal and attach metadata
    for hash_type in ["md5", "sha1", "sha256", "sha512"]:
        for hash_entry in iocs[hash_type]:
            hash_value = hash_entry["hash"]
            print(f"Analyzing {hash_type.upper()} hash: {hash_value}")
            url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
            headers = {"x-apikey": api_key}
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                last_analysis_stats = attributes.get("last_analysis_stats", {})
                print(last_analysis_stats)
                # Attach metadata only if the hash is flagged as malicious
                if last_analysis_stats.get("malicious", 0) > 0:
                    hash_entry["metadata"] = {
                        "malicious": last_analysis_stats.get("malicious"),
                        "suspicious": last_analysis_stats.get("suspicious"),
                        "tags": attributes.get("tags", []),
                        "tlsh": attributes.get("tlsh"),
                        "file_type": attributes.get("type_description")
                    }

    return iocs

if __name__ == "__main__":
    # Example input text
    text = """The APT33 group, suspected to be from Iran, has launched a new campaign targeting 
    the energy sector organizations. 
    The attack utilizes Shamoon malware, known for its destructive capabilities. The threat 
    actor exploited a vulnerability in the network perimeter to gain initial access. 
    The malware was delivered via spear-phishing emails containing a malicious 
    attachment. The malware's behavior was observed communicating with IP address 
    192.168.1.1 and domain example.com. The attack also involved lateral movement using 
    PowerShell scripts."""


    # Extract, analyze, and print the final IOCs with metadata for malicious hashes
    iocs = extract_and_analyze_iocs(text, api_key=os.getenv("api_key"))
    print(iocs)
