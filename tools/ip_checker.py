import os
import requests
from dotenv import load_dotenv

load_dotenv()

def check_ip_reputation(ip_address: str) -> dict:
    """
    Checks the reputation of an IP address using the VirusTotal API.
    Returns threat scores, owner info, and malicious flags.

    Args:
        ip_address: The IP address to check (e.g., '8.8.8.8')
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"error": "VIRUSTOTAL_API_KEY not set in .env file"}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "ip": ip_address,
            "owner": attributes.get("as_owner", "Unknown"),
            "country": attributes.get("country", "Unknown"),
            "malicious_votes": stats.get("malicious", 0),
            "harmless_votes": stats.get("harmless", 0),
            "suspicious_votes": stats.get("suspicious", 0),
            "reputation_score": attributes.get("reputation", 0),
            "threat_verdict": "MALICIOUS" if stats.get("malicious", 0) > 0 else "CLEAN"
        }

    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP error: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}
