import re


def extract_intel(text: str):
    upi_pattern = r"\b[\w.-]+@[\w.-]+\b"
    bank_pattern = r"\b\d{9,18}\b"
    ifsc_pattern = r"\b[A-Z]{4}0[A-Z0-9]{6}\b"
    url_pattern = r"https?://[^\s]+"
    phone_pattern = r"(?:\+?91[-\s]?)?[6-9]\d{9}\b"

    upis = [u for u in set(re.findall(upi_pattern, text)) if "http" not in u.lower()]
    return {
        "upi_ids": upis,
        "bank_accounts": list(set(re.findall(bank_pattern, text))),
        "ifsc_codes": list(set(re.findall(ifsc_pattern, text))),
        "phishing_urls": list(set(re.findall(url_pattern, text))),
        "phone_numbers": list(set(re.findall(phone_pattern, text))),
        "wallet_addresses": []
    }
