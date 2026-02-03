import re


def extract_intel(text: str):
    upi_pattern = r"\b[\w.-]+@[\w.-]+\b"
    bank_pattern = r"\b\d{9,18}\b"
    ifsc_pattern = r"\b[A-Z]{4}0[A-Z0-9]{6}\b"
    url_pattern = r"https?://[^\s]+"

    return {
        "upi_ids": list(set(re.findall(upi_pattern, text))),
        "bank_accounts": list(set(re.findall(bank_pattern, text))),
        "ifsc_codes": list(set(re.findall(ifsc_pattern, text))),
        "phishing_urls": list(set(re.findall(url_pattern, text))),
        "wallet_addresses": []
    }
