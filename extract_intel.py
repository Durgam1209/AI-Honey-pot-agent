import re

_NON_DIGIT = re.compile(r"\D+")
_NON_ALNUM = re.compile(r"[^A-Z0-9]+")

def _normalize_bank_account(raw: str) -> str | None:
    digits = _NON_DIGIT.sub("", raw)
    if 9 <= len(digits) <= 18:
        return digits
    return None

def _normalize_ifsc(raw: str) -> str | None:
    cleaned = _NON_ALNUM.sub("", raw.upper())
    if len(cleaned) != 11:
        return None
    # IFSC format: 4 letters + 0 + 6 alnum, allow 'O' in place of zero
    if cleaned[4] == "O":
        cleaned = cleaned[:4] + "0" + cleaned[5:]
    if re.fullmatch(r"[A-Z]{4}0[A-Z0-9]{6}", cleaned):
        return cleaned
    return None

def _normalize_upi(raw: str) -> str:
    # Strip common trailing punctuation and whitespace
    return raw.strip().strip(".,;:()[]{}<>").lower()

def _normalize_phone(raw: str) -> str | None:
    digits = _NON_DIGIT.sub("", raw)
    # Accept 10-digit local or 12-digit with country code 91
    if len(digits) == 12 and digits.startswith("91"):
        return f"+{digits}"
    if len(digits) == 10:
        return f"+91{digits}"
    return None


def extract_intel(text: str):
    upi_pattern = r"\b[\w.-]+@[\w.-]+\b"
    bank_pattern = r"\b(?:\d[ -]?){9,20}\b"
    ifsc_pattern = r"\b[A-Z0-9][A-Z0-9\s-]{8,20}[A-Z0-9]\b"
    url_pattern = r"https?://[^\s]+"
    phone_pattern = r"(?:\+?91[-\s]?)?[6-9]\d{9}\b"

    upis_raw = [u for u in re.findall(upi_pattern, text) if "http" not in u.lower()]
    upis = {_normalize_upi(u) for u in upis_raw}

    bank_candidates = re.findall(bank_pattern, text)
    bank_accounts = set()
    for candidate in bank_candidates:
        normalized = _normalize_bank_account(candidate)
        if normalized:
            bank_accounts.add(normalized)

    ifsc_candidates = re.findall(ifsc_pattern, text.upper())
    ifsc_codes = set()
    for candidate in ifsc_candidates:
        normalized = _normalize_ifsc(candidate)
        if normalized:
            ifsc_codes.add(normalized)

    phones_raw = re.findall(phone_pattern, text)
    phone_numbers = set()
    for raw in phones_raw:
        normalized = _normalize_phone(raw)
        if normalized:
            phone_numbers.add(normalized)

    return {
        "upi_ids": sorted(upis),
        "bank_accounts": sorted(bank_accounts),
        "ifsc_codes": sorted(ifsc_codes),
        "phishing_urls": sorted(set(re.findall(url_pattern, text))),
        "phone_numbers": sorted(phone_numbers),
        "wallet_addresses": []
    }
