import csv
import os
from datetime import datetime

FILE_PATH = "data/scam_logs.csv"

def log_scam(session_id, intel, confidence):
    file_exists = os.path.isfile(FILE_PATH)

    with open(FILE_PATH, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow([
                "timestamp", "session_id", "upi_ids",
                "bank_accounts", "ifsc_codes",
                "phishing_urls", "confidence"
            ])

        writer.writerow([
            datetime.utcnow().isoformat(),
            session_id,
            ",".join(intel.get("upi_ids", [])),
            ",".join(intel.get("bank_accounts", [])),
            ",".join(intel.get("ifsc_codes", [])),
            ",".join(intel.get("phishing_urls", [])),
            confidence
        ])
