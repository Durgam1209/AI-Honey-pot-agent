from collections import defaultdict
import time

conversations = defaultdict(lambda: {
    "history": [],
    "start_time": time.time(),
    "extracted": {
        "bank_accounts": [],
        "upi_ids": [],
        "phishing_urls": [],
        "wallet_addresses": []
    }
})
