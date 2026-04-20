import csv
import random
import time
from datetime import datetime

events = [
    "FAILED_LOGIN",
    "SUCCESS_LOGIN",
    "MALWARE_DETECTED",
    "SUSPICIOUS_IP",
    "BRUTE_FORCE_ATTEMPT"
]

while True:
    event = random.choice(events)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open("security_logs.csv", "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, event])

    print("New event generated:", event)
    time.sleep(5)

