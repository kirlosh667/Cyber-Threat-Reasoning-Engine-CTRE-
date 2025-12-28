import random
import csv
from datetime import datetime, timedelta

# -----------------------------
# Normal traffic examples
# -----------------------------
normal_traffic = [
    "HTTP request to google.com",
    "DNS query to microsoft.com",
    "User logged into Office365",
    "Email sent via Outlook",
    "File downloaded from company portal"
]

# -----------------------------
# Attack traffic examples
# -----------------------------
attack_traffic = [
    "ALERT: IoT camera attempted SSH login",
    "ALERT: Multiple failed SSH login attempts",
    "ALERT: Suspicious DNS tunneling activity"
]

# -----------------------------
# Generate logs
# -----------------------------
start_time = datetime.now()
logs = []

for i in range(30):
    time = start_time + timedelta(minutes=i)

    if i in [10, 18, 25]:  # Inject attacks
        activity = random.choice(attack_traffic)
        status = "ATTACK"
    else:
        activity = random.choice(normal_traffic)
        status = "NORMAL"

    logs.append([time.strftime("%H:%M"), activity, status])

# -----------------------------
# Save to CSV
# -----------------------------
with open("network_logs.csv", "w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["Time", "Activity", "Status"])
    writer.writerows(logs)

print("✅ Synthetic network logs generated: network_logs.csv")
