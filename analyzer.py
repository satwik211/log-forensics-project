
from collections import defaultdict

# Count requests per IP
ip_counts = defaultdict(int)

with open("logs.txt", "r") as f:
    for line in f:
        parts = line.split()
        if len(parts) > 0:
            ip = parts[0]
            ip_counts[ip] += 1

# Detect suspicious IPs (example: >10 requests)
print("Suspicious IPs (more than 10 requests):")
for ip, count in ip_counts.items():
    if count > 10:
        print(ip, count)

# Detect error responses (4xx or 5xx)
print("\nErrors detected (4xx/5xx):")
for line in open("logs.txt"):
    parts = line.split()
    if len(parts) > 8:
        status = parts[8]
        if status.startswith("4") or status.startswith("5"):
            print(parts[0], status)
