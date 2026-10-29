

import csv
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path


def check_repeated_failures(rows):
    """Report repeated failures and successful logins after those failures."""
    recent_failures = {}

    for row in rows:
        timestamp = row["timestamp"]
        username = row["username"]
        ip = row["ip_address"]
        status = row["status"]
        current_time = datetime.fromisoformat(timestamp)
        key = (ip, username)

        if key not in recent_failures:
            recent_failures[key] = deque()

        failures = recent_failures[key]
        cutoff = current_time - timedelta(minutes=5)

        while failures and failures[0] < cutoff:
            failures.popleft()

        if status == "failed":
            failures.append(current_time)

            if len(failures) == 5:
                print(
                    f"Alert: 5 failures within 5 minutes for {username} from {ip}"
                )
        elif status == "success":
            if len(failures) >= 5:
                print(
                    f"Alert: Successful login after repeated failures for "
                    f"{username} from {ip}"
                )
            failures.clear()


def check_suspicious_ips(rows):
    """Report IPs targeting many usernames in a burst or across the log."""
    recent_attempts = {}
    usernames_by_ip = {}
    burst_alerted_ips = set()

    for row in rows:
        timestamp = datetime.fromisoformat(row["timestamp"])
        ip = row["ip_address"]
        username = row["username"]
        usernames_by_ip.setdefault(ip, set()).add(username)
        attempts = recent_attempts.setdefault(ip, deque())
        cutoff = timestamp - timedelta(minutes=5)

        while attempts and attempts[0][0] < cutoff:
            attempts.popleft()

        attempts.append((timestamp, username))
        unique_usernames = {attempt[1] for attempt in attempts}

        if len(unique_usernames) > 5 and ip not in burst_alerted_ips:
            print(
                f"Alert: IP {ip} attempted logins "
                f"for {len(unique_usernames)} unique usernames within 5 minutes."
            )
            burst_alerted_ips.add(ip)

    for ip, usernames in usernames_by_ip.items():
        if len(usernames) > 5:
            print(
                f"Alert: IP {ip} attempted logins for "
                f"{len(usernames)} unique usernames across the log."
            )

def analyze_logins(rows):
    """Run login checks and return per-IP login statistics."""
    rows = sorted(
        rows,
        key=lambda row: datetime.fromisoformat(row["timestamp"])
    )
    ip_log = {}

    for row in rows:
        timestamp = row["timestamp"]
        username = row["username"]
        ip = row["ip_address"]
        status = row["status"]

        if ip not in ip_log:
            ip_log[ip] = {
                "failed_attempts": 0,
                "successful_attempts": 0,
                "last_failed_timestamp": None,
                "last_successful_timestamp": None,
                "usernames": set(),
            }

        ip_log[ip]["usernames"].add(username)

        if status == "failed":
            ip_log[ip]["failed_attempts"] += 1
            ip_log[ip]["last_failed_timestamp"] = timestamp
        elif status == "success":
            ip_log[ip]["successful_attempts"] += 1
            ip_log[ip]["last_successful_timestamp"] = timestamp

    check_repeated_failures(rows)
    check_suspicious_ips(rows)
    return ip_log


def main():
    file_path = Path(__file__).parent / "data" / "sample_logins.csv"

    with file_path.open(newline="", encoding="utf-8-sig") as file:
        rows = list(csv.DictReader(file))

    for line_number, row in enumerate(rows, start=2):
        row["status"] = row["status"].strip().lower()

        if row["status"] not in {"failed", "success"}:
            raise ValueError(
                f"Invalid status on CSV line {line_number}: "
                f"{row['status']!r}"
            )

    ip_log = analyze_logins(rows)

    for ip, details in ip_log.items():
        print(f"\nIP: {ip}")
        print(f"  Failed attempts: {details['failed_attempts']}")
        print(f"  Successful attempts: {details['successful_attempts']}")
        print(f"  Unique usernames: {len(details['usernames'])}")

    


if __name__ == "__main__":
    main()
