import csv
from datetime import datetime, timedelta
from pathlib import Path


# Detection settings.
FAILURE_THRESHOLD = 5
ACCOUNT_THRESHOLD = 5
WINDOW_MINUTES = 10


def load_logs(file_path):
    """Read, check, and sort login records."""
    events = []

    required_columns = {
        "timestamp",
        "username",
        "ip_address",
        "result"
    }

    # utf-8-sig also handles CSV files saved with a UTF-8 marker.
    with open(file_path, newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)

        # Check that the CSV has all required column names.
        columns = set(reader.fieldnames or [])
        missing_columns = required_columns - columns

        if missing_columns:
            missing = ", ".join(sorted(missing_columns))
            raise ValueError(f"Missing CSV columns: {missing}")

        # Start at 2 because the header occupies the first line.
        for row_number, row in enumerate(reader, start=2):
            event = {}

            # Remove extra spaces and check for missing values.
            for column in required_columns:
                value = row.get(column)

                if value is None or not value.strip():
                    raise ValueError(
                        f"Record {row_number}: missing {column}."
                    )

                event[column] = value.strip()

            event["result"] = event["result"].lower()

            if event["result"] not in ("success", "failure"):
                raise ValueError(
                    f"Record {row_number}: result must be "
                    "'success' or 'failure'."
                )

            try:
                event["timestamp"] = datetime.fromisoformat(
                    event["timestamp"]
                )
            except ValueError:
                raise ValueError(
                    f"Record {row_number}: invalid timestamp. "
                    "Use a format like 2026-10-12T10:00:00."
                ) from None

            # This version expects timestamps without timezone offsets.
            # All records must use the same time basis.
            if event["timestamp"].tzinfo is not None:
                raise ValueError(
                    f"Record {row_number}: use timestamps without "
                    "timezone offsets for this version."
                )

            events.append(event)

    # Process records in time order, even if the CSV is out of order.
    events.sort(key=get_event_time)

    return events


def get_event_time(event):
    """Provide the timestamp used when sorting records."""
    return event["timestamp"]


def display_logs(events):
    """Print the records supporting an alert."""
    for event in events:
        timestamp = event["timestamp"].isoformat()

        print(
            f"  {timestamp} | "
            f"{event['username']} | "
            f"{event['ip_address']} | "
            f"{event['result']}"
        )


def count_failed_logins(events):
    """Count total failures for each account."""
    failure_counts = {}

    for event in events:
        if event["result"] == "failure":
            username = event["username"]

            if username not in failure_counts:
                failure_counts[username] = 0

            failure_counts[username] += 1

    return failure_counts


def create_alert(rule, target, summary, evidence):
    """Create a consistent alert with a score and investigation step."""

    # Fixed scores make our first scoring system easy to explain.
    risk_settings = {
        "Possible brute force": {
            "score": 50,
            "reason": "Repeated failures against one account.",
            "next_step": (
                "Check whether the account owner recognizes the "
                "attempts and review the source IP addresses."
            )
        },
        "Possible password spraying": {
            "score": 70,
            "reason": "One IP failed against multiple accounts.",
            "next_step": (
                "Check whether the IP belongs to an authorized "
                "service and look for successful logins."
            )
        },
        "Success after repeated failures": {
            "score": 90,
            "reason": (
                "A successful login followed repeated failures "
                "for the same account from the same IP."
            ),
            "next_step": (
                "Verify the successful login with the account "
                "owner and review subsequent account activity."
            )
        }
    }

    settings = risk_settings[rule]
    score = settings["score"]

    if score >= 70:
        risk_level = "High"
    elif score >= 40:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "rule": rule,
        "target": target,
        "summary": summary,
        "risk_score": score,
        "risk_level": risk_level,
        "risk_reason": settings["reason"],
        "next_step": settings["next_step"],
        "evidence": evidence
    }


def detect_brute_force(events):
    """Find repeated failures for one account within ten minutes."""
    alerts = []
    alerted_users = set()

    for start_event in events:
        if start_event["result"] != "failure":
            continue

        username = start_event["username"]

        # This version reports one brute-force alert per account.
        if username in alerted_users:
            continue

        start_time = start_event["timestamp"]
        end_time = start_time + timedelta(minutes=WINDOW_MINUTES)
        evidence = []

        for event in events:
            if (
                event["username"] == username
                and event["result"] == "failure"
                and start_time <= event["timestamp"] <= end_time
            ):
                evidence.append(event)

        if len(evidence) >= FAILURE_THRESHOLD:
            alert = create_alert(
                rule="Possible brute force",
                target=username,
                summary=(
                    f"{len(evidence)} failed logins for {username} "
                    f"within {WINDOW_MINUTES} minutes."
                ),
                evidence=evidence
            )

            alerts.append(alert)
            alerted_users.add(username)

    return alerts


def detect_password_spraying(events):
    """Find one IP failing against several different accounts."""
    alerts = []
    alerted_ips = set()

    for start_event in events:
        if start_event["result"] != "failure":
            continue

        ip_address = start_event["ip_address"]

        # This version reports one spraying alert per IP.
        if ip_address in alerted_ips:
            continue

        start_time = start_event["timestamp"]
        end_time = start_time + timedelta(minutes=WINDOW_MINUTES)

        evidence = []
        targeted_users = set()

        for event in events:
            if (
                event["ip_address"] == ip_address
                and event["result"] == "failure"
                and start_time <= event["timestamp"] <= end_time
            ):
                evidence.append(event)
                targeted_users.add(event["username"])

        if len(targeted_users) >= ACCOUNT_THRESHOLD:
            alert = create_alert(
                rule="Possible password spraying",
                target=ip_address,
                summary=(
                    f"{ip_address} failed against "
                    f"{len(targeted_users)} different accounts "
                    f"within {WINDOW_MINUTES} minutes."
                ),
                evidence=evidence
            )

            alerts.append(alert)
            alerted_ips.add(ip_address)

    return alerts


def detect_success_after_failures(events):
    """Find a success after failures for the same account and IP."""
    alerts = []

    # Each pair contains an account and an IP address.
    alerted_pairs = set()

    for success_event in events:
        if success_event["result"] != "success":
            continue

        username = success_event["username"]
        ip_address = success_event["ip_address"]
        pair = (username, ip_address)

        if pair in alerted_pairs:
            continue

        success_time = success_event["timestamp"]

        # Look BACK ten minutes from the successful login.
        start_time = success_time - timedelta(minutes=WINDOW_MINUTES)
        failures = []

        for event in events:
            if (
                event["username"] == username
                and event["ip_address"] == ip_address
                and event["result"] == "failure"
                and start_time <= event["timestamp"] < success_time
            ):
                failures.append(event)

        if len(failures) >= FAILURE_THRESHOLD:
            # Include both the failures and the successful login.
            evidence = failures + [success_event]

            alert = create_alert(
                rule="Success after repeated failures",
                target=f"{username} from {ip_address}",
                summary=(
                    f"{username} logged in successfully from "
                    f"{ip_address} after {len(failures)} failures "
                    f"in the preceding {WINDOW_MINUTES} minutes."
                ),
                evidence=evidence
            )

            alerts.append(alert)
            alerted_pairs.add(pair)

    return alerts


def get_alert_score(alert):
    """Provide the score used when sorting alerts."""
    return alert["risk_score"]


def analyze_logs(events):
    """Run all three rules and put higher-risk alerts first."""
    alerts = []

    # extend() adds the items from one list into another list.
    alerts.extend(detect_brute_force(events))
    alerts.extend(detect_password_spraying(events))
    alerts.extend(detect_success_after_failures(events))

    alerts.sort(key=get_alert_score, reverse=True)

    return alerts


def display_alerts(alerts):
    """Print alert details, evidence, and investigation guidance."""
    if not alerts:
        print("\nNo alerts matched the three detection rules.")
        return

    for number, alert in enumerate(alerts, start=1):
        print("\n" + "=" * 60)
        print(f"ALERT {number}: {alert['rule']}")
        print(f"Target: {alert['target']}")
        print(
            f"Risk: {alert['risk_level']} "
            f"({alert['risk_score']}/100)"
        )
        print(f"Summary: {alert['summary']}")
        print(f"Scoring reason: {alert['risk_reason']}")

        print("Evidence:")
        display_logs(alert["evidence"])

        print(f"Suggested investigation: {alert['next_step']}")


def main():
    """Load the file, analyze the records, and display results."""
    log_path = Path(__file__).parent / "sample_logs.csv"

    try:
        events = load_logs(log_path)
    except (OSError, ValueError, UnicodeError, csv.Error) as error:
        print(f"Could not load logs: {error}")
        return

    print("SENTINELLAB")
    print(f"Loaded records: {len(events)}")
    print("Failed logins:", count_failed_logins(events))

    alerts = analyze_logs(events)

    print(f"Total alerts: {len(alerts)}")
    display_alerts(alerts)


# Run main() when this file is executed directly.
# Importing these functions into a future dashboard won't run main().
if __name__ == "__main__":
    main()
