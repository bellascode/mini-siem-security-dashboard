from app.database import count_alerts, fetch_recent_alerts, init_db


def main():
    init_db()

    print(f"Total alerts: {count_alerts()}\n")

    for alert in fetch_recent_alerts(limit=20):
        print(
            f"#{alert['id']} | "
            f"{alert['timestamp']} | "
            f"{alert['severity']} | "
            f"{alert['alert_type']} | "
            f"IP={alert['ip']} | "
            f"evidence={alert['evidence_count']}"
        )

        print(f"    {alert['description']}\n")


if __name__ == "__main__":
    main()