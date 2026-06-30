from app.database import count_events, fetch_recent_events, init_db


def main():
    init_db()

    print(f"Total events: {count_events()}\n")

    for event in fetch_recent_events(limit=20):
        print(
            f"#{event['id']} | "
            f"{event['timestamp']} | "
            f"{event['event_type']} | "
            f"IP={event['ip']} | "
            f"user={event['username']} | "
            f"path={event['path']} | "
            f"status={event['status_code']}"
        )


if __name__ == "__main__":
    main()
