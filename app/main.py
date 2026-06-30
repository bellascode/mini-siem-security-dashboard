from flask import Flask, render_template

from app.database import (
    init_db,
    count_events,
    count_alerts,
    fetch_recent_events,
    fetch_recent_alerts,
    fetch_top_ips,
    fetch_alert_counts_by_type,
    fetch_event_counts_by_type,
)


app = Flask(__name__)


@app.route("/")
def dashboard():
    """
    Main dashboard page.
    """
    init_db()

    return render_template(
        "index.html",
        total_events=count_events(),
        total_alerts=count_alerts(),
        top_ips=fetch_top_ips(limit=5),
        alert_counts=fetch_alert_counts_by_type(),
        event_counts=fetch_event_counts_by_type(),
        recent_alerts=fetch_recent_alerts(limit=5),
    )


@app.route("/events")
def events():
    """
    Shows recent parsed events.
    """
    init_db()

    return render_template(
        "events.html",
        events=fetch_recent_events(limit=100),
    )


@app.route("/alerts")
def alerts():
    """
    Shows recent generated alerts.
    """
    init_db()

    return render_template(
        "alerts.html",
        alerts=fetch_recent_alerts(limit=100),
    )


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
