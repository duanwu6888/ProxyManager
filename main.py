import csv
import io
import ipaddress
import sqlite3
import socket
import urllib.error
import urllib.request
import random
from datetime import datetime
from pathlib import Path

from flask import Flask, Response, flash, g, jsonify, redirect, render_template_string, request, url_for


app = Flask(__name__)
app.config["DATABASE"] = "proxy_manager.db"
app.secret_key = "proxy-manager-dev-secret"

CSV_FILE = Path("proxy_check_results.csv")
CONNECT_TIMEOUT_SECONDS = 5
UNKNOWN = "Unknown"
PROXY_TYPES = ("HTTP", "HTTPS", "SOCKS5", "SOCKS4")
STATE_FILTERS = ("California", "New York", "Texas", "Florida")
API_TOKEN = "proxymanager-v2-token"

PAGE_TEMPLATE = """
<!doctype html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ProxyManager</title>
    <link
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
        rel="stylesheet"
    >
    <style>
        body {
            background: #f4f6f9;
        }

        .navbar {
            border-bottom: 1px solid #dde3ec;
        }

        .stat-card {
            min-height: 112px;
        }

        .table td,
        .table th {
            vertical-align: middle;
        }

        .proxy-address {
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        }

        .failure-reason {
            max-width: 280px;
        }

        .dashboard-card {
            min-height: 100%;
        }

        @media (max-width: 575.98px) {
            main.container-fluid {
                padding-left: 0.75rem !important;
                padding-right: 0.75rem !important;
            }

            .navbar .container-fluid {
                align-items: stretch;
                flex-direction: column;
                gap: 0.75rem;
                padding-left: 0.75rem !important;
                padding-right: 0.75rem !important;
            }

            .navbar form,
            .navbar button,
            .mobile-full {
                width: 100%;
            }

            .stat-card {
                min-height: 92px;
            }

            .display-6 {
                font-size: 1.8rem;
            }

            .table {
                min-width: 1120px;
            }
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg bg-white">
        <div class="container-fluid px-4">
            <span class="navbar-brand fw-bold">ProxyManager</span>
            <form action="{{ url_for('check_all') }}" method="post" class="ms-auto">
                <button type="submit" class="btn btn-primary">
                    &#25209;&#37327;&#26816;&#27979;
                </button>
            </form>
        </div>
    </nav>

    <main class="container-fluid px-4 py-4">
        <div class="d-flex flex-column flex-lg-row justify-content-between gap-3 mb-4">
            <div>
                <h1 class="h3 mb-1">&#20195;&#29702; IP &#26816;&#27979;&#21518;&#21488;</h1>
                <div class="text-secondary">
                    Flask + SQLite &#20195;&#29702;&#36164;&#20135;&#31649;&#29702;&#19982;&#36830;&#36890;&#24615;&#26816;&#27979;
                </div>
            </div>
            <div class="d-flex flex-column flex-sm-row gap-2">
                <a href="{{ url_for('export_csv') }}" class="btn btn-outline-success mobile-full">
                    &#23548;&#20986; CSV
                </a>
                <a href="{{ url_for('api_docs') }}" class="btn btn-outline-primary mobile-full">
                    API v2
                </a>
                <a href="{{ url_for('health') }}" class="btn btn-outline-secondary mobile-full">
                    Health
                </a>
            </div>
        </div>

        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for message in messages %}
                    <div class="alert alert-info alert-dismissible fade show" role="alert">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        <section class="row g-3 mb-4">
            <div class="col-6 col-xl-3">
                <div class="card stat-card border-0 shadow-sm">
                    <div class="card-body">
                        <div class="text-secondary small">&#20195;&#29702;&#24635;&#25968;</div>
                        <div class="display-6 fw-semibold">{{ stats.total }}</div>
                    </div>
                </div>
            </div>
            <div class="col-6 col-xl-3">
                <div class="card stat-card border-0 shadow-sm">
                    <div class="card-body">
                        <div class="text-secondary small">&#21487;&#36830;&#25509;</div>
                        <div class="display-6 fw-semibold text-success">{{ stats.online }}</div>
                    </div>
                </div>
            </div>
            <div class="col-6 col-xl-3">
                <div class="card stat-card border-0 shadow-sm">
                    <div class="card-body">
                        <div class="text-secondary small">&#19981;&#21487;&#36830;&#25509;</div>
                        <div class="display-6 fw-semibold text-danger">{{ stats.offline }}</div>
                    </div>
                </div>
            </div>
            <div class="col-6 col-xl-3">
                <div class="card stat-card border-0 shadow-sm">
                    <div class="card-body">
                        <div class="text-secondary small">&#26410;&#26816;&#27979;</div>
                        <div class="display-6 fw-semibold text-secondary">{{ stats.untested }}</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="row g-3 mb-4">
            <div class="col-12 col-xl-4">
                <div class="card dashboard-card border-0 shadow-sm">
                    <div class="card-header bg-white fw-semibold">Auto Check</div>
                    <div class="card-body">
                        <label for="auto-check-interval" class="form-label">Interval</label>
                        <select id="auto-check-interval" class="form-select">
                            <option value="0">Off</option>
                            <option value="300">5 minutes</option>
                            <option value="1800">30 minutes</option>
                            <option value="3600">1 hour</option>
                        </select>
                        <div id="auto-check-status" class="form-text mt-2">
                            Auto check is currently off.
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-12 col-xl-4">
                <div class="card dashboard-card border-0 shadow-sm">
                    <div class="card-header bg-white fw-semibold">Online Rate</div>
                    <div class="card-body">
                        <div class="display-6 fw-semibold text-primary">{{ dashboard.online_rate }}%</div>
                        <div class="text-secondary small">{{ stats.online }} / {{ stats.total }} online</div>
                    </div>
                </div>
            </div>
            <div class="col-12 col-xl-4">
                <div class="card dashboard-card border-0 shadow-sm">
                    <div class="card-header bg-white fw-semibold">Latest Check</div>
                    <div class="card-body">
                        <div class="h5 mb-1">{{ dashboard.last_checked_at or "-" }}</div>
                        <div class="text-secondary small">Most recent check record</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="card border-0 shadow-sm mb-4">
            <div class="card-header bg-white fw-semibold">Proxy Count By State</div>
            <div class="card-body">
                <div class="row g-3">
                    {% for item in dashboard.state_counts %}
                        <div class="col-6 col-xl-3">
                            <div class="border rounded bg-light p-3">
                                <div class="text-secondary small">{{ item.state }}</div>
                                <div class="h3 mb-0">{{ item.count }}</div>
                            </div>
                        </div>
                    {% endfor %}
                </div>
            </div>
        </section>

        <section class="row g-4">
            <div class="col-12 col-xl-3">
                <div class="card border-0 shadow-sm">
                    <div class="card-header bg-white fw-semibold">&#36755;&#20837; IP &#21644;&#31471;&#21475;</div>
                    <div class="card-body">
                        <form action="{{ url_for('create_proxy') }}" method="post" class="vstack gap-3">
                            <div>
                                <label for="ip" class="form-label">IP</label>
                                <input
                                    id="ip"
                                    name="ip"
                                    class="form-control"
                                    placeholder="8.8.8.8"
                                    required
                                >
                            </div>
                            <div>
                                <label for="port" class="form-label">&#31471;&#21475;</label>
                                <input
                                    id="port"
                                    name="port"
                                    class="form-control"
                                    placeholder="53"
                                    inputmode="numeric"
                                    required
                                >
                            </div>
                            <div>
                                <label for="label" class="form-label">&#22791;&#27880;</label>
                                <input
                                    id="label"
                                    name="label"
                                    class="form-control"
                                    placeholder="DNS / HTTP Proxy"
                                >
                            </div>
                            <div>
                                <label for="proxy_type" class="form-label">Proxy Type</label>
                                <select id="proxy_type" name="proxy_type" class="form-select">
                                    {% for proxy_type in proxy_types %}
                                        <option value="{{ proxy_type }}">{{ proxy_type }}</option>
                                    {% endfor %}
                                </select>
                            </div>
                            <button type="submit" class="btn btn-primary w-100">
                                &#28155;&#21152;&#20195;&#29702;
                            </button>
                        </form>
                    </div>
                </div>
            </div>

            <div class="col-12 col-xl-9">
                <div class="card border-0 shadow-sm mb-4">
                    <div class="card-body">
                        <form action="{{ url_for('index') }}" method="get" class="row g-2 align-items-end">
                            <div class="col-12 col-md">
                                <label for="q" class="form-label">&#25628;&#32034;</label>
                                <input
                                    id="q"
                                    name="q"
                                    class="form-control"
                                    value="{{ query }}"
                                    placeholder="IP / port / label / country / state / city"
                                >
                            </div>
                            <div class="col-12 col-md-3">
                                <label for="state" class="form-label">State</label>
                                <select id="state" name="state" class="form-select">
                                    <option value="">All states</option>
                                    {% for state in state_filters %}
                                        <option value="{{ state }}" {% if selected_state == state %}selected{% endif %}>
                                            {{ state }}
                                        </option>
                                    {% endfor %}
                                </select>
                            </div>
                            <div class="col-12 col-md-auto d-flex gap-2">
                                <button type="submit" class="btn btn-outline-primary mobile-full">
                                    &#25628;&#32034;
                                </button>
                                <a href="{{ url_for('index') }}" class="btn btn-outline-secondary mobile-full">
                                    &#37325;&#32622;
                                </a>
                            </div>
                        </form>
                    </div>
                </div>

                <div class="card border-0 shadow-sm mb-4">
                    <div class="card-header bg-white fw-semibold">&#25209;&#37327;&#23548;&#20837;&#20195;&#29702;</div>
                    <div class="card-body">
                        <form action="{{ url_for('import_proxies') }}" method="post" class="vstack gap-3">
                            <textarea
                                name="proxies"
                                class="form-control"
                                rows="5"
                                placeholder="8.8.8.8:53&#10;1.1.1.1,53,DNS&#10;208.67.222.222 53 OpenDNS"
                            ></textarea>
                            <div class="d-flex flex-column flex-sm-row justify-content-between gap-2">
                                <div class="form-text">
                                    &#27599;&#34892;&#19968;&#20010;&#20195;&#29702;&#65292;&#25903;&#25345; IP:PORT&#12289;IP,PORT,备注 &#25110; IP PORT 备注&#12290;
                                </div>
                                <button type="submit" class="btn btn-primary mobile-full">
                                    &#25209;&#37327;&#23548;&#20837;
                                </button>
                            </div>
                        </form>
                    </div>
                </div>

                <div class="card border-0 shadow-sm mb-4">
                    <div class="card-header bg-white d-flex flex-column flex-lg-row justify-content-between align-items-lg-center gap-2">
                        <div>
                            <span class="fw-semibold">&#20195;&#29702;&#21015;&#34920;</span>
                            <span class="badge text-bg-light">{{ proxies|length }} items</span>
                        </div>
                        <div class="d-flex flex-column flex-sm-row gap-2">
                            <a href="{{ url_for('export_csv') }}" class="btn btn-sm btn-outline-success mobile-full">
                                &#23548;&#20986; CSV
                            </a>
                            <form
                                action="{{ url_for('delete_all_proxies') }}"
                                method="post"
                                onsubmit="return confirm('Delete all proxies and history?');"
                            >
                                <button type="submit" class="btn btn-sm btn-outline-danger mobile-full">
                                    &#21024;&#38500;&#20840;&#37096;&#20195;&#29702;
                                </button>
                            </form>
                        </div>
                    </div>
                    <div class="table-responsive">
                        <table class="table table-hover mb-0">
                            <thead class="table-light">
                                <tr>
                                    <th>&#20195;&#29702;</th>
                                    <th>Type</th>
                                    <th>&#22791;&#27880;</th>
                                    <th>&#26816;&#27979;&#29366;&#24577;</th>
                                    <th>&#22269;&#23478;</th>
                                    <th>&#24030;</th>
                                    <th>&#22478;&#24066;</th>
                                    <th>&#22833;&#36133;&#21407;&#22240;</th>
                                    <th>&#26368;&#36817;&#26816;&#27979;</th>
                                    <th class="text-end">&#25805;&#20316;</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for proxy in proxies %}
                                    <tr>
                                        <td class="proxy-address fw-semibold">{{ proxy.ip }}:{{ proxy.port }}</td>
                                        <td><span class="badge text-bg-dark">{{ proxy.proxy_type }}</span></td>
                                        <td>{{ proxy.label or "-" }}</td>
                                        <td>
                                            {% if proxy.last_connectable is none %}
                                                <span class="badge rounded-pill text-bg-secondary">&#26410;&#26816;&#27979;</span>
                                            {% elif proxy.last_connectable %}
                                                <span class="badge rounded-pill text-bg-success">&#21487;&#36830;&#25509;</span>
                                            {% else %}
                                                <span class="badge rounded-pill text-bg-danger">&#19981;&#21487;&#36830;&#25509;</span>
                                            {% endif %}
                                        </td>
                                        <td>{{ proxy.country or UNKNOWN }}</td>
                                        <td>{{ proxy.state or UNKNOWN }}</td>
                                        <td>{{ proxy.city or UNKNOWN }}</td>
                                        <td class="failure-reason text-break">
                                            {% if proxy.last_connectable == 0 %}
                                                {{ proxy.last_message or "-" }}
                                            {% else %}
                                                -
                                            {% endif %}
                                        </td>
                                        <td>{{ proxy.last_checked_at or "-" }}</td>
                                        <td>
                                            <div class="d-flex justify-content-end gap-2">
                                                <form action="{{ url_for('check_proxy_route', proxy_id=proxy.id) }}" method="post">
                                                    <button type="submit" class="btn btn-sm btn-outline-primary">
                                                        &#26816;&#27979;
                                                    </button>
                                                </form>
                                                <form
                                                    action="{{ url_for('delete_proxy', proxy_id=proxy.id) }}"
                                                    method="post"
                                                    onsubmit="return confirm('Delete this proxy and its history?');"
                                                >
                                                    <button type="submit" class="btn btn-sm btn-outline-danger">
                                                        &#21024;&#38500;
                                                    </button>
                                                </form>
                                            </div>
                                        </td>
                                    </tr>
                                {% else %}
                                    <tr>
                                        <td colspan="10" class="text-center text-secondary py-5">
                                            &#26242;&#26080;&#20195;&#29702;&#65292;&#35831;&#20808;&#28155;&#21152; IP &#21644;&#31471;&#21475;&#12290;
                                        </td>
                                    </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="card border-0 shadow-sm">
                    <div class="card-header bg-white fw-semibold">&#21382;&#21490;&#35760;&#24405;</div>
                    <div class="table-responsive">
                        <table class="table table-striped mb-0">
                            <thead class="table-light">
                                <tr>
                                    <th>&#26816;&#27979;&#26102;&#38388;</th>
                                    <th>&#20195;&#29702;</th>
                                    <th>&#29366;&#24577;</th>
                                    <th>&#22269;&#23478;</th>
                                    <th>&#24030;</th>
                                    <th>&#22478;&#24066;</th>
                                    <th>&#28040;&#24687;</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for check in recent_checks %}
                                    <tr>
                                        <td>{{ check.checked_at }}</td>
                                        <td class="proxy-address">{{ check.ip }}:{{ check.port }}</td>
                                        <td>
                                            {% if check.connectable %}
                                                <span class="badge text-bg-success">&#21487;&#36830;&#25509;</span>
                                            {% else %}
                                                <span class="badge text-bg-danger">&#19981;&#21487;&#36830;&#25509;</span>
                                            {% endif %}
                                        </td>
                                        <td>{{ check.country }}</td>
                                        <td>{{ check.state }}</td>
                                        <td>{{ check.city }}</td>
                                        <td class="text-break">{{ check.message }}</td>
                                    </tr>
                                {% else %}
                                    <tr>
                                        <td colspan="7" class="text-center text-secondary py-5">
                                            &#36824;&#27809;&#26377;&#26816;&#27979;&#35760;&#24405;&#12290;
                                        </td>
                                    </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </section>
    </main>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        (() => {
            const select = document.getElementById("auto-check-interval");
            const status = document.getElementById("auto-check-status");
            const storageKey = "proxymanager.autoCheckSeconds";
            let timerId = null;

            const setStatus = (seconds) => {
                if (!status) return;
                if (!seconds) {
                    status.textContent = "Auto check is currently off.";
                    return;
                }
                const label = seconds === 300 ? "5 minutes" : seconds === 1800 ? "30 minutes" : "1 hour";
                status.textContent = `Auto check enabled. Running every ${label}.`;
            };

            const schedule = (seconds) => {
                if (timerId) {
                    window.clearInterval(timerId);
                    timerId = null;
                }
                setStatus(seconds);
                if (!seconds) return;
                timerId = window.setInterval(async () => {
                    try {
                        await fetch("{{ url_for('check_all') }}", { method: "POST" });
                        window.location.reload();
                    } catch (error) {
                        status.textContent = `Auto check failed: ${error}`;
                    }
                }, seconds * 1000);
            };

            if (select) {
                const savedSeconds = Number(window.localStorage.getItem(storageKey) || "0");
                select.value = String(savedSeconds);
                schedule(savedSeconds);
                select.addEventListener("change", () => {
                    const seconds = Number(select.value || "0");
                    window.localStorage.setItem(storageKey, String(seconds));
                    schedule(seconds);
                });
            }
        })();
    </script>
</body>
</html>
"""

API_DOCS_TEMPLATE = """
<!doctype html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ProxyManager API v2</title>
    <link
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
        rel="stylesheet"
    >
    <style>
        body { background: #f4f6f9; }
        .navbar { border-bottom: 1px solid #dde3ec; }
        code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
        pre { white-space: pre-wrap; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg bg-white">
        <div class="container-fluid px-4">
            <a class="navbar-brand fw-bold text-decoration-none" href="{{ url_for('index') }}">ProxyManager</a>
            <span class="badge text-bg-primary">API v2</span>
        </div>
    </nav>

    <main class="container-fluid px-4 py-4">
        <div class="d-flex flex-column flex-lg-row justify-content-between gap-3 mb-4">
            <div>
                <h1 class="h3 mb-1">Proxy Pool API v2</h1>
                <div class="text-secondary">All API requests require <code>?token={{ api_token }}</code>.</div>
            </div>
            <a href="{{ url_for('index') }}" class="btn btn-outline-secondary align-self-start">Back to Dashboard</a>
        </div>

        <section class="row g-4">
            <div class="col-12 col-xl-5">
                <div class="card border-0 shadow-sm">
                    <div class="card-header bg-white fw-semibold">Endpoints</div>
                    <div class="list-group list-group-flush">
                        {% for endpoint in endpoints %}
                            <div class="list-group-item">
                                <div class="fw-semibold">{{ endpoint.method }} {{ endpoint.path }}</div>
                                <code>{{ base_url }}{{ endpoint.path }}?token={{ api_token }}</code>
                            </div>
                        {% endfor %}
                    </div>
                </div>
            </div>
            <div class="col-12 col-xl-7">
                <div class="card border-0 shadow-sm mb-4">
                    <div class="card-header bg-white fw-semibold">Example Request</div>
                    <div class="card-body">
                        <pre class="bg-light border rounded p-3 mb-0">GET {{ base_url }}/api/random?token={{ api_token }}</pre>
                    </div>
                </div>
                <div class="card border-0 shadow-sm">
                    <div class="card-header bg-white fw-semibold">Example Response</div>
                    <div class="card-body">
                        <pre class="bg-light border rounded p-3 mb-0">{
  "success": true,
  "data": {
    "ip": "8.8.8.8",
    "port": 53,
    "proxy_type": "HTTP",
    "country": "United States",
    "state": "California",
    "city": "Los Angeles",
    "last_checked": "2026-06-07 10:00:00"
  }
}</pre>
                    </div>
                </div>
            </div>
        </section>
    </main>
</body>
</html>
"""


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_error: BaseException | None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    with app.app_context():
        db = get_db()
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS proxies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                proxy_type TEXT NOT NULL DEFAULT 'HTTP',
                label TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(ip, port)
            );

            CREATE TABLE IF NOT EXISTS checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                proxy_id INTEGER NOT NULL,
                checked_at TEXT NOT NULL,
                connectable INTEGER NOT NULL,
                message TEXT NOT NULL,
                country TEXT NOT NULL,
                state TEXT NOT NULL,
                city TEXT NOT NULL,
                FOREIGN KEY(proxy_id) REFERENCES proxies(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS api_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                accessed_at TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                success INTEGER NOT NULL
            );
            """
        )
        ensure_schema(db)
        db.commit()
        import_csv_if_empty(db)


def ensure_schema(db: sqlite3.Connection) -> None:
    columns = {
        row["name"] for row in db.execute("PRAGMA table_info(proxies)").fetchall()
    }
    if "proxy_type" not in columns:
        db.execute("ALTER TABLE proxies ADD COLUMN proxy_type TEXT NOT NULL DEFAULT 'HTTP'")
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS api_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            accessed_at TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            success INTEGER NOT NULL
        )
        """
    )


def import_csv_if_empty(db: sqlite3.Connection) -> None:
    proxy_count = db.execute("SELECT COUNT(*) FROM proxies").fetchone()[0]
    if proxy_count or not CSV_FILE.exists():
        return

    for row in read_legacy_csv_rows():
        ip = (row.get("ip") or "").strip()
        port_text = (row.get("port") or "").strip()
        port, error = validate_proxy(ip, port_text)
        if error or port is None:
            continue

        now = current_time()
        db.execute(
            """
            INSERT OR IGNORE INTO proxies (ip, port, proxy_type, label, created_at, updated_at)
            VALUES (?, ?, 'HTTP', '', ?, ?)
            """,
            (ip, port, now, now),
        )
        proxy_id = db.execute(
            "SELECT id FROM proxies WHERE ip = ? AND port = ?", (ip, port)
        ).fetchone()["id"]

        db.execute(
            """
            INSERT INTO checks
                (proxy_id, checked_at, connectable, message, country, state, city)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                proxy_id,
                row.get("checked_at") or now,
                normalize_connectable(row.get("connectable", "")),
                row.get("message") or "",
                row.get("country") or UNKNOWN,
                row.get("state") or UNKNOWN,
                row.get("city") or UNKNOWN,
            ),
        )
    db.commit()


def read_legacy_csv_rows() -> list[dict[str, str]]:
    raw = CSV_FILE.read_bytes()
    for encoding in ("utf-8-sig", "utf-8", "gbk"):
        try:
            text = raw.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    else:
        text = raw.decode("utf-8", errors="replace")

    return list(csv.DictReader(text.splitlines()))


def normalize_connectable(value: str) -> int:
    return 1 if value.strip().lower() in {"yes", "true", "1", "\u662f", "\u53ef\u8fde\u63a5"} else 0


def current_time() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def validate_proxy(ip: str, port_text: str) -> tuple[int | None, str | None]:
    if not ip:
        return None, "\u8bf7\u8f93\u5165 IP \u5730\u5740\u3002"

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None, "IP \u5730\u5740\u683c\u5f0f\u4e0d\u6b63\u786e\u3002"

    if not port_text.isdigit():
        return None, "\u7aef\u53e3\u5fc5\u987b\u662f\u6570\u5b57\u3002"

    port = int(port_text)
    if not 1 <= port <= 65535:
        return None, "\u7aef\u53e3\u8303\u56f4\u5fc5\u987b\u662f 1-65535\u3002"

    return port, None


def check_connection(ip: str, port: int) -> tuple[bool, str]:
    try:
        with socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT_SECONDS):
            return True, "\u8fde\u63a5\u6210\u529f"
    except OSError as exc:
        return False, str(exc)


def get_location(ip: str) -> dict[str, str]:
    url = (
        f"http://ip-api.com/csv/{ip}"
        "?fields=status,country,regionName,city,message&lang=zh-CN"
    )

    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            body = response.read().decode("utf-8").strip()
    except urllib.error.URLError as exc:
        return {"country": UNKNOWN, "state": UNKNOWN, "city": UNKNOWN, "error": str(exc)}

    row = next(csv.reader([body]))
    status = row[0] if row else "fail"
    if status != "success":
        message = row[4] if len(row) > 4 else "\u4f4d\u7f6e\u67e5\u8be2\u5931\u8d25"
        return {"country": UNKNOWN, "state": UNKNOWN, "city": UNKNOWN, "error": message}

    return {
        "country": row[1] if len(row) > 1 and row[1] else UNKNOWN,
        "state": row[2] if len(row) > 2 and row[2] else UNKNOWN,
        "city": row[3] if len(row) > 3 and row[3] else UNKNOWN,
        "error": "",
    }


def run_check(proxy_id: int) -> sqlite3.Row | None:
    db = get_db()
    proxy = db.execute("SELECT * FROM proxies WHERE id = ?", (proxy_id,)).fetchone()
    if proxy is None:
        return None

    connectable, message = check_connection(proxy["ip"], proxy["port"])
    location = get_location(proxy["ip"])
    if location["error"]:
        message = f"{message}; location: {location['error']}"

    checked_at = current_time()
    db.execute(
        """
        INSERT INTO checks
            (proxy_id, checked_at, connectable, message, country, state, city)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            proxy["id"],
            checked_at,
            1 if connectable else 0,
            message,
            location["country"],
            location["state"],
            location["city"],
        ),
    )
    db.execute("UPDATE proxies SET updated_at = ? WHERE id = ?", (checked_at, proxy["id"]))
    db.commit()
    return proxy


def fetch_proxies(query: str = "", state: str = "") -> list[sqlite3.Row]:
    where = ""
    params: list[str] = []
    conditions: list[str] = []
    if query:
        conditions.append(
            """
            (
            p.ip LIKE ?
            OR CAST(p.port AS TEXT) LIKE ?
            OR p.proxy_type LIKE ?
            OR p.label LIKE ?
            OR c.country LIKE ?
            OR c.state LIKE ?
            OR c.city LIKE ?
            )
            """
        )
        like_query = f"%{query}%"
        params.extend([like_query] * 7)
    if state:
        conditions.append("c.state = ?")
        params.append(state)
    if conditions:
        where = "WHERE " + " AND ".join(conditions)

    return get_db().execute(
        """
        SELECT
            p.*,
            c.checked_at AS last_checked_at,
            c.connectable AS last_connectable,
            c.message AS last_message,
            c.country,
            c.state,
            c.city
        FROM proxies p
        LEFT JOIN checks c ON c.id = (
            SELECT id FROM checks
            WHERE proxy_id = p.id
            ORDER BY checked_at DESC, id DESC
            LIMIT 1
        )
        """ + where + """
        ORDER BY p.created_at DESC, p.id DESC
        """,
        params,
    ).fetchall()


def fetch_recent_checks(limit: int = 20) -> list[sqlite3.Row]:
    return get_db().execute(
        """
        SELECT c.*, p.ip, p.port, p.proxy_type
        FROM checks c
        JOIN proxies p ON p.id = c.proxy_id
        ORDER BY c.checked_at DESC, c.id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()


def build_stats(proxies: list[sqlite3.Row]) -> dict[str, int]:
    return {
        "total": len(proxies),
        "online": sum(1 for proxy in proxies if proxy["last_connectable"] == 1),
        "offline": sum(1 for proxy in proxies if proxy["last_connectable"] == 0),
        "untested": sum(1 for proxy in proxies if proxy["last_connectable"] is None),
    }


def build_dashboard_stats(proxies: list[sqlite3.Row]) -> dict[str, object]:
    total = len(proxies)
    online = sum(1 for proxy in proxies if proxy["last_connectable"] == 1)
    last_checked_at = get_db().execute(
        "SELECT MAX(checked_at) FROM checks"
    ).fetchone()[0]
    state_counts = []
    for state in STATE_FILTERS:
        count = sum(1 for proxy in proxies if proxy["state"] == state)
        state_counts.append({"state": state, "count": count})

    return {
        "online_rate": round((online / total) * 100, 1) if total else 0,
        "last_checked_at": last_checked_at,
        "state_counts": state_counts,
    }


def serialize_proxy(proxy: sqlite3.Row) -> dict[str, object]:
    return {
        "ip": proxy["ip"],
        "port": proxy["port"],
        "proxy_type": proxy["proxy_type"],
        "country": proxy["country"] or UNKNOWN,
        "state": proxy["state"] or UNKNOWN,
        "city": proxy["city"] or UNKNOWN,
        "last_checked": proxy["last_checked_at"],
    }


def log_api_request(endpoint: str, success: bool) -> None:
    get_db().execute(
        """
        INSERT INTO api_logs (accessed_at, endpoint, client_ip, success)
        VALUES (?, ?, ?, ?)
        """,
        (
            current_time(),
            endpoint,
            request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip(),
            1 if success else 0,
        ),
    )
    get_db().commit()


def token_is_valid() -> bool:
    return request.args.get("token", "") == API_TOKEN


def api_error(message: str, status_code: int):
    log_api_request(request.path, False)
    response = jsonify({"success": False, "error": message})
    response.status_code = status_code
    return response


def require_api_token():
    if not token_is_valid():
        return api_error("invalid token", 401)
    return None


def fetch_online_proxies(
    country: str | None = None,
    state: str | None = None,
    city: str | None = None,
) -> list[sqlite3.Row]:
    conditions = ["c.connectable = 1"]
    params: list[str] = []
    if country is not None:
        conditions.append("LOWER(c.country) = LOWER(?)")
        params.append(country)
    if state is not None:
        conditions.append("LOWER(c.state) = LOWER(?)")
        params.append(state)
    if city is not None:
        conditions.append("LOWER(c.city) = LOWER(?)")
        params.append(city)

    return get_db().execute(
        """
        SELECT
            p.ip,
            p.port,
            p.proxy_type,
            c.country,
            c.state,
            c.city,
            c.checked_at AS last_checked_at
        FROM proxies p
        JOIN checks c ON c.id = (
            SELECT id FROM checks
            WHERE proxy_id = p.id
            ORDER BY checked_at DESC, id DESC
            LIMIT 1
        )
        WHERE """ + " AND ".join(conditions) + """
        ORDER BY c.checked_at DESC, p.id DESC
        """,
        params,
    ).fetchall()


def api_success(data):
    log_api_request(request.path, True)
    count = len(data) if isinstance(data, list) else 0 if data is None else 1
    return jsonify({"success": True, "count": count, "data": data})


def parse_proxy_line(line: str) -> tuple[str, str, str, str] | None:
    cleaned = line.strip()
    if not cleaned or cleaned.startswith("#"):
        return None

    label = ""
    if "," in cleaned:
        parts = [part.strip() for part in cleaned.split(",", 3)]
        if len(parts) >= 2:
            ip, port_text = parts[0], parts[1]
            proxy_type = normalize_proxy_type(parts[2] if len(parts) >= 3 else "")
            label = parts[3] if len(parts) == 4 else ""
            if len(parts) == 3 and parts[2].upper() not in PROXY_TYPES:
                proxy_type = "HTTP"
                label = parts[2]
            return ip, port_text, proxy_type, label

    if ":" in cleaned and " " not in cleaned:
        ip, port_text = cleaned.rsplit(":", 1)
        return ip.strip(), port_text.strip(), "HTTP", label

    parts = cleaned.split(maxsplit=3)
    if len(parts) >= 2:
        ip, port_text = parts[0], parts[1]
        proxy_type = normalize_proxy_type(parts[2] if len(parts) >= 3 else "")
        label = parts[3] if len(parts) == 4 else ""
        if len(parts) == 3 and parts[2].upper() not in PROXY_TYPES:
            proxy_type = "HTTP"
            label = parts[2]
        return ip, port_text, proxy_type, label

    return None


def normalize_proxy_type(value: str) -> str:
    proxy_type = value.strip().upper()
    return proxy_type if proxy_type in PROXY_TYPES else "HTTP"


def insert_proxy(ip: str, port: int, proxy_type: str, label: str) -> bool:
    now = current_time()
    try:
        get_db().execute(
            """
            INSERT INTO proxies (ip, port, proxy_type, label, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (ip, port, normalize_proxy_type(proxy_type), label, now, now),
        )
        get_db().commit()
        return True
    except sqlite3.IntegrityError:
        return False


@app.route("/")
def index():
    query = request.args.get("q", "").strip()
    selected_state = request.args.get("state", "").strip()
    if selected_state not in STATE_FILTERS:
        selected_state = ""
    proxies = fetch_proxies(query, selected_state)
    return render_template_string(
        PAGE_TEMPLATE,
        UNKNOWN=UNKNOWN,
        dashboard=build_dashboard_stats(fetch_proxies()),
        query=query,
        proxy_types=PROXY_TYPES,
        proxies=proxies,
        recent_checks=fetch_recent_checks(),
        selected_state=selected_state,
        state_filters=STATE_FILTERS,
        stats=build_stats(proxies),
    )


@app.route("/proxies", methods=["POST"])
def create_proxy():
    ip = request.form.get("ip", "").strip()
    port_text = request.form.get("port", "").strip()
    label = request.form.get("label", "").strip()
    proxy_type = normalize_proxy_type(request.form.get("proxy_type", "HTTP"))
    port, error = validate_proxy(ip, port_text)

    if error:
        flash(error)
        return redirect(url_for("index"))

    if insert_proxy(ip, port, proxy_type, label):
        flash(f"\u5df2\u6dfb\u52a0\u4ee3\u7406 {ip}:{port}\u3002")
    else:
        flash(f"\u4ee3\u7406 {ip}:{port} \u5df2\u5b58\u5728\u3002")

    return redirect(url_for("index"))


@app.route("/proxies/import", methods=["POST"])
def import_proxies():
    text = request.form.get("proxies", "")
    added = 0
    skipped = 0
    invalid = 0

    for line in text.splitlines():
        parsed = parse_proxy_line(line)
        if parsed is None:
            if line.strip():
                invalid += 1
            continue

        ip, port_text, proxy_type, label = parsed
        port, error = validate_proxy(ip, port_text)
        if error or port is None:
            invalid += 1
            continue

        if insert_proxy(ip, port, proxy_type, label):
            added += 1
        else:
            skipped += 1

    flash(
        "\u6279\u91cf\u5bfc\u5165\u5b8c\u6210\uff1a"
        f"\u65b0\u589e {added} \u4e2a\uff0c"
        f"\u8df3\u8fc7\u91cd\u590d {skipped} \u4e2a\uff0c"
        f"\u65e0\u6548 {invalid} \u884c\u3002"
    )
    return redirect(url_for("index"))


@app.route("/proxies/<int:proxy_id>/check", methods=["POST"])
def check_proxy_route(proxy_id: int):
    proxy = run_check(proxy_id)
    if proxy is None:
        flash("\u4ee3\u7406\u4e0d\u5b58\u5728\u3002")
    else:
        flash(f"\u5df2\u68c0\u6d4b {proxy['ip']}:{proxy['port']}\u3002")
    return redirect(url_for("index"))


@app.route("/checks/run-all", methods=["POST"])
def check_all():
    proxies = get_db().execute("SELECT id FROM proxies ORDER BY id").fetchall()
    for proxy in proxies:
        run_check(proxy["id"])
    flash(f"\u6279\u91cf\u68c0\u6d4b\u5b8c\u6210\uff0c\u5171\u68c0\u6d4b {len(proxies)} \u4e2a\u4ee3\u7406\u3002")
    return redirect(url_for("index"))


@app.route("/proxies/<int:proxy_id>/delete", methods=["POST"])
def delete_proxy(proxy_id: int):
    get_db().execute("DELETE FROM proxies WHERE id = ?", (proxy_id,))
    get_db().commit()
    flash("\u4ee3\u7406\u5df2\u5220\u9664\u3002")
    return redirect(url_for("index"))


@app.route("/proxies/delete-all", methods=["POST"])
def delete_all_proxies():
    deleted = get_db().execute("SELECT COUNT(*) FROM proxies").fetchone()[0]
    get_db().execute("DELETE FROM proxies")
    get_db().commit()
    flash(f"\u5df2\u5220\u9664\u5168\u90e8 {deleted} \u4e2a\u4ee3\u7406\u53ca\u5176\u5386\u53f2\u8bb0\u5f55\u3002")
    return redirect(url_for("index"))


@app.route("/export.csv")
def export_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "ip",
            "port",
            "proxy_type",
            "label",
            "last_checked_at",
            "connectable",
            "failure_reason",
            "country",
            "state",
            "city",
        ]
    )
    for proxy in fetch_proxies():
        writer.writerow(
            [
                proxy["ip"],
                proxy["port"],
                proxy["proxy_type"],
                proxy["label"],
                proxy["last_checked_at"] or "",
                "" if proxy["last_connectable"] is None else proxy["last_connectable"],
                proxy["last_message"] if proxy["last_connectable"] == 0 else "",
                proxy["country"] or "",
                proxy["state"] or "",
                proxy["city"] or "",
            ]
        )

    filename = f"proxy_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/api-docs")
def api_docs():
    endpoints = [
        {"method": "GET", "path": "/api/proxies"},
        {"method": "GET", "path": "/api/random"},
        {"method": "GET", "path": "/api/country/United States"},
        {"method": "GET", "path": "/api/state/California"},
        {"method": "GET", "path": "/api/city/Los Angeles"},
    ]
    return render_template_string(
        API_DOCS_TEMPLATE,
        api_token=API_TOKEN,
        base_url=request.host_url.rstrip("/"),
        endpoints=endpoints,
    )


@app.route("/api/proxies")
def api_proxies():
    token_error = require_api_token()
    if token_error:
        return token_error
    proxies = [serialize_proxy(proxy) for proxy in fetch_online_proxies()]
    return api_success(proxies)


@app.route("/api/random")
def api_random():
    token_error = require_api_token()
    if token_error:
        return token_error
    proxies = fetch_online_proxies()
    if not proxies:
        return api_success(None)
    return api_success(serialize_proxy(random.choice(proxies)))


@app.route("/api/country/<path:country>")
def api_country(country: str):
    token_error = require_api_token()
    if token_error:
        return token_error
    proxies = [serialize_proxy(proxy) for proxy in fetch_online_proxies(country=country)]
    return api_success(proxies)


@app.route("/api/state/<path:state>")
def api_state(state: str):
    token_error = require_api_token()
    if token_error:
        return token_error
    proxies = [serialize_proxy(proxy) for proxy in fetch_online_proxies(state=state)]
    return api_success(proxies)


@app.route("/api/city/<path:city>")
def api_city(city: str):
    token_error = require_api_token()
    if token_error:
        return token_error
    proxies = [serialize_proxy(proxy) for proxy in fetch_online_proxies(city=city)]
    return api_success(proxies)


@app.route("/health")
def health():
    return {"status": "ok"}


init_db()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
