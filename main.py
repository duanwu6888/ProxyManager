import csv
import ipaddress
import sqlite3
import socket
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

from flask import Flask, flash, g, redirect, render_template_string, request, url_for


app = Flask(__name__)
app.config["DATABASE"] = "proxy_manager.db"
app.secret_key = "proxy-manager-dev-secret"

CSV_FILE = Path("proxy_check_results.csv")
CONNECT_TIMEOUT_SECONDS = 5
UNKNOWN = "Unknown"

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
            <a href="{{ url_for('health') }}" class="btn btn-outline-secondary align-self-start">
                Health
            </a>
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
                            <button type="submit" class="btn btn-primary w-100">
                                &#28155;&#21152;&#20195;&#29702;
                            </button>
                        </form>
                    </div>
                </div>
            </div>

            <div class="col-12 col-xl-9">
                <div class="card border-0 shadow-sm mb-4">
                    <div class="card-header bg-white d-flex justify-content-between align-items-center">
                        <span class="fw-semibold">&#20195;&#29702;&#21015;&#34920;</span>
                        <span class="badge text-bg-light">{{ proxies|length }} items</span>
                    </div>
                    <div class="table-responsive">
                        <table class="table table-hover mb-0">
                            <thead class="table-light">
                                <tr>
                                    <th>&#20195;&#29702;</th>
                                    <th>&#22791;&#27880;</th>
                                    <th>&#26816;&#27979;&#29366;&#24577;</th>
                                    <th>&#22269;&#23478;</th>
                                    <th>&#24030;</th>
                                    <th>&#22478;&#24066;</th>
                                    <th>&#26368;&#36817;&#26816;&#27979;</th>
                                    <th class="text-end">&#25805;&#20316;</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for proxy in proxies %}
                                    <tr>
                                        <td class="proxy-address fw-semibold">{{ proxy.ip }}:{{ proxy.port }}</td>
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
                                        <td colspan="8" class="text-center text-secondary py-5">
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
            """
        )
        db.commit()
        import_csv_if_empty(db)


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
            INSERT OR IGNORE INTO proxies (ip, port, label, created_at, updated_at)
            VALUES (?, ?, '', ?, ?)
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


def fetch_proxies() -> list[sqlite3.Row]:
    return get_db().execute(
        """
        SELECT
            p.*,
            c.checked_at AS last_checked_at,
            c.connectable AS last_connectable,
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
        ORDER BY p.created_at DESC, p.id DESC
        """
    ).fetchall()


def fetch_recent_checks(limit: int = 20) -> list[sqlite3.Row]:
    return get_db().execute(
        """
        SELECT c.*, p.ip, p.port
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


@app.route("/")
def index():
    proxies = fetch_proxies()
    return render_template_string(
        PAGE_TEMPLATE,
        UNKNOWN=UNKNOWN,
        proxies=proxies,
        recent_checks=fetch_recent_checks(),
        stats=build_stats(proxies),
    )


@app.route("/proxies", methods=["POST"])
def create_proxy():
    ip = request.form.get("ip", "").strip()
    port_text = request.form.get("port", "").strip()
    label = request.form.get("label", "").strip()
    port, error = validate_proxy(ip, port_text)

    if error:
        flash(error)
        return redirect(url_for("index"))

    now = current_time()
    try:
        get_db().execute(
            """
            INSERT INTO proxies (ip, port, label, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (ip, port, label, now, now),
        )
        get_db().commit()
        flash(f"\u5df2\u6dfb\u52a0\u4ee3\u7406 {ip}:{port}\u3002")
    except sqlite3.IntegrityError:
        flash(f"\u4ee3\u7406 {ip}:{port} \u5df2\u5b58\u5728\u3002")

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


@app.route("/health")
def health():
    return {"status": "ok"}


init_db()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
