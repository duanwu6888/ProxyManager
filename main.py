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
UNKNOWN = "未知"

PAGE_TEMPLATE = """
<!doctype html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ProxyManager</title>
    <style>
        :root {
            color-scheme: light;
            font-family: Arial, "Microsoft YaHei", sans-serif;
            background: #eef2f7;
            color: #172033;
        }

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            min-height: 100vh;
            background: #eef2f7;
        }

        header {
            background: #ffffff;
            border-bottom: 1px solid #d8e0eb;
        }

        .wrap {
            width: min(1180px, calc(100% - 32px));
            margin: 0 auto;
        }

        .topbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 16px;
            padding: 18px 0;
        }

        h1 {
            margin: 0;
            font-size: 24px;
            line-height: 1.2;
        }

        .muted {
            color: #66758d;
            font-size: 14px;
        }

        main {
            padding: 24px 0 40px;
        }

        .stats {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
            margin-bottom: 16px;
        }

        .stat,
        .panel,
        .table-shell {
            background: #ffffff;
            border: 1px solid #d8e0eb;
            border-radius: 8px;
        }

        .stat {
            padding: 16px;
        }

        .stat span {
            display: block;
            color: #66758d;
            font-size: 13px;
            margin-bottom: 8px;
        }

        .stat strong {
            font-size: 28px;
        }

        .layout {
            display: grid;
            grid-template-columns: 340px 1fr;
            gap: 16px;
            align-items: start;
        }

        .panel {
            padding: 18px;
        }

        h2 {
            margin: 0 0 14px;
            font-size: 18px;
        }

        form.stack {
            display: grid;
            gap: 12px;
        }

        label {
            display: grid;
            gap: 7px;
            color: #39465c;
            font-size: 14px;
            font-weight: 700;
        }

        input {
            width: 100%;
            height: 40px;
            border: 1px solid #b9c6d8;
            border-radius: 6px;
            padding: 0 11px;
            font-size: 15px;
            background: #ffffff;
            color: #172033;
        }

        .actions {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            align-items: center;
        }

        button,
        .button {
            min-height: 38px;
            border: 1px solid #1769aa;
            border-radius: 6px;
            padding: 0 13px;
            background: #1769aa;
            color: #ffffff;
            font-size: 14px;
            font-weight: 700;
            cursor: pointer;
            text-decoration: none;
        }

        button:hover,
        .button:hover {
            background: #12578e;
            border-color: #12578e;
        }

        .button.secondary,
        button.secondary {
            background: #ffffff;
            color: #1769aa;
        }

        .button.danger,
        button.danger {
            border-color: #c2413a;
            background: #ffffff;
            color: #b02e28;
        }

        .flash {
            margin: 0 0 16px;
            padding: 12px 14px;
            border: 1px solid #b9d7bd;
            border-radius: 8px;
            background: #f1fbf3;
            color: #256b32;
        }

        .table-shell {
            overflow-x: auto;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            min-width: 780px;
        }

        th,
        td {
            padding: 12px 14px;
            border-bottom: 1px solid #e2e8f0;
            text-align: left;
            vertical-align: middle;
            font-size: 14px;
        }

        th {
            background: #f8fafc;
            color: #516078;
            font-size: 12px;
            text-transform: uppercase;
        }

        tr:last-child td {
            border-bottom: 0;
        }

        .status {
            display: inline-flex;
            align-items: center;
            min-height: 26px;
            border-radius: 999px;
            padding: 0 10px;
            font-size: 13px;
            font-weight: 700;
        }

        .ok {
            background: #e7f7ed;
            color: #1f7a3d;
        }

        .bad {
            background: #fff0ef;
            color: #b02e28;
        }

        .unknown {
            background: #eef2f7;
            color: #66758d;
        }

        .empty {
            padding: 24px;
            color: #66758d;
        }

        .recent {
            margin-top: 16px;
        }

        @media (max-width: 900px) {
            .stats,
            .layout {
                grid-template-columns: 1fr;
            }

            .topbar {
                align-items: flex-start;
                flex-direction: column;
            }
        }
    </style>
</head>
<body>
    <header>
        <div class="wrap topbar">
            <div>
                <h1>ProxyManager</h1>
                <div class="muted">代理资产检测与结果管理后台</div>
            </div>
            <form action="{{ url_for('check_all') }}" method="post">
                <button type="submit">批量检测</button>
            </form>
        </div>
    </header>

    <main class="wrap">
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for message in messages %}
                    <div class="flash">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        <section class="stats">
            <div class="stat"><span>代理总数</span><strong>{{ stats.total }}</strong></div>
            <div class="stat"><span>可连接</span><strong>{{ stats.online }}</strong></div>
            <div class="stat"><span>不可连接</span><strong>{{ stats.offline }}</strong></div>
            <div class="stat"><span>未检测</span><strong>{{ stats.untested }}</strong></div>
        </section>

        <section class="layout">
            <aside class="panel">
                <h2>添加代理</h2>
                <form class="stack" action="{{ url_for('create_proxy') }}" method="post">
                    <label>
                        IP 地址
                        <input name="ip" placeholder="例如 8.8.8.8" required>
                    </label>
                    <label>
                        端口
                        <input name="port" placeholder="例如 53" inputmode="numeric" required>
                    </label>
                    <label>
                        备注
                        <input name="label" placeholder="例如 美国 DNS">
                    </label>
                    <button type="submit">保存代理</button>
                </form>
            </aside>

            <section>
                <div class="table-shell">
                    <table>
                        <thead>
                            <tr>
                                <th>代理</th>
                                <th>备注</th>
                                <th>最近状态</th>
                                <th>位置</th>
                                <th>最近检测</th>
                                <th>操作</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for proxy in proxies %}
                                <tr>
                                    <td><strong>{{ proxy.ip }}:{{ proxy.port }}</strong></td>
                                    <td>{{ proxy.label or "-" }}</td>
                                    <td>
                                        {% if proxy.last_connectable is none %}
                                            <span class="status unknown">未检测</span>
                                        {% elif proxy.last_connectable %}
                                            <span class="status ok">可连接</span>
                                        {% else %}
                                            <span class="status bad">不可连接</span>
                                        {% endif %}
                                    </td>
                                    <td>{{ proxy.country or UNKNOWN }} / {{ proxy.state or UNKNOWN }} / {{ proxy.city or UNKNOWN }}</td>
                                    <td>{{ proxy.last_checked_at or "-" }}</td>
                                    <td>
                                        <div class="actions">
                                            <form action="{{ url_for('check_proxy_route', proxy_id=proxy.id) }}" method="post">
                                                <button class="secondary" type="submit">检测</button>
                                            </form>
                                            <form action="{{ url_for('delete_proxy', proxy_id=proxy.id) }}" method="post" onsubmit="return confirm('确定删除这个代理及其检测记录？');">
                                                <button class="danger" type="submit">删除</button>
                                            </form>
                                        </div>
                                    </td>
                                </tr>
                            {% else %}
                                <tr><td class="empty" colspan="6">暂无代理，先添加一个 IP 和端口。</td></tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>

                <div class="table-shell recent">
                    <table>
                        <thead>
                            <tr>
                                <th>检测时间</th>
                                <th>代理</th>
                                <th>状态</th>
                                <th>消息</th>
                                <th>位置</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for check in recent_checks %}
                                <tr>
                                    <td>{{ check.checked_at }}</td>
                                    <td>{{ check.ip }}:{{ check.port }}</td>
                                    <td>
                                        {% if check.connectable %}
                                            <span class="status ok">可连接</span>
                                        {% else %}
                                            <span class="status bad">不可连接</span>
                                        {% endif %}
                                    </td>
                                    <td>{{ check.message }}</td>
                                    <td>{{ check.country }} / {{ check.state }} / {{ check.city }}</td>
                                </tr>
                            {% else %}
                                <tr><td class="empty" colspan="5">还没有检测记录。</td></tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </section>
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

    with CSV_FILE.open("r", encoding="utf-8-sig", newline="") as csv_file:
        for row in csv.DictReader(csv_file):
            ip = (row.get("ip") or "").strip()
            port_text = (row.get("port") or "").strip()
            try:
                port, error = validate_proxy(ip, port_text)
            except ValueError:
                continue
            if error:
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

            connectable = normalize_connectable(row.get("connectable", ""))
            db.execute(
                """
                INSERT INTO checks
                    (proxy_id, checked_at, connectable, message, country, state, city)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    proxy_id,
                    row.get("checked_at") or now,
                    connectable,
                    row.get("message") or "",
                    row.get("country") or UNKNOWN,
                    row.get("state") or UNKNOWN,
                    row.get("city") or UNKNOWN,
                ),
            )
    db.commit()


def normalize_connectable(value: str) -> int:
    return 1 if value.strip().lower() in {"yes", "true", "1", "是", "可连接"} else 0


def current_time() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def validate_proxy(ip: str, port_text: str) -> tuple[int | None, str | None]:
    if not ip:
        return None, "请输入 IP 地址。"

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None, "IP 地址格式不正确。"

    if not port_text.isdigit():
        return None, "端口必须是数字。"

    port = int(port_text)
    if not 1 <= port <= 65535:
        return None, "端口范围必须是 1-65535。"

    return port, None


def check_connection(ip: str, port: int) -> tuple[bool, str]:
    try:
        with socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT_SECONDS):
            return True, "连接成功"
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
        message = row[4] if len(row) > 4 else "位置查询失败"
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
        message = f"{message}; 位置查询: {location['error']}"

    db.execute(
        """
        INSERT INTO checks
            (proxy_id, checked_at, connectable, message, country, state, city)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            proxy["id"],
            current_time(),
            1 if connectable else 0,
            message,
            location["country"],
            location["state"],
            location["city"],
        ),
    )
    db.execute("UPDATE proxies SET updated_at = ? WHERE id = ?", (current_time(), proxy["id"]))
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


def fetch_recent_checks(limit: int = 10) -> list[sqlite3.Row]:
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


def fetch_stats() -> dict[str, int]:
    proxies = fetch_proxies()
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
        stats={
            "total": len(proxies),
            "online": sum(1 for proxy in proxies if proxy["last_connectable"] == 1),
            "offline": sum(1 for proxy in proxies if proxy["last_connectable"] == 0),
            "untested": sum(1 for proxy in proxies if proxy["last_connectable"] is None),
        },
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
        flash(f"已添加代理 {ip}:{port}。")
    except sqlite3.IntegrityError:
        flash(f"代理 {ip}:{port} 已存在。")

    return redirect(url_for("index"))


@app.route("/proxies/<int:proxy_id>/check", methods=["POST"])
def check_proxy_route(proxy_id: int):
    proxy = run_check(proxy_id)
    if proxy is None:
        flash("代理不存在。")
    else:
        flash(f"已检测 {proxy['ip']}:{proxy['port']}。")
    return redirect(url_for("index"))


@app.route("/checks/run-all", methods=["POST"])
def check_all():
    proxies = get_db().execute("SELECT id FROM proxies ORDER BY id").fetchall()
    for proxy in proxies:
        run_check(proxy["id"])
    flash(f"批量检测完成，共检测 {len(proxies)} 个代理。")
    return redirect(url_for("index"))


@app.route("/proxies/<int:proxy_id>/delete", methods=["POST"])
def delete_proxy(proxy_id: int):
    get_db().execute("DELETE FROM proxies WHERE id = ?", (proxy_id,))
    get_db().commit()
    flash("代理已删除。")
    return redirect(url_for("index"))


@app.route("/health")
def health():
    return {"status": "ok"}


init_db()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
