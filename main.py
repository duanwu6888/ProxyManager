import csv
import socket
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template_string, request


app = Flask(__name__)

CSV_FILE = Path("proxy_check_results.csv")
CONNECT_TIMEOUT_SECONDS = 5

LOCATION_NAME_TRANSLATIONS = {
    "Ashburn": "阿什本",
    "Virginia": "弗吉尼亚州",
    "United States": "美国",
}

PAGE_TEMPLATE = """
<!doctype html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Proxy IP Checker</title>
    <style>
        :root {
            color-scheme: light;
            font-family: Arial, "Microsoft YaHei", sans-serif;
            background: #f4f7fb;
            color: #172033;
        }

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 32px 16px;
        }

        main {
            width: min(760px, 100%);
            background: #ffffff;
            border: 1px solid #d9e2ef;
            border-radius: 8px;
            box-shadow: 0 16px 40px rgba(28, 44, 74, 0.12);
            padding: 28px;
        }

        h1 {
            margin: 0 0 8px;
            font-size: 28px;
            line-height: 1.2;
        }

        .subtitle {
            margin: 0 0 24px;
            color: #5d6b82;
        }

        form {
            display: grid;
            grid-template-columns: 1fr 160px auto;
            gap: 12px;
            align-items: end;
        }

        label {
            display: grid;
            gap: 8px;
            font-weight: 700;
        }

        input {
            width: 100%;
            height: 44px;
            border: 1px solid #b8c5d9;
            border-radius: 6px;
            padding: 0 12px;
            font-size: 16px;
        }

        button {
            height: 44px;
            border: 0;
            border-radius: 6px;
            padding: 0 18px;
            background: #1769aa;
            color: #ffffff;
            font-size: 16px;
            font-weight: 700;
            cursor: pointer;
        }

        button:hover {
            background: #12578e;
        }

        .error {
            margin-top: 18px;
            padding: 12px 14px;
            border: 1px solid #f0b3b3;
            border-radius: 6px;
            background: #fff3f3;
            color: #a32626;
        }

        .result {
            margin-top: 24px;
            border-top: 1px solid #d9e2ef;
            padding-top: 22px;
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 12px;
        }

        .item {
            border: 1px solid #d9e2ef;
            border-radius: 6px;
            padding: 14px;
            background: #fbfdff;
        }

        .item span {
            display: block;
            color: #66758d;
            font-size: 13px;
            margin-bottom: 6px;
        }

        .item strong {
            overflow-wrap: anywhere;
        }

        .note {
            margin: 16px 0 0;
            color: #5d6b82;
        }

        @media (max-width: 680px) {
            main {
                padding: 20px;
            }

            form,
            .grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <main>
        <h1>代理 IP 检测工具</h1>
        <p class="subtitle">输入代理 IP 和端口，检测连接状态并保存 CSV 结果。</p>

        <form method="post">
            <label>
                IP
                <input name="ip" value="{{ ip }}" placeholder="例如 8.8.8.8" required>
            </label>
            <label>
                端口
                <input name="port" value="{{ port }}" placeholder="例如 53" inputmode="numeric" required>
            </label>
            <button type="submit">检测</button>
        </form>

        {% if error %}
            <div class="error">{{ error }}</div>
        {% endif %}

        {% if result %}
            <section class="result">
                <div class="grid">
                    <div class="item"><span>IP</span><strong>{{ result.ip }}</strong></div>
                    <div class="item"><span>端口</span><strong>{{ result.port }}</strong></div>
                    <div class="item"><span>是否可连接</span><strong>{{ result.connectable }}</strong></div>
                    <div class="item"><span>国家</span><strong>{{ result.country }}</strong></div>
                    <div class="item"><span>州/省</span><strong>{{ result.state }}</strong></div>
                    <div class="item"><span>城市</span><strong>{{ result.city }}</strong></div>
                </div>
                <p class="note">结果已保存到 {{ csv_file }}。</p>
                {% if location_error %}
                    <p class="note">位置查询提示：{{ location_error }}</p>
                {% endif %}
            </section>
        {% endif %}
    </main>
</body>
</html>
"""


def check_connection(ip: str, port: int) -> tuple[bool, str]:
    try:
        with socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT_SECONDS):
            return True, "可连接"
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
        return {
            "country": "未知",
            "state": "未知",
            "city": "未知",
            "error": str(exc),
        }

    row = next(csv.reader([body]))
    status = row[0] if row else "fail"

    if status != "success":
        message = row[4] if len(row) > 4 else "位置查询失败"
        return {
            "country": "未知",
            "state": "未知",
            "city": "未知",
            "error": message,
        }

    country = row[1] if len(row) > 1 else ""
    state = row[2] if len(row) > 2 else ""
    city = row[3] if len(row) > 3 else ""

    return {
        "country": translate_location_name(country),
        "state": translate_location_name(state),
        "city": translate_location_name(city),
        "error": "",
    }


def translate_location_name(name: str) -> str:
    return LOCATION_NAME_TRANSLATIONS.get(name, name)


def save_result(result: dict[str, str]) -> None:
    fieldnames = [
        "checked_at",
        "ip",
        "port",
        "connectable",
        "message",
        "country",
        "state",
        "city",
    ]

    file_exists = CSV_FILE.exists()

    with CSV_FILE.open("a", encoding="utf-8-sig", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerow(result)


def validate_form(ip: str, port_text: str) -> tuple[int | None, str | None]:
    if not ip:
        return None, "请输入 IP。"

    if not port_text.isdigit():
        return None, "端口必须是数字。"

    port = int(port_text)
    if not 1 <= port <= 65535:
        return None, "端口范围必须是 1-65535。"

    return port, None


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None
    location_error = None
    ip = ""
    port_text = ""

    if request.method == "POST":
        ip = request.form.get("ip", "").strip()
        port_text = request.form.get("port", "").strip()
        port, error = validate_form(ip, port_text)

        if error is None and port is not None:
            connectable, message = check_connection(ip, port)
            location = get_location(ip)
            location_error = location["error"]

            result = {
                "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "ip": ip,
                "port": str(port),
                "connectable": "是" if connectable else "否",
                "message": message if connectable else f"连接失败: {message}",
                "country": location["country"],
                "state": location["state"],
                "city": location["city"],
            }
            save_result(result)

    return render_template_string(
        PAGE_TEMPLATE,
        csv_file=CSV_FILE,
        error=error,
        ip=ip,
        location_error=location_error,
        port=port_text,
        result=result,
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
