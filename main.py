import csv
import io
import ipaddress
import sqlite3
import socket
import urllib.error
import urllib.request
import random
import secrets
from datetime import datetime
from pathlib import Path

import requests
from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask, Response, flash, g, jsonify, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.config["DATABASE"] = "proxy_manager.db"
app.secret_key = "proxy-manager-dev-secret"

CSV_FILE = Path("proxy_check_results.csv")
CONNECT_TIMEOUT_SECONDS = 5
IPIFY_URL = "https://api.ipify.org?format=json"
IP_API_JSON_URL = "http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,as,query,message"
UNKNOWN = "Unknown"
PROXY_TYPES = ("HTTP", "HTTPS", "SOCKS5", "SOCKS4")
STATE_FILTERS = ("California", "New York", "Texas", "Florida")
SCHEDULER_JOB_ID = "proxy_auto_check"
DEFAULT_SCHEDULE_SECONDS = 300
scheduler = BackgroundScheduler(daemon=True)

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
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
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
                <a href="{{ url_for('api_keys_page') }}" class="btn btn-outline-dark mobile-full">
                    API Keys
                </a>
                <a href="{{ url_for('logout') }}" class="btn btn-outline-secondary mobile-full">
                    Logout
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
                        <form action="{{ url_for('update_scheduler') }}" method="post" class="vstack gap-2">
                            <label for="schedule_interval" class="form-label">Interval</label>
                            <select id="schedule_interval" name="interval_seconds" class="form-select">
                                <option value="300" {% if scheduler_config.interval_seconds == 300 %}selected{% endif %}>5 minutes</option>
                                <option value="1800" {% if scheduler_config.interval_seconds == 1800 %}selected{% endif %}>30 minutes</option>
                                <option value="3600" {% if scheduler_config.interval_seconds == 3600 %}selected{% endif %}>1 hour</option>
                                <option value="21600" {% if scheduler_config.interval_seconds == 21600 %}selected{% endif %}>6 hours</option>
                                <option value="custom">Custom</option>
                            </select>
                            <input
                                name="custom_interval_seconds"
                                class="form-control"
                                inputmode="numeric"
                                placeholder="Custom seconds, minimum 60"
                            >
                            <div class="form-check">
                                <input id="schedule_enabled" name="enabled" value="1" type="checkbox" class="form-check-input" {% if scheduler_config.enabled %}checked{% endif %}>
                                <label for="schedule_enabled" class="form-check-label">Enable background scheduler</label>
                            </div>
                            <button type="submit" class="btn btn-primary mobile-full">Save Scheduler</button>
                        </form>
                        <div class="form-text mt-2">
                            Current: {% if scheduler_config.enabled %}enabled{% else %}disabled{% endif %},
                            every {{ scheduler_config.interval_seconds }} seconds.
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

        <section class="row g-3 mb-4">
            <div class="col-6 col-xl-3">
                <div class="card dashboard-card border-0 shadow-sm">
                    <div class="card-body">
                        <div class="text-secondary small">Average Latency</div>
                        <div class="h3 mb-0">{{ dashboard.avg_latency_ms }} ms</div>
                    </div>
                </div>
            </div>
            <div class="col-6 col-xl-3">
                <div class="card dashboard-card border-0 shadow-sm">
                    <div class="card-body">
                        <div class="text-secondary small">Fastest Proxy</div>
                        <div class="fw-semibold proxy-address">{{ dashboard.fastest_proxy or "-" }}</div>
                    </div>
                </div>
            </div>
            <div class="col-6 col-xl-3">
                <div class="card dashboard-card border-0 shadow-sm">
                    <div class="card-body">
                        <div class="text-secondary small">Slowest Proxy</div>
                        <div class="fw-semibold proxy-address">{{ dashboard.slowest_proxy or "-" }}</div>
                    </div>
                </div>
            </div>
            <div class="col-6 col-xl-3">
                <div class="card dashboard-card border-0 shadow-sm">
                    <div class="card-body">
                        <div class="text-secondary small">Average Success Rate</div>
                        <div class="h3 mb-0">{{ dashboard.avg_success_rate }}%</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="row g-4 mb-4">
            <div class="col-12 col-xl-6">
                <div class="card border-0 shadow-sm">
                    <div class="card-header bg-white fw-semibold">Online Rate Trend</div>
                    <div class="card-body"><canvas id="onlineRateChart"></canvas></div>
                </div>
            </div>
            <div class="col-12 col-xl-6">
                <div class="card border-0 shadow-sm">
                    <div class="card-header bg-white fw-semibold">Proxy Growth</div>
                    <div class="card-body"><canvas id="proxyGrowthChart"></canvas></div>
                </div>
            </div>
            <div class="col-12 col-xl-6">
                <div class="card border-0 shadow-sm">
                    <div class="card-header bg-white fw-semibold">Failure Rate</div>
                    <div class="card-body"><canvas id="failureRateChart"></canvas></div>
                </div>
            </div>
            <div class="col-12 col-xl-6">
                <div class="card border-0 shadow-sm">
                    <div class="card-header bg-white fw-semibold">Country Stats</div>
                    <div class="card-body"><canvas id="countryChart"></canvas></div>
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
                            <div class="col-12 col-md-3">
                                <label for="sort" class="form-label">Sort</label>
                                <select id="sort" name="sort" class="form-select">
                                    <option value="">Default</option>
                                    <option value="score" {% if selected_sort == 'score' %}selected{% endif %}>Score</option>
                                    <option value="latency" {% if selected_sort == 'latency' %}selected{% endif %}>Latency</option>
                                    <option value="success_rate" {% if selected_sort == 'success_rate' %}selected{% endif %}>Success Rate</option>
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
                                    <th>Status</th>
                                    <th>Score</th>
                                    <th>Success Rate</th>
                                    <th>Exit IP</th>
                                    <th>Latency</th>
                                    <th>ISP</th>
                                    <th>ASN</th>
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
                                        <td>
                                            {% if proxy.status == 'online' %}
                                                <span class="badge text-bg-success">online</span>
                                            {% elif proxy.status == 'invalid' %}
                                                <span class="badge text-bg-danger">invalid</span>
                                            {% elif proxy.status == 'offline' %}
                                                <span class="badge text-bg-warning">offline</span>
                                            {% else %}
                                                <span class="badge text-bg-secondary">unknown</span>
                                            {% endif %}
                                        </td>
                                        <td>{{ proxy.score }}</td>
                                        <td>{{ proxy.success_rate }}%</td>
                                        <td class="proxy-address">{{ proxy.last_exit_ip or proxy.exit_ip or "-" }}</td>
                                        <td>{{ proxy.last_latency_ms or proxy.latency_ms or "-" }}</td>
                                        <td class="text-break">{{ proxy.last_isp or proxy.isp or "-" }}</td>
                                        <td class="text-break">{{ proxy.last_asn or proxy.asn or "-" }}</td>
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
                                        <td colspan="17" class="text-center text-secondary py-5">
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
        const chartData = {{ chart_data|tojson }};
        const lineOptions = { responsive: true, scales: { y: { beginAtZero: true, max: 100 } } };
        new Chart(document.getElementById("onlineRateChart"), {
            type: "line",
            data: { labels: chartData.labels, datasets: [{ label: "Online %", data: chartData.online_rates, borderColor: "#0d6efd", tension: 0.25 }] },
            options: lineOptions
        });
        new Chart(document.getElementById("proxyGrowthChart"), {
            type: "line",
            data: { labels: chartData.labels, datasets: [{ label: "Proxies", data: chartData.proxy_growth, borderColor: "#198754", tension: 0.25 }] },
            options: { responsive: true, scales: { y: { beginAtZero: true } } }
        });
        new Chart(document.getElementById("failureRateChart"), {
            type: "bar",
            data: { labels: chartData.labels, datasets: [{ label: "Failure %", data: chartData.failure_rates, backgroundColor: "#dc3545" }] },
            options: lineOptions
        });
        new Chart(document.getElementById("countryChart"), {
            type: "doughnut",
            data: { labels: chartData.country_labels, datasets: [{ data: chartData.country_counts, backgroundColor: ["#0d6efd", "#198754", "#ffc107", "#dc3545", "#6f42c1", "#20c997"] }] },
            options: { responsive: true }
        });
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
                <div class="text-secondary">All API requests require the <code>X-API-Key</code> header.</div>
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
                                <code>{{ base_url }}{{ endpoint.path }}</code>
                            </div>
                        {% endfor %}
                    </div>
                </div>
            </div>
            <div class="col-12 col-xl-7">
                <div class="card border-0 shadow-sm mb-4">
                    <div class="card-header bg-white fw-semibold">Example Request</div>
                    <div class="card-body">
                        <pre class="bg-light border rounded p-3 mb-0">GET {{ base_url }}/api/random
X-API-Key: {{ example_api_key }}</pre>
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

AUTH_TEMPLATE = """
<!doctype html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ title }} - ProxyManager</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>body { background: #f4f6f9; }</style>
</head>
<body>
    <main class="container py-5">
        <div class="row justify-content-center">
            <div class="col-12 col-sm-10 col-md-6 col-xl-4">
                <div class="card border-0 shadow-sm">
                    <div class="card-header bg-white fw-semibold">{{ title }}</div>
                    <div class="card-body">
                        {% with messages = get_flashed_messages() %}
                            {% if messages %}
                                {% for message in messages %}
                                    <div class="alert alert-info">{{ message }}</div>
                                {% endfor %}
                            {% endif %}
                        {% endwith %}
                        <form method="post" class="vstack gap-3">
                            <div>
                                <label for="username" class="form-label">Username</label>
                                <input id="username" name="username" class="form-control" required autofocus>
                            </div>
                            <div>
                                <label for="password" class="form-label">Password</label>
                                <input id="password" name="password" type="password" class="form-control" required>
                            </div>
                            <button class="btn btn-primary w-100" type="submit">{{ button_text }}</button>
                        </form>
                    </div>
                    <div class="card-footer bg-white text-center">
                        {% if mode == "login" %}
                            <a href="{{ url_for('register') }}">Create an account</a>
                        {% else %}
                            <a href="{{ url_for('login') }}">Already have an account?</a>
                        {% endif %}
                    </div>
                </div>
            </div>
        </div>
    </main>
</body>
</html>
"""

API_KEYS_TEMPLATE = """
<!doctype html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>API Keys - ProxyManager</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: #f4f6f9; }
        .navbar { border-bottom: 1px solid #dde3ec; }
        code { word-break: break-all; }
        @media (max-width: 575.98px) {
            .mobile-full { width: 100%; }
            .table { min-width: 860px; }
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg bg-white">
        <div class="container-fluid px-4">
            <a class="navbar-brand fw-bold text-decoration-none" href="{{ url_for('index') }}">ProxyManager</a>
            <div class="d-flex flex-column flex-sm-row gap-2">
                <a href="{{ url_for('api_docs') }}" class="btn btn-outline-primary mobile-full">API Docs</a>
                <a href="{{ url_for('logout') }}" class="btn btn-outline-secondary mobile-full">Logout</a>
            </div>
        </div>
    </nav>
    <main class="container-fluid px-4 py-4">
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for message in messages %}
                    <div class="alert alert-info">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <section class="row g-3 mb-4">
            <div class="col-6 col-xl-3"><div class="card border-0 shadow-sm"><div class="card-body"><div class="text-secondary small">Total Users</div><div class="display-6 fw-semibold">{{ metrics.total_users }}</div></div></div></div>
            <div class="col-6 col-xl-3"><div class="card border-0 shadow-sm"><div class="card-body"><div class="text-secondary small">Total API Keys</div><div class="display-6 fw-semibold">{{ metrics.total_api_keys }}</div></div></div></div>
            <div class="col-6 col-xl-3"><div class="card border-0 shadow-sm"><div class="card-body"><div class="text-secondary small">Requests Today</div><div class="display-6 fw-semibold">{{ metrics.today_requests }}</div></div></div></div>
            <div class="col-6 col-xl-3"><div class="card border-0 shadow-sm"><div class="card-body"><div class="text-secondary small">Online Proxies</div><div class="display-6 fw-semibold text-success">{{ metrics.online_proxies }}</div></div></div></div>
        </section>
        <div class="card border-0 shadow-sm mb-4">
            <div class="card-header bg-white fw-semibold">Create API Key</div>
            <div class="card-body">
                <form action="{{ url_for('create_api_key') }}" method="post">
                    <button class="btn btn-primary mobile-full" type="submit">Create Key</button>
                </form>
            </div>
        </div>
        <div class="card border-0 shadow-sm">
            <div class="card-header bg-white fw-semibold">Your API Keys</div>
            <div class="table-responsive">
                <table class="table table-hover mb-0">
                    <thead class="table-light">
                        <tr><th>API Key</th><th>Status</th><th>Created</th><th>Calls</th><th class="text-end">Actions</th></tr>
                    </thead>
                    <tbody>
                        {% for key in api_keys %}
                            <tr>
                                <td><code>{{ key.api_key }}</code></td>
                                <td><span class="badge {% if key.status == 'active' %}text-bg-success{% else %}text-bg-secondary{% endif %}">{{ key.status }}</span></td>
                                <td>{{ key.created_at }}</td>
                                <td>{{ key.call_count }}</td>
                                <td>
                                    <div class="d-flex justify-content-end gap-2">
                                        {% if key.status == 'active' %}
                                            <form action="{{ url_for('disable_api_key', key_id=key.id) }}" method="post"><button class="btn btn-sm btn-outline-warning" type="submit">Disable</button></form>
                                        {% else %}
                                            <form action="{{ url_for('enable_api_key', key_id=key.id) }}" method="post"><button class="btn btn-sm btn-outline-success" type="submit">Enable</button></form>
                                        {% endif %}
                                        <form action="{{ url_for('delete_api_key', key_id=key.id) }}" method="post" onsubmit="return confirm('Delete this API key?');"><button class="btn btn-sm btn-outline-danger" type="submit">Delete</button></form>
                                    </div>
                                </td>
                            </tr>
                        {% else %}
                            <tr><td colspan="5" class="text-center text-secondary py-5">No API keys yet.</td></tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
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
                status TEXT NOT NULL DEFAULT 'unknown',
                score INTEGER NOT NULL DEFAULT 100,
                consecutive_failures INTEGER NOT NULL DEFAULT 0,
                success_count INTEGER NOT NULL DEFAULT 0,
                failure_count INTEGER NOT NULL DEFAULT 0,
                exit_ip TEXT NOT NULL DEFAULT '',
                latency_ms INTEGER,
                isp TEXT NOT NULL DEFAULT '',
                asn TEXT NOT NULL DEFAULT '',
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
                exit_ip TEXT NOT NULL DEFAULT '',
                latency_ms INTEGER,
                isp TEXT NOT NULL DEFAULT '',
                asn TEXT NOT NULL DEFAULT '',
                FOREIGN KEY(proxy_id) REFERENCES proxies(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS api_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                accessed_at TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                success INTEGER NOT NULL,
                user_id INTEGER,
                api_key_id INTEGER,
                status INTEGER NOT NULL DEFAULT 200
            );

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                api_key TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS scheduler_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                enabled INTEGER NOT NULL DEFAULT 0,
                interval_seconds INTEGER NOT NULL DEFAULT 300,
                updated_at TEXT NOT NULL
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
    proxy_column_defaults = {
        "status": "TEXT NOT NULL DEFAULT 'unknown'",
        "score": "INTEGER NOT NULL DEFAULT 100",
        "consecutive_failures": "INTEGER NOT NULL DEFAULT 0",
        "success_count": "INTEGER NOT NULL DEFAULT 0",
        "failure_count": "INTEGER NOT NULL DEFAULT 0",
        "exit_ip": "TEXT NOT NULL DEFAULT ''",
        "latency_ms": "INTEGER",
        "isp": "TEXT NOT NULL DEFAULT ''",
        "asn": "TEXT NOT NULL DEFAULT ''",
    }
    for column, definition in proxy_column_defaults.items():
        if column not in columns:
            db.execute(f"ALTER TABLE proxies ADD COLUMN {column} {definition}")
    check_columns = {
        row["name"] for row in db.execute("PRAGMA table_info(checks)").fetchall()
    }
    check_column_defaults = {
        "exit_ip": "TEXT NOT NULL DEFAULT ''",
        "latency_ms": "INTEGER",
        "isp": "TEXT NOT NULL DEFAULT ''",
        "asn": "TEXT NOT NULL DEFAULT ''",
    }
    for column, definition in check_column_defaults.items():
        if column not in check_columns:
            db.execute(f"ALTER TABLE checks ADD COLUMN {column} {definition}")
    ensure_table(
        db,
        "users",
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """,
    )
    ensure_table(
        db,
        "api_keys",
        """
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            api_key TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """,
    )
    ensure_table(
        db,
        "scheduler_settings",
        """
        CREATE TABLE IF NOT EXISTS scheduler_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            enabled INTEGER NOT NULL DEFAULT 0,
            interval_seconds INTEGER NOT NULL DEFAULT 300,
            updated_at TEXT NOT NULL
        )
        """,
    )
    db.execute(
        """
        INSERT OR IGNORE INTO scheduler_settings (id, enabled, interval_seconds, updated_at)
        VALUES (1, 0, ?, ?)
        """,
        (DEFAULT_SCHEDULE_SECONDS, current_time()),
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS api_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            accessed_at TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            success INTEGER NOT NULL,
            user_id INTEGER,
            api_key_id INTEGER,
            status INTEGER NOT NULL DEFAULT 200
        )
        """
    )
    log_columns = {
        row["name"] for row in db.execute("PRAGMA table_info(api_logs)").fetchall()
    }
    if "user_id" not in log_columns:
        db.execute("ALTER TABLE api_logs ADD COLUMN user_id INTEGER")
    if "api_key_id" not in log_columns:
        db.execute("ALTER TABLE api_logs ADD COLUMN api_key_id INTEGER")
    if "status" not in log_columns:
        db.execute("ALTER TABLE api_logs ADD COLUMN status INTEGER NOT NULL DEFAULT 200")


def ensure_table(db: sqlite3.Connection, _name: str, ddl: str) -> None:
    db.execute(ddl)


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


def proxy_url(proxy: sqlite3.Row) -> str:
    scheme = proxy["proxy_type"].lower()
    if scheme == "socks5":
        scheme = "socks5h"
    return f"{scheme}://{proxy['ip']}:{proxy['port']}"


def proxy_requests_config(proxy: sqlite3.Row) -> dict[str, str]:
    url = proxy_url(proxy)
    return {"http": url, "https": url}


def query_exit_location(exit_ip: str) -> dict[str, str]:
    try:
        response = requests.get(IP_API_JSON_URL.format(ip=exit_ip), timeout=10)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as exc:
        return {
            "country": UNKNOWN,
            "state": UNKNOWN,
            "city": UNKNOWN,
            "isp": UNKNOWN,
            "asn": UNKNOWN,
            "error": str(exc),
        }

    if data.get("status") != "success":
        return {
            "country": UNKNOWN,
            "state": UNKNOWN,
            "city": UNKNOWN,
            "isp": UNKNOWN,
            "asn": UNKNOWN,
            "error": data.get("message", "location lookup failed"),
        }

    return {
        "country": data.get("country") or UNKNOWN,
        "state": data.get("regionName") or UNKNOWN,
        "city": data.get("city") or UNKNOWN,
        "isp": data.get("isp") or UNKNOWN,
        "asn": data.get("as") or UNKNOWN,
        "error": "",
    }


def verify_proxy(proxy: sqlite3.Row) -> dict[str, object]:
    started_at = datetime.now()
    try:
        response = requests.get(
            IPIFY_URL,
            proxies=proxy_requests_config(proxy),
            timeout=CONNECT_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        exit_ip = response.json().get("ip", "")
        if not exit_ip:
            raise requests.RequestException("ipify response did not include ip")
    except (requests.RequestException, ValueError) as exc:
        return {
            "connectable": False,
            "message": str(exc),
            "exit_ip": "",
            "latency_ms": None,
            "country": UNKNOWN,
            "state": UNKNOWN,
            "city": UNKNOWN,
            "isp": UNKNOWN,
            "asn": UNKNOWN,
        }

    latency_ms = int((datetime.now() - started_at).total_seconds() * 1000)
    location = query_exit_location(exit_ip)
    message = "proxy verified"
    if location["error"]:
        message = f"proxy verified; location: {location['error']}"

    return {
        "connectable": True,
        "message": message,
        "exit_ip": exit_ip,
        "latency_ms": latency_ms,
        "country": location["country"],
        "state": location["state"],
        "city": location["city"],
        "isp": location["isp"],
        "asn": location["asn"],
    }


def latency_score_bonus(latency_ms: int | None) -> int:
    if latency_ms is None:
        return 0
    if latency_ms <= 500:
        return 3
    if latency_ms <= 1000:
        return 2
    if latency_ms <= 2000:
        return 1
    if latency_ms >= 5000:
        return -2
    if latency_ms >= 3000:
        return -1
    return 0


def run_check(proxy_id: int) -> sqlite3.Row | None:
    db = get_db()
    proxy = db.execute("SELECT * FROM proxies WHERE id = ?", (proxy_id,)).fetchone()
    if proxy is None:
        return None

    result = verify_proxy(proxy)
    connectable = bool(result["connectable"])
    message = str(result["message"])

    checked_at = current_time()
    db.execute(
        """
        INSERT INTO checks
            (proxy_id, checked_at, connectable, message, country, state, city, exit_ip, latency_ms, isp, asn)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            proxy["id"],
            checked_at,
            1 if connectable else 0,
            message,
            result["country"],
            result["state"],
            result["city"],
            result["exit_ip"],
            result["latency_ms"],
            result["isp"],
            result["asn"],
        ),
    )
    if connectable:
        new_status = "online"
        new_score = min(100, proxy["score"] + 1 + latency_score_bonus(result["latency_ms"]))
        db.execute(
            """
            UPDATE proxies
            SET
                status = ?,
                score = ?,
                consecutive_failures = 0,
                success_count = success_count + 1,
                exit_ip = ?,
                latency_ms = ?,
                isp = ?,
                asn = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                new_status,
                new_score,
                result["exit_ip"],
                result["latency_ms"],
                result["isp"],
                result["asn"],
                checked_at,
                proxy["id"],
            ),
        )
    else:
        consecutive_failures = proxy["consecutive_failures"] + 1
        new_status = "invalid" if consecutive_failures >= 3 else proxy["status"]
        if new_status == "unknown":
            new_status = "offline"
        new_score = max(0, proxy["score"] - 5)
        db.execute(
            """
            UPDATE proxies
            SET
                status = ?,
                score = ?,
                consecutive_failures = ?,
                failure_count = failure_count + 1,
                updated_at = ?
            WHERE id = ?
            """,
            (new_status, new_score, consecutive_failures, checked_at, proxy["id"]),
        )
    db.commit()
    return proxy


def fetch_proxies(query: str = "", state: str = "", sort_by: str = "") -> list[sqlite3.Row]:
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

    order_by = "p.created_at DESC, p.id DESC"
    if sort_by == "score":
        order_by = "p.score DESC, p.created_at DESC"
    elif sort_by == "latency":
        order_by = "CASE WHEN p.latency_ms IS NULL THEN 1 ELSE 0 END, p.latency_ms ASC"
    elif sort_by == "success_rate":
        order_by = "success_rate DESC, p.created_at DESC"

    return get_db().execute(
        """
        SELECT
            p.*,
            c.checked_at AS last_checked_at,
            c.connectable AS last_connectable,
            c.message AS last_message,
            c.country,
            c.state,
            c.city,
            c.exit_ip AS last_exit_ip,
            c.latency_ms AS last_latency_ms,
            c.isp AS last_isp,
            c.asn AS last_asn,
            CASE
                WHEN (p.success_count + p.failure_count) = 0 THEN 0
                ELSE ROUND((p.success_count * 100.0) / (p.success_count + p.failure_count), 1)
            END AS success_rate
        FROM proxies p
        LEFT JOIN checks c ON c.id = (
            SELECT id FROM checks
            WHERE proxy_id = p.id
            ORDER BY checked_at DESC, id DESC
            LIMIT 1
        )
        """ + where + """
        ORDER BY """ + order_by + """
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
    latencies = [
        proxy["latency_ms"] for proxy in proxies
        if proxy["latency_ms"] is not None and proxy["status"] == "online"
    ]
    avg_latency_ms = round(sum(latencies) / len(latencies)) if latencies else 0
    fastest = min(
        (proxy for proxy in proxies if proxy["latency_ms"] is not None),
        key=lambda proxy: proxy["latency_ms"],
        default=None,
    )
    slowest = max(
        (proxy for proxy in proxies if proxy["latency_ms"] is not None),
        key=lambda proxy: proxy["latency_ms"],
        default=None,
    )
    rates = [proxy["success_rate"] for proxy in proxies if proxy["success_rate"] is not None]
    avg_success_rate = round(sum(rates) / len(rates), 1) if rates else 0

    return {
        "online_rate": round((online / total) * 100, 1) if total else 0,
        "last_checked_at": last_checked_at,
        "state_counts": state_counts,
        "avg_latency_ms": avg_latency_ms,
        "fastest_proxy": f"{fastest['ip']}:{fastest['port']} ({fastest['latency_ms']} ms)" if fastest else "",
        "slowest_proxy": f"{slowest['ip']}:{slowest['port']} ({slowest['latency_ms']} ms)" if slowest else "",
        "avg_success_rate": avg_success_rate,
    }


def build_chart_data() -> dict[str, list]:
    rows = get_db().execute(
        """
        SELECT substr(checked_at, 1, 10) AS day,
               SUM(CASE WHEN connectable = 1 THEN 1 ELSE 0 END) AS success_count,
               COUNT(*) AS total_count
        FROM checks
        GROUP BY day
        ORDER BY day DESC
        LIMIT 7
        """
    ).fetchall()
    rows = list(reversed(rows))
    labels = [row["day"] for row in rows]
    online_rates = [
        round((row["success_count"] * 100.0) / row["total_count"], 1) if row["total_count"] else 0
        for row in rows
    ]
    failure_rates = [
        round(((row["total_count"] - row["success_count"]) * 100.0) / row["total_count"], 1)
        if row["total_count"] else 0
        for row in rows
    ]
    proxy_growth = []
    for day in labels:
        proxy_growth.append(
            get_db().execute(
                "SELECT COUNT(*) FROM proxies WHERE substr(created_at, 1, 10) <= ?",
                (day,),
            ).fetchone()[0]
        )

    country_rows = get_db().execute(
        """
        SELECT COALESCE(c.country, ?) AS country, COUNT(*) AS count
        FROM proxies p
        LEFT JOIN checks c ON c.id = (
            SELECT id FROM checks
            WHERE proxy_id = p.id
            ORDER BY checked_at DESC, id DESC
            LIMIT 1
        )
        GROUP BY country
        ORDER BY count DESC
        LIMIT 6
        """,
        (UNKNOWN,),
    ).fetchall()

    if not labels:
        labels = [datetime.now().strftime("%Y-%m-%d")]
        online_rates = [0]
        failure_rates = [0]
        proxy_growth = [get_db().execute("SELECT COUNT(*) FROM proxies").fetchone()[0]]

    return {
        "labels": labels,
        "online_rates": online_rates,
        "failure_rates": failure_rates,
        "proxy_growth": proxy_growth,
        "country_labels": [row["country"] for row in country_rows] or [UNKNOWN],
        "country_counts": [row["count"] for row in country_rows] or [0],
    }


def run_all_checks() -> int:
    proxies = get_db().execute("SELECT id FROM proxies ORDER BY id").fetchall()
    for proxy in proxies:
        run_check(proxy["id"])
    return len(proxies)


def scheduled_check_job() -> None:
    with app.app_context():
        run_all_checks()


def scheduler_settings() -> sqlite3.Row:
    return get_db().execute("SELECT * FROM scheduler_settings WHERE id = 1").fetchone()


def configure_scheduler(enabled: bool, interval_seconds: int) -> None:
    interval_seconds = max(60, int(interval_seconds))
    get_db().execute(
        """
        UPDATE scheduler_settings
        SET enabled = ?, interval_seconds = ?, updated_at = ?
        WHERE id = 1
        """,
        (1 if enabled else 0, interval_seconds, current_time()),
    )
    get_db().commit()
    apply_scheduler_settings(enabled, interval_seconds)


def apply_scheduler_settings(enabled: bool, interval_seconds: int) -> None:
    if scheduler.get_job(SCHEDULER_JOB_ID):
        scheduler.remove_job(SCHEDULER_JOB_ID)
    if enabled:
        scheduler.add_job(
            scheduled_check_job,
            "interval",
            seconds=max(60, int(interval_seconds)),
            id=SCHEDULER_JOB_ID,
            replace_existing=True,
            coalesce=True,
            max_instances=1,
        )


def start_scheduler() -> None:
    with app.app_context():
        settings = scheduler_settings()
        apply_scheduler_settings(bool(settings["enabled"]), settings["interval_seconds"])
    if not scheduler.running:
        scheduler.start()


def serialize_proxy(proxy: sqlite3.Row) -> dict[str, object]:
    return {
        "ip": proxy["ip"],
        "port": proxy["port"],
        "proxy_type": proxy["proxy_type"],
        "country": proxy["country"] or UNKNOWN,
        "state": proxy["state"] or UNKNOWN,
        "city": proxy["city"] or UNKNOWN,
        "exit_ip": proxy["exit_ip"] or "",
        "latency_ms": proxy["latency_ms"],
        "isp": proxy["isp"] or "",
        "asn": proxy["asn"] or "",
        "success_rate": proxy["success_rate"],
        "score": proxy["score"],
        "last_checked": proxy["last_checked_at"],
    }


def get_current_user() -> sqlite3.Row | None:
    user_id = session.get("user_id")
    if not user_id:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def login_required():
    if get_current_user() is None:
        return redirect(url_for("login"))
    return None


def generate_api_key() -> str:
    return "pm_" + secrets.token_urlsafe(32)


def find_api_key() -> sqlite3.Row | None:
    api_key = request.headers.get("X-API-Key", "").strip()
    if not api_key:
        return None
    return get_db().execute(
        """
        SELECT k.*, u.username
        FROM api_keys k
        JOIN users u ON u.id = k.user_id
        WHERE k.api_key = ? AND k.status = 'active'
        """,
        (api_key,),
    ).fetchone()


def log_api_request(endpoint: str, success: bool, api_key: sqlite3.Row | None, status_code: int) -> None:
    get_db().execute(
        """
        INSERT INTO api_logs
            (accessed_at, endpoint, client_ip, success, user_id, api_key_id, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            current_time(),
            endpoint,
            request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip(),
            1 if success else 0,
            api_key["user_id"] if api_key else None,
            api_key["id"] if api_key else None,
            status_code,
        ),
    )
    get_db().commit()


def api_error(message: str, status_code: int):
    log_api_request(request.path, False, None, status_code)
    response = jsonify({"success": False, "error": message})
    response.status_code = status_code
    return response


def require_api_key():
    api_key = find_api_key()
    if api_key is None:
        return None, api_error("invalid api key", 401)
    return api_key, None


def fetch_online_proxies(
    country: str | None = None,
    state: str | None = None,
    city: str | None = None,
) -> list[sqlite3.Row]:
    conditions = ["c.connectable = 1", "p.status = 'online'"]
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
            p.score,
            p.latency_ms,
            p.isp,
            p.asn,
            p.success_count,
            p.failure_count,
            c.country,
            c.state,
            c.city,
            c.exit_ip,
            c.latency_ms AS check_latency_ms,
            c.isp AS check_isp,
            c.asn AS check_asn,
            c.checked_at AS last_checked_at,
            CASE
                WHEN (p.success_count + p.failure_count) = 0 THEN 0
                ELSE ROUND((p.success_count * 100.0) / (p.success_count + p.failure_count), 1)
            END AS success_rate
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


def api_success(data, api_key: sqlite3.Row):
    log_api_request(request.path, True, api_key, 200)
    count = len(data) if isinstance(data, list) else 0 if data is None else 1
    return jsonify({"success": True, "count": count, "data": data})


def dashboard_metrics() -> dict[str, int]:
    today = datetime.now().strftime("%Y-%m-%d")
    return {
        "total_users": get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "total_api_keys": get_db().execute("SELECT COUNT(*) FROM api_keys").fetchone()[0],
        "today_requests": get_db().execute(
            "SELECT COUNT(*) FROM api_logs WHERE accessed_at LIKE ?", (f"{today}%",)
        ).fetchone()[0],
        "online_proxies": len(fetch_online_proxies()),
    }


def user_api_keys(user_id: int) -> list[sqlite3.Row]:
    return get_db().execute(
        """
        SELECT
            k.*,
            COUNT(l.id) AS call_count
        FROM api_keys k
        LEFT JOIN api_logs l ON l.api_key_id = k.id
        WHERE k.user_id = ?
        GROUP BY k.id
        ORDER BY k.created_at DESC, k.id DESC
        """,
        (user_id,),
    ).fetchall()


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
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
    query = request.args.get("q", "").strip()
    selected_state = request.args.get("state", "").strip()
    selected_sort = request.args.get("sort", "").strip()
    if selected_state not in STATE_FILTERS:
        selected_state = ""
    if selected_sort not in {"score", "latency", "success_rate"}:
        selected_sort = ""
    proxies = fetch_proxies(query, selected_state, selected_sort)
    return render_template_string(
        PAGE_TEMPLATE,
        UNKNOWN=UNKNOWN,
        chart_data=build_chart_data(),
        dashboard=build_dashboard_stats(fetch_proxies()),
        query=query,
        proxy_types=PROXY_TYPES,
        proxies=proxies,
        recent_checks=fetch_recent_checks(),
        scheduler_config=scheduler_settings(),
        selected_state=selected_state,
        selected_sort=selected_sort,
        state_filters=STATE_FILTERS,
        stats=build_stats(proxies),
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Username and password are required.")
            return redirect(url_for("register"))
        try:
            cursor = get_db().execute(
                """
                INSERT INTO users (username, password_hash, created_at)
                VALUES (?, ?, ?)
                """,
                (username, generate_password_hash(password), current_time()),
            )
            get_db().commit()
            session["user_id"] = cursor.lastrowid
            flash("Account created.")
            return redirect(url_for("index"))
        except sqlite3.IntegrityError:
            flash("Username already exists.")
    return render_template_string(
        AUTH_TEMPLATE,
        title="Register",
        button_text="Create Account",
        mode="register",
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            flash("Logged in.")
            return redirect(url_for("index"))
        flash("Invalid username or password.")
    return render_template_string(
        AUTH_TEMPLATE,
        title="Login",
        button_text="Login",
        mode="login",
    )


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for("login"))


@app.route("/api-keys")
def api_keys_page():
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
    user = get_current_user()
    return render_template_string(
        API_KEYS_TEMPLATE,
        api_keys=user_api_keys(user["id"]),
        metrics=dashboard_metrics(),
    )


@app.route("/api-keys", methods=["POST"])
def create_api_key():
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
    user = get_current_user()
    get_db().execute(
        """
        INSERT INTO api_keys (user_id, api_key, status, created_at)
        VALUES (?, ?, 'active', ?)
        """,
        (user["id"], generate_api_key(), current_time()),
    )
    get_db().commit()
    flash("API key created.")
    return redirect(url_for("api_keys_page"))


def update_api_key_status(key_id: int, status: str):
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
    user = get_current_user()
    get_db().execute(
        "UPDATE api_keys SET status = ? WHERE id = ? AND user_id = ?",
        (status, key_id, user["id"]),
    )
    get_db().commit()
    flash(f"API key {status}.")
    return redirect(url_for("api_keys_page"))


@app.route("/api-keys/<int:key_id>/enable", methods=["POST"])
def enable_api_key(key_id: int):
    return update_api_key_status(key_id, "active")


@app.route("/api-keys/<int:key_id>/disable", methods=["POST"])
def disable_api_key(key_id: int):
    return update_api_key_status(key_id, "disabled")


@app.route("/api-keys/<int:key_id>/delete", methods=["POST"])
def delete_api_key(key_id: int):
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
    user = get_current_user()
    get_db().execute("DELETE FROM api_keys WHERE id = ? AND user_id = ?", (key_id, user["id"]))
    get_db().commit()
    flash("API key deleted.")
    return redirect(url_for("api_keys_page"))


@app.route("/proxies", methods=["POST"])
def create_proxy():
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
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
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
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
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
    proxy = run_check(proxy_id)
    if proxy is None:
        flash("\u4ee3\u7406\u4e0d\u5b58\u5728\u3002")
    else:
        flash(f"\u5df2\u68c0\u6d4b {proxy['ip']}:{proxy['port']}\u3002")
    return redirect(url_for("index"))


@app.route("/checks/run-all", methods=["POST"])
def check_all():
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
    checked_count = run_all_checks()
    flash(f"\u6279\u91cf\u68c0\u6d4b\u5b8c\u6210\uff0c\u5171\u68c0\u6d4b {checked_count} \u4e2a\u4ee3\u7406\u3002")
    return redirect(url_for("index"))


@app.route("/scheduler", methods=["POST"])
def update_scheduler():
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
    enabled = request.form.get("enabled") == "1"
    interval_text = request.form.get("interval_seconds", "300")
    if interval_text == "custom":
        interval_text = request.form.get("custom_interval_seconds", "300")
    try:
        interval_seconds = int(interval_text)
    except ValueError:
        interval_seconds = DEFAULT_SCHEDULE_SECONDS
    interval_seconds = max(60, interval_seconds)
    configure_scheduler(enabled, interval_seconds)
    flash(f"Scheduler {'enabled' if enabled else 'disabled'}; interval {interval_seconds} seconds.")
    return redirect(url_for("index"))


@app.route("/proxies/<int:proxy_id>/delete", methods=["POST"])
def delete_proxy(proxy_id: int):
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
    get_db().execute("DELETE FROM proxies WHERE id = ?", (proxy_id,))
    get_db().commit()
    flash("\u4ee3\u7406\u5df2\u5220\u9664\u3002")
    return redirect(url_for("index"))


@app.route("/proxies/delete-all", methods=["POST"])
def delete_all_proxies():
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
    deleted = get_db().execute("SELECT COUNT(*) FROM proxies").fetchone()[0]
    get_db().execute("DELETE FROM proxies")
    get_db().commit()
    flash(f"\u5df2\u5220\u9664\u5168\u90e8 {deleted} \u4e2a\u4ee3\u7406\u53ca\u5176\u5386\u53f2\u8bb0\u5f55\u3002")
    return redirect(url_for("index"))


@app.route("/export.csv")
def export_csv():
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
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
            "exit_ip",
            "latency_ms",
            "isp",
            "asn",
            "success_rate",
            "score",
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
                proxy["last_exit_ip"] or proxy["exit_ip"] or "",
                proxy["last_latency_ms"] or proxy["latency_ms"] or "",
                proxy["last_isp"] or proxy["isp"] or "",
                proxy["last_asn"] or proxy["asn"] or "",
                proxy["success_rate"],
                proxy["score"],
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
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
    endpoints = [
        {"method": "GET", "path": "/api/proxies"},
        {"method": "GET", "path": "/api/random"},
        {"method": "GET", "path": "/api/country/United States"},
        {"method": "GET", "path": "/api/state/California"},
        {"method": "GET", "path": "/api/city/Los Angeles"},
    ]
    return render_template_string(
        API_DOCS_TEMPLATE,
        example_api_key="pm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        base_url=request.host_url.rstrip("/"),
        endpoints=endpoints,
    )


@app.route("/api/proxies")
def api_proxies():
    api_key, key_error = require_api_key()
    if key_error:
        return key_error
    proxies = [serialize_proxy(proxy) for proxy in fetch_online_proxies()]
    return api_success(proxies, api_key)


@app.route("/api/random")
def api_random():
    api_key, key_error = require_api_key()
    if key_error:
        return key_error
    proxies = fetch_online_proxies()
    if not proxies:
        return api_success(None, api_key)
    return api_success(serialize_proxy(random.choice(proxies)), api_key)


@app.route("/api/country/<path:country>")
def api_country(country: str):
    api_key, key_error = require_api_key()
    if key_error:
        return key_error
    proxies = [serialize_proxy(proxy) for proxy in fetch_online_proxies(country=country)]
    return api_success(proxies, api_key)


@app.route("/api/state/<path:state>")
def api_state(state: str):
    api_key, key_error = require_api_key()
    if key_error:
        return key_error
    proxies = [serialize_proxy(proxy) for proxy in fetch_online_proxies(state=state)]
    return api_success(proxies, api_key)


@app.route("/api/city/<path:city>")
def api_city(city: str):
    api_key, key_error = require_api_key()
    if key_error:
        return key_error
    proxies = [serialize_proxy(proxy) for proxy in fetch_online_proxies(city=city)]
    return api_success(proxies, api_key)


@app.route("/health")
def health():
    return {"status": "ok"}


init_db()


if __name__ == "__main__":
    start_scheduler()
    app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)
