import csv
import io
import ipaddress
import json
import os
import sqlite3
import socket
import urllib.error
import urllib.request
import random
import secrets
import shutil
import ssl
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlparse

import requests
from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask, Response, flash, g, jsonify, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
APP_DIR = Path(__file__).resolve().parent


def resolve_database_path(database_url: str) -> str:
    if database_url.startswith("sqlite:///"):
        return database_url.removeprefix("sqlite:///")
    if database_url.startswith("sqlite://"):
        return database_url.removeprefix("sqlite://")
    return database_url


app.config["DATABASE"] = resolve_database_path(
    os.environ.get("DATABASE_URL", "sqlite:///proxy_manager.db")
)
app.secret_key = os.environ.get("SECRET_KEY", "proxy-manager-dev-secret")

CSV_FILE = Path("proxy_check_results.csv")
CONNECT_TIMEOUT_SECONDS = 30
PROXY_CHECK_RETRY_ATTEMPTS = 3
PROXY_CHECK_RETRY_DELAY_SECONDS = 2
IPIFY_URL = "https://api.ipify.org?format=json"
IP_API_JSON_URL = "http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,as,query,message"
IPWHOIS_URL = "https://ipwho.is/{ip}"
UNKNOWN = "Unknown"
PROXY_TYPES = ("HTTP", "HTTPS", "SOCKS5", "SOCKS4")
PROTOCOL_STATUSES = ("端口开放", "协议错误", "认证失败", "超时", "连接重置", "无代理服务")
NODE_STATUS_CONFIG_OK = "配置正常"
NODE_STATUS_PORT_OPEN = "端口开放"
NODE_STATUS_PORT_CLOSED = "端口关闭"
NODE_STATUS_PARSE_FAILED = "解析失败"
NODE_STATUS_AVAILABLE = "可用"
NODE_STATUS_UNAVAILABLE = "不可用"
NODE_STATUSES = (
    NODE_STATUS_CONFIG_OK,
    NODE_STATUS_PORT_OPEN,
    NODE_STATUS_PORT_CLOSED,
    NODE_STATUS_PARSE_FAILED,
    NODE_STATUS_AVAILABLE,
    NODE_STATUS_UNAVAILABLE,
)
XRAY_TEST_TIMEOUT_SECONDS = 20
XRAY_SOCKS_TEST_PORT = 10888
STATE_FILTERS = ("California", "New York", "Texas", "Florida")
LOCATION_DISPLAY_NAMES = {
    "": "-",
    "Unknown": "未知",
    "United States": "美国",
    "USA": "美国",
    "US": "美国",
    "California": "加利福尼亚州",
    "New York": "纽约州",
    "Texas": "得克萨斯州",
    "Florida": "佛罗里达州",
    "Arizona": "亚利桑那州",
    "Los Angeles": "洛杉矶",
    "Phoenix": "凤凰城",
    "Mesa": "梅萨",
    "New York City": "纽约市",
    "Miami": "迈阿密",
    "Dallas": "达拉斯",
    "Houston": "休斯敦",
}
HEALTH_LEVELS = ("健康", "一般", "危险", "失效")
FAILURE_REASONS = (
    "DNS失败",
    "连接超时",
    "连接被拒绝",
    "连接重置",
    "TLS失败",
    "HTTP失败",
    "出口IP获取失败",
    "地理位置查询失败",
)
FAILURE_REASON_SUMMARY = ("连接超时", "连接重置", "TLS失败", "出口IP获取失败")
UNCATEGORIZED_REASON = "未分类"
INVALID_FAILURE_THRESHOLD = 5
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

        .proxy-table {
            table-layout: fixed;
            min-width: 1160px;
            font-size: 0.82rem;
        }

        .history-table {
            table-layout: fixed;
            min-width: 1040px;
            font-size: 0.78rem;
        }

        .proxy-table th,
        .proxy-table td,
        .history-table th,
        .history-table td {
            padding: 0.45rem 0.5rem;
            line-height: 1.25;
        }

        .history-table .badge {
            font-size: 0.68rem;
            padding: 0.28em 0.55em;
        }

        .proxy-address {
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: 0.78rem;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .proxy-cell {
            min-width: 0;
        }

        .proxy-rank-badge {
            font-size: 0.62rem;
            line-height: 1;
            padding: 0.22rem 0.32rem;
        }

        .proxy-recommend-score {
            color: #6c757d;
            font-family: var(--bs-body-font-family);
            font-size: 0.68rem;
            margin-top: 0.18rem;
        }

        .cell-compact {
            max-width: 100%;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .cell-tiny {
            width: 66px;
        }

        .cell-small {
            width: 92px;
        }

        .cell-medium {
            width: 128px;
        }

        .cell-proxy {
            width: 170px;
        }

        .cell-large {
            width: 180px;
        }

        .cell-provider {
            width: 190px;
        }

        .cell-customer {
            width: 170px;
        }

        .cell-message {
            width: 220px;
        }

        .cell-failures {
            width: 78px;
        }

        .cell-health {
            width: 76px;
        }

        .cell-reason {
            width: 126px;
        }

        .cell-protocol {
            width: 96px;
        }

        .cell-auth {
            width: 92px;
        }

        .diagnostic-row {
            background: #fbfcfe;
        }

        .diagnostic-table {
            font-size: 0.76rem;
        }

        .history-time {
            width: 132px;
        }

        .history-status {
            width: 84px;
        }

        .history-message {
            width: 420px;
        }

        .chart-body {
            height: 260px;
            padding: 1rem 1.25rem;
        }

        .chart-body canvas {
            width: 100% !important;
            height: 100% !important;
        }

        .dashboard-card {
            min-height: 100%;
        }

        .compact-dashboard-card {
            min-height: 112px;
        }

        .compact-dashboard-card .card-body {
            padding: 0.65rem 0.85rem;
        }

        .compact-dashboard-card .card-header {
            padding-bottom: 0.45rem;
            padding-top: 0.45rem;
        }

        .compact-metric {
            font-size: 1.75rem;
            line-height: 1.1;
        }

        .scheduler-compact-form {
            align-items: end;
            display: grid;
            gap: 0.75rem;
            grid-template-columns: minmax(120px, 1fr) minmax(96px, 0.75fr) auto auto;
        }

        .scheduler-switch {
            min-height: 38px;
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

            .compact-dashboard-card {
                min-height: auto;
            }

            .scheduler-compact-form {
                grid-template-columns: 1fr;
            }

            .display-6 {
                font-size: 1.8rem;
            }

            .proxy-table {
                min-width: 1080px;
                font-size: 0.78rem;
            }

            .history-table {
                min-width: 920px;
                font-size: 0.74rem;
            }

            .chart-body {
                height: 220px;
                padding: 0.75rem;
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
                <a href="{{ url_for('analytics_page') }}" class="btn btn-outline-primary mobile-full">
                    &#25968;&#25454;&#20998;&#26512;
                </a>
                <a href="{{ url_for('nodes_page') }}" class="btn btn-outline-dark mobile-full">
                    节点管理
                </a>
                <a href="{{ url_for('api_keys_page') }}" class="btn btn-outline-dark mobile-full">
                    API Keys
                </a>
                <a href="{{ url_for('providers_page') }}" class="btn btn-outline-dark mobile-full">
                    来源管理
                </a>
                <a href="{{ url_for('customers_page') }}" class="btn btn-outline-dark mobile-full">
                    客户管理
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
            <div class="col-12">
                <div class="card dashboard-card border-0 shadow-sm">
                    <div class="card-body d-flex flex-column flex-lg-row justify-content-between gap-3">
                        <div>
                            <div class="text-secondary small">最佳代理</div>
                            {% if dashboard.best_proxy %}
                                <div class="h4 mb-1 proxy-address">
                                    {{ dashboard.best_proxy.ip }}:{{ dashboard.best_proxy.port }}
                                </div>
                                <div class="text-secondary small">
                                    类型 {{ dashboard.best_proxy.proxy_type }} · 来源 {{ dashboard.best_proxy.provider_name or "IPRoyal" }}
                                </div>
                            {% else %}
                                <div class="h4 mb-1">-</div>
                                <div class="text-secondary small">暂无可推荐代理</div>
                            {% endif %}
                        </div>
                        <div class="row g-3 flex-fill">
                            <div class="col-4">
                                <div class="text-secondary small">推荐分</div>
                                <div class="h4 mb-0">{{ dashboard.best_proxy_recommend_score }}</div>
                            </div>
                            <div class="col-4">
                                <div class="text-secondary small">成功率</div>
                                <div class="h4 mb-0">{% if dashboard.best_proxy %}{{ dashboard.best_proxy.success_rate }}%{% else %}-{% endif %}</div>
                            </div>
                            <div class="col-4">
                                <div class="text-secondary small">延迟</div>
                                <div class="h4 mb-0">{% if dashboard.best_proxy %}{{ dashboard.best_proxy.last_latency_ms or dashboard.best_proxy.latency_ms or "-" }} ms{% else %}-{% endif %}</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-12 col-xl-4">
                <div class="card compact-dashboard-card border-0 shadow-sm">
                    <div class="card-header bg-white fw-semibold">自动检测</div>
                    <div class="card-body">
                        <form action="{{ url_for('update_scheduler') }}" method="post" class="scheduler-compact-form">
                            <div>
                                <label for="schedule_interval" class="form-label small mb-1">检测间隔</label>
                                <select id="schedule_interval" name="interval_seconds" class="form-select form-select-sm">
                                    <option value="300" {% if scheduler_config.interval_seconds == 300 %}selected{% endif %}>5 minutes</option>
                                    <option value="1800" {% if scheduler_config.interval_seconds == 1800 %}selected{% endif %}>30 minutes</option>
                                    <option value="3600" {% if scheduler_config.interval_seconds == 3600 %}selected{% endif %}>1 hour</option>
                                    <option value="21600" {% if scheduler_config.interval_seconds == 21600 %}selected{% endif %}>6 hours</option>
                                    <option value="custom">Custom</option>
                                </select>
                            </div>
                            <div>
                                <label class="form-label small mb-1">自定义秒数</label>
                                <input
                                    name="custom_interval_seconds"
                                    class="form-control form-control-sm"
                                    inputmode="numeric"
                                    placeholder=">= 60"
                                >
                            </div>
                            <div class="form-check form-switch scheduler-switch d-flex align-items-center">
                                <input id="schedule_enabled" name="enabled" value="1" type="checkbox" class="form-check-input me-2" {% if scheduler_config.enabled %}checked{% endif %}>
                                <label for="schedule_enabled" class="form-check-label small">开启</label>
                            </div>
                            <button type="submit" class="btn btn-sm btn-primary mobile-full">保存</button>
                        </form>
                    </div>
                </div>
            </div>
            <div class="col-12 col-xl-4">
                <div class="card compact-dashboard-card border-0 shadow-sm">
                    <div class="card-header bg-white fw-semibold">在线率</div>
                    <div class="card-body d-flex flex-column justify-content-center">
                        <div class="compact-metric fw-semibold text-primary">{{ dashboard.online_rate }}%</div>
                        <div class="text-secondary small">{{ stats.online }} / {{ stats.total }} 个在线</div>
                    </div>
                </div>
            </div>
            <div class="col-12 col-xl-4">
                <div class="card compact-dashboard-card border-0 shadow-sm">
                    <div class="card-header bg-white fw-semibold">Latest Check</div>
                    <div class="card-body d-flex flex-column justify-content-center">
                        <div class="h6 mb-1">{{ dashboard.last_checked_at or "-" }}</div>
                        <div class="text-secondary small">最近一条检测记录</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="row g-3 mb-4">
            <div class="col-6 col-xl">
                <div class="card dashboard-card border-0 shadow-sm">
                    <div class="card-body">
                        <div class="text-secondary small">平均延迟</div>
                        <div class="h3 mb-0">{{ dashboard.avg_latency_ms }} ms</div>
                    </div>
                </div>
            </div>
            <div class="col-6 col-xl">
                <div class="card dashboard-card border-0 shadow-sm">
                    <div class="card-body">
                        <div class="text-secondary small">最快代理</div>
                        <div class="fw-semibold proxy-address">{{ dashboard.fastest_proxy or "-" }}</div>
                    </div>
                </div>
            </div>
            <div class="col-6 col-xl">
                <div class="card dashboard-card border-0 shadow-sm">
                    <div class="card-body">
                        <div class="text-secondary small">最慢代理</div>
                        <div class="fw-semibold proxy-address">{{ dashboard.slowest_proxy or "-" }}</div>
                    </div>
                </div>
            </div>
            <div class="col-6 col-xl">
                <div class="card dashboard-card border-0 shadow-sm">
                    <div class="card-body">
                        <div class="text-secondary small">平均成功率</div>
                        <div class="h3 mb-0">{{ dashboard.avg_success_rate }}%</div>
                    </div>
                </div>
            </div>
            <div class="col-12 col-xl">
                <div class="card dashboard-card border-0 shadow-sm">
                    <div class="card-body">
                        <div class="text-secondary small">主要 ISP</div>
                        <div class="fw-semibold text-break">{{ dashboard.top_isp or "-" }}</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="row g-3 mb-4">
            {% for reason in failure_summary_reasons %}
                <div class="col-6 col-xl-3">
                    <div class="card dashboard-card border-0 shadow-sm">
                        <div class="card-body">
                            <div class="text-secondary small">{{ reason }}</div>
                            <div class="h3 mb-0 text-danger">{{ dashboard.failure_reason_counts.get(reason, 0) }}</div>
                        </div>
                    </div>
                </div>
            {% endfor %}
        </section>

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
                            placeholder="IP / 端口 / 备注 / 国家 / 州 / 城市"
                        >
                    </div>
                    <div class="col-12 col-md-3">
                        <label for="state" class="form-label">州筛选</label>
                        <select id="state" name="state" class="form-select">
                            <option value="">全部州</option>
                            {% for state in state_filters %}
                                <option value="{{ state }}" {% if selected_state == state %}selected{% endif %}>
                                    {{ state }}
                                </option>
                            {% endfor %}
                        </select>
                    </div>
                    <div class="col-12 col-md-3">
                        <label for="sort" class="form-label">排序</label>
                        <select id="sort" name="sort" class="form-select">
                            <option value="">默认</option>
                            <option value="score" {% if selected_sort == 'score' %}selected{% endif %}>按评分</option>
                            <option value="latency" {% if selected_sort == 'latency' %}selected{% endif %}>按延迟</option>
                            <option value="success_rate" {% if selected_sort == 'success_rate' %}selected{% endif %}>按成功率</option>
                            <option value="provider" {% if selected_sort == 'provider' %}selected{% endif %}>按来源</option>
                        </select>
                    </div>
                    <div class="col-12 col-md-3">
                        <label for="provider_filter" class="form-label">来源筛选</label>
                        <select id="provider_filter" name="provider" class="form-select">
                            <option value="">全部来源</option>
                            {% for provider in providers %}
                                <option value="{{ provider.id }}" {% if selected_provider_id == provider.id %}selected{% endif %}>{{ provider.name }}</option>
                            {% endfor %}
                        </select>
                    </div>
                    <div class="col-12 col-md-3">
                        <label for="customer_filter" class="form-label">客户筛选</label>
                        <select id="customer_filter" name="customer" class="form-select">
                            <option value="">全部客户</option>
                            <option value="unassigned" {% if selected_customer_filter == 'unassigned' %}selected{% endif %}>未分配</option>
                            {% for customer in customers %}
                                <option value="{{ customer.id }}" {% if selected_customer_id == customer.id %}selected{% endif %}>{{ customer.name }}</option>
                            {% endfor %}
                        </select>
                    </div>
                    <div class="col-12 col-md-3">
                        <label for="health" class="form-label">健康等级</label>
                        <select id="health" name="health" class="form-select">
                            <option value="">全部等级</option>
                            {% for level in health_levels %}
                                <option value="{{ level }}" {% if selected_health == level %}selected{% endif %}>{{ level }}</option>
                            {% endfor %}
                        </select>
                    </div>
                    <div class="col-12 col-md-3">
                        <label for="failure_reason" class="form-label">失败原因</label>
                        <select id="failure_reason" name="failure_reason" class="form-select">
                            <option value="">全部原因</option>
                            {% for reason in failure_reasons %}
                                <option value="{{ reason }}" {% if selected_failure_reason == reason %}selected{% endif %}>{{ reason }}</option>
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

        <section class="vstack gap-4">
            <div>
                <div class="card border-0 shadow-sm">
                    <div class="card-header bg-white fw-semibold">单个代理添加</div>
                    <div class="card-body">
                        <form action="{{ url_for('create_proxy') }}" method="post" class="row g-3 align-items-end">
                            <div class="col-12 col-md-3 col-xl-2">
                                <label for="ip" class="form-label">IP</label>
                                <input
                                    id="ip"
                                    name="ip"
                                    class="form-control"
                                    placeholder="8.8.8.8"
                                    required
                                >
                            </div>
                            <div class="col-12 col-md-2 col-xl-1">
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
                            <div class="col-12 col-md-3 col-xl-2">
                                <label for="proxy_username" class="form-label">认证用户名</label>
                                <input
                                    id="proxy_username"
                                    name="username"
                                    class="form-control"
                                    autocomplete="off"
                                    placeholder="可选"
                                >
                            </div>
                            <div class="col-12 col-md-3 col-xl-2">
                                <label for="proxy_password" class="form-label">认证密码</label>
                                <input
                                    id="proxy_password"
                                    name="password"
                                    type="password"
                                    class="form-control"
                                    autocomplete="new-password"
                                    placeholder="可选"
                                >
                            </div>
                            <div class="col-12 col-md-3 col-xl-2">
                                <label for="proxy_type" class="form-label">代理类型</label>
                                <select id="proxy_type" name="proxy_type" class="form-select">
                                    {% for proxy_type in proxy_types %}
                                        <option value="{{ proxy_type }}">{{ proxy_type }}</option>
                                    {% endfor %}
                                </select>
                            </div>
                            <div class="col-12 col-md-3 col-xl-2">
                                <label for="provider_id" class="form-label">代理来源</label>
                                <select id="provider_id" name="provider_id" class="form-select">
                                    {% for provider in providers %}
                                        <option value="{{ provider.id }}">{{ provider.name }}</option>
                                    {% endfor %}
                                </select>
                            </div>
                            <div class="col-12 col-md-6 col-xl-2">
                                <label for="label" class="form-label">&#22791;&#27880;</label>
                                <input
                                    id="label"
                                    name="label"
                                    class="form-control"
                                    placeholder="DNS / HTTP Proxy"
                                >
                            </div>
                            <div class="col-12 col-md-auto">
                                <button type="submit" class="btn btn-primary mobile-full">
                                    &#28155;&#21152;&#20195;&#29702;
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>

            <div>


                <div class="card border-0 shadow-sm mb-4">
                    <div class="card-header bg-white fw-semibold">&#25209;&#37327;&#23548;&#20837;&#20195;&#29702;</div>
                    <div class="card-body">
                        <form action="{{ url_for('import_proxies') }}" method="post" class="vstack gap-3">
                            <div>
                                <label for="import_provider_id" class="form-label">导入来源</label>
                                <select id="import_provider_id" name="provider_id" class="form-select">
                                    {% for provider in providers %}
                                        <option value="{{ provider.id }}">{{ provider.name }}</option>
                                    {% endfor %}
                                </select>
                            </div>
                            <textarea
                                name="proxies"
                                class="form-control"
                                rows="5"
                                placeholder="8.8.8.8:53&#10;1.1.1.1,53,DNS&#10;208.67.222.222 53 OpenDNS&#10;proxy.example.com:12345:user:pass"
                            ></textarea>
                            <div class="d-flex flex-column flex-sm-row justify-content-between gap-2">
                                <div class="form-text">
                                    &#27599;&#34892;&#19968;&#20010;&#20195;&#29702;&#65292;&#25903;&#25345; IP:PORT&#12289;IP,PORT,备注&#12289;IP PORT 备注 或 IP:PORT:USER:PASS。
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
                            <div class="text-secondary small mt-1">
                                V5.1 会通过 ipify 真实验证代理出口；“池状态”按连续失败 5 次自动隔离为失效代理，“最近结果”显示最新一次真实检测是否成功。点击“详情”可查看最近 10 次检测记录。
                            </div>
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
                        <table class="table table-hover mb-0 proxy-table">
                            <thead class="table-light">
                                <tr>
                                    <th class="cell-proxy">&#20195;&#29702;</th>
                                    <th class="cell-medium">来源</th>
                                    <th class="cell-customer">客户</th>
                                    <th class="cell-tiny">类型</th>
                                    <th class="cell-auth">认证状态</th>
                                    <th class="cell-small">成功率</th>
                                    <th class="cell-medium">出口 IP</th>
                                    <th class="cell-small">延迟</th>
                                    <th class="cell-provider">&#22791;&#27880;</th>
                                    <th class="cell-small">最近结果</th>
                                    <th class="cell-small">&#22269;&#23478;</th>
                                    <th class="cell-small">&#24030;</th>
                                    <th class="cell-small">&#22478;&#24066;</th>
                                    <th class="cell-reason">失败分类</th>
                                    <th class="cell-message">最近错误</th>
                                    <th class="cell-medium">&#26368;&#36817;&#26816;&#27979;</th>
                                    <th class="cell-small text-end">&#25805;&#20316;</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for proxy in proxies %}
                                    <tr>
                                        <td>
                                            <div class="proxy-cell">
                                                <div class="proxy-address fw-semibold" title="{{ proxy.ip }}:{{ proxy.port }}">{{ proxy.ip }}:{{ proxy.port }}</div>
                                                <div class="proxy-recommend-score">
                                                    {% if proxy.id in top_proxy_ids %}
                                                        <span class="badge text-bg-warning proxy-rank-badge">Top 10</span>
                                                    {% endif %}
                                                    推荐分 {{ recommend_score(proxy) }}
                                                </div>
                                            </div>
                                        </td>
                                        <td><div class="cell-compact" title="{{ proxy.provider_name or 'IPRoyal' }}">{{ proxy.provider_name or "IPRoyal" }}</div></td>
                                        <td>
                                            <form action="{{ url_for('assign_proxy_customer', proxy_id=proxy.id) }}" method="post" class="d-flex gap-1">
                                                <select name="customer_id" class="form-select form-select-sm">
                                                    <option value="">未分配</option>
                                                    {% for customer in customers %}
                                                        <option value="{{ customer.id }}" {% if proxy.customer_id == customer.id %}selected{% endif %}>{{ customer.name }}</option>
                                                    {% endfor %}
                                                </select>
                                                <button class="btn btn-sm btn-outline-primary" type="submit">保存</button>
                                            </form>
                                        </td>
                                        <td><span class="badge text-bg-dark">{{ proxy.proxy_type }}</span></td>
                                        <td>
                                            {% set proxy_auth_status = auth_status(proxy) %}
                                            {% if proxy_auth_status == '认证通过' %}
                                                <span class="badge text-bg-success">{{ proxy_auth_status }}</span>
                                            {% elif proxy_auth_status == '认证失败' %}
                                                <span class="badge text-bg-danger">{{ proxy_auth_status }}</span>
                                            {% elif proxy_auth_status == '已配置' %}
                                                <span class="badge text-bg-primary">{{ proxy_auth_status }}</span>
                                            {% else %}
                                                <span class="badge text-bg-secondary">{{ proxy_auth_status }}</span>
                                            {% endif %}
                                        </td>
                                        <td>{{ proxy.success_rate }}%</td>
                                        <td class="proxy-address">{{ proxy.last_exit_ip or proxy.exit_ip or "-" }}</td>
                                        <td>{{ proxy.last_latency_ms or proxy.latency_ms or "-" }}</td>
                                        <td><div class="cell-compact" title="{{ display_proxy_label(proxy) }}">{{ display_proxy_label(proxy) }}</div></td>
                                        <td>
                                            {% if proxy.last_connectable is none %}
                                                <span class="badge rounded-pill text-bg-secondary">&#26410;&#26816;&#27979;</span>
                                            {% elif proxy.last_connectable %}
                                                <span class="badge rounded-pill text-bg-success">&#21487;&#36830;&#25509;</span>
                                            {% else %}
                                                <span class="badge rounded-pill text-bg-danger">&#19981;&#21487;&#36830;&#25509;</span>
                                            {% endif %}
                                        </td>
                                        <td><div class="cell-compact" title="{{ display_location(proxy.country or UNKNOWN) }}">{{ display_location(proxy.country or UNKNOWN) }}</div></td>
                                        <td><div class="cell-compact" title="{{ display_location(proxy.state or UNKNOWN) }}">{{ display_location(proxy.state or UNKNOWN) }}</div></td>
                                        <td><div class="cell-compact" title="{{ display_location(proxy.city or UNKNOWN) }}">{{ display_location(proxy.city or UNKNOWN) }}</div></td>
                                        <td><div class="cell-compact" title="{{ proxy.last_failure_reason or proxy.failure_reason or '-' }}">{{ proxy.last_failure_reason or proxy.failure_reason or "-" }}</div></td>
                                        <td>
                                            {% if proxy.last_connectable == 0 %}
                                                <div class="cell-compact" title="{{ proxy.last_message or '-' }}">{{ proxy.last_message or "-" }}</div>
                                            {% else %}
                                                -
                                            {% endif %}
                                        </td>
                                        <td>{{ proxy.last_checked_at or "-" }}</td>
                                        <td>
                                            <div class="d-flex justify-content-end gap-1">
                                                <button
                                                    class="btn btn-sm btn-outline-secondary"
                                                    type="button"
                                                    data-bs-toggle="collapse"
                                                    data-bs-target="#history-{{ proxy.id }}"
                                                    aria-expanded="false"
                                                    aria-controls="history-{{ proxy.id }}"
                                                >
                                                    详情
                                                </button>
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
                                    <tr class="collapse diagnostic-row" id="history-{{ proxy.id }}">
                                        <td colspan="17">
                                            <div class="p-2">
                                                <div class="fw-semibold mb-2">最近 10 次检测记录</div>
                                                <div class="table-responsive">
                                                    <table class="table table-sm diagnostic-table mb-0">
                                                        <thead>
                                                            <tr>
                                                                <th>时间</th>
                                                                <th>状态</th>
                                                                <th>延迟</th>
                                                                <th>出口 IP</th>
                                                                <th>识别协议</th>
                                                                <th>协议诊断</th>
                                                                <th>失败原因</th>
                                                                <th>消息</th>
                                                            </tr>
                                                        </thead>
                                                        <tbody>
                                                            {% for item in proxy_check_map.get(proxy.id, []) %}
                                                                <tr>
                                                                    <td>{{ item.checked_at }}</td>
                                                                    <td>
                                                                        {% if item.connectable %}
                                                                            <span class="badge text-bg-success">可连接</span>
                                                                        {% else %}
                                                                            <span class="badge text-bg-danger">不可连接</span>
                                                                        {% endif %}
                                                                    </td>
                                                                    <td>{{ item.latency_ms or "-" }}</td>
                                                                    <td class="proxy-address">{{ item.exit_ip or "-" }}</td>
                                                                    <td>{{ item.detected_proxy_type or "-" }}</td>
                                                                    <td>{{ item.protocol_status or "-" }}</td>
                                                                    <td>{{ item.failure_reason or "-" }}</td>
                                                                    <td><div class="cell-compact" title="{{ item.message }}">{{ item.message }}</div></td>
                                                                </tr>
                                                            {% else %}
                                                                <tr>
                                                                    <td colspan="8" class="text-center text-secondary py-3">暂无检测记录</td>
                                                                </tr>
                                                            {% endfor %}
                                                        </tbody>
                                                    </table>
                                                </div>
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

                <div class="card border-0 shadow-sm mb-4">
                    <div class="card-header bg-white d-flex justify-content-between align-items-center">
                        <span class="fw-semibold">失效代理列表</span>
                        <span class="badge text-bg-danger">{{ invalid_proxies|length }} items</span>
                    </div>
                    <div class="table-responsive">
                        <table class="table table-sm table-striped mb-0 history-table">
                            <thead class="table-light">
                                <tr>
                                    <th class="cell-medium">代理</th>
                                    <th class="cell-health">健康等级</th>
                                    <th class="cell-failures">连续失败</th>
                                    <th class="cell-protocol">识别协议</th>
                                    <th class="cell-protocol">协议诊断</th>
                                    <th class="cell-reason">失败分类</th>
                                    <th class="cell-medium">最近检测</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for proxy in invalid_proxies %}
                                    <tr>
                                        <td class="proxy-address">{{ proxy.ip }}:{{ proxy.port }}</td>
                                        <td><span class="badge text-bg-danger">{{ health_level(proxy.success_rate) }}</span></td>
                                        <td>{{ proxy.consecutive_failures }} 次</td>
                                        <td>{{ proxy.last_detected_proxy_type or proxy.detected_proxy_type or "-" }}</td>
                                        <td>{{ proxy.last_protocol_status or proxy.protocol_status or "-" }}</td>
                                        <td><div class="cell-compact" title="{{ proxy.last_failure_reason or proxy.failure_reason or '-' }}">{{ proxy.last_failure_reason or proxy.failure_reason or "-" }}</div></td>
                                        <td>{{ proxy.last_checked_at or "-" }}</td>
                                    </tr>
                                {% else %}
                                    <tr>
                                        <td colspan="7" class="text-center text-secondary py-3">暂无自动隔离的失效代理</td>
                                    </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="card border-0 shadow-sm">
                    <div class="card-header bg-white">
                        <div class="fw-semibold">&#21382;&#21490;&#35760;&#24405;</div>
                        <div class="text-secondary small mt-1">
                            历史记录保留每次检测当时的结果，不会跟随当前代理池状态自动改写；V5 之前的记录可能来自旧检测规则。
                        </div>
                    </div>
                    <div class="table-responsive">
                        <table class="table table-striped mb-0 history-table">
                            <thead class="table-light">
                                <tr>
                                    <th class="history-time">&#26816;&#27979;&#26102;&#38388;</th>
                                    <th class="cell-medium">&#20195;&#29702;</th>
                                    <th class="history-status">&#29366;&#24577;</th>
                                    <th class="cell-protocol">识别协议</th>
                                    <th class="cell-protocol">协议诊断</th>
                                    <th class="cell-small">&#22269;&#23478;</th>
                                    <th class="cell-small">&#24030;</th>
                                    <th class="cell-small">&#22478;&#24066;</th>
                                    <th class="history-message">&#28040;&#24687;</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for check in recent_checks %}
                                    <tr>
                                        <td><div class="cell-compact" title="{{ check.checked_at }}">{{ check.checked_at }}</div></td>
                                        <td><div class="proxy-address cell-compact" title="{{ check.ip }}:{{ check.port }}">{{ check.ip }}:{{ check.port }}</div></td>
                                        <td>
                                            {% if check.connectable %}
                                                <span class="badge text-bg-success">&#21487;&#36830;&#25509;</span>
                                            {% else %}
                                                <span class="badge text-bg-danger">&#19981;&#21487;&#36830;&#25509;</span>
                                            {% endif %}
                                        </td>
                                        <td>{{ check.detected_proxy_type or "-" }}</td>
                                        <td>{{ check.protocol_status or "-" }}</td>
                                        <td><div class="cell-compact" title="{{ display_location(check.country) }}">{{ display_location(check.country) }}</div></td>
                                        <td><div class="cell-compact" title="{{ display_location(check.state) }}">{{ display_location(check.state) }}</div></td>
                                        <td><div class="cell-compact" title="{{ display_location(check.city) }}">{{ display_location(check.city) }}</div></td>
                                        <td><div class="cell-compact" title="{{ check.message }}">{{ check.message }}</div></td>
                                    </tr>
                                {% else %}
                                    <tr>
                                        <td colspan="9" class="text-center text-secondary py-5">
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

NODES_TEMPLATE = """
<!doctype html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ProxyManager Nodes</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: #f4f6f9; }
        .table td, .table th { vertical-align: middle; }
        .node-table { min-width: 1900px; table-layout: fixed; font-size: 0.84rem; }
        .cell-compact { max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .cell-name { width: 170px; }
        .cell-small { width: 90px; }
        .cell-medium { width: 130px; }
        .cell-large { width: 190px; }
        .node-url { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.78rem; }
        @media (max-width: 575.98px) {
            main.container-fluid { padding-left: 0.75rem !important; padding-right: 0.75rem !important; }
            .mobile-full { width: 100%; }
            .node-table { min-width: 1660px; font-size: 0.76rem; }
        }
    </style>
</head>
<body>
    <main class="container-fluid px-4 py-4">
        <div class="d-flex flex-column flex-lg-row justify-content-between gap-3 mb-4">
            <div>
                <h1 class="h3 mb-1">节点管理</h1>
                <div class="text-secondary">导入和管理 VLESS / Reality 节点链接，保留 TCP 端口检测，并通过 Xray-core 验证真实出口 IP。</div>
            </div>
            <div class="d-flex flex-column flex-sm-row gap-2">
                <a href="{{ url_for('xray_status_page') }}" class="btn btn-outline-primary mobile-full">Xray状态</a>
                <a href="{{ url_for('index') }}" class="btn btn-outline-secondary mobile-full">返回首页</a>
            </div>
        </div>

        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for message in messages %}
                    <div class="alert alert-info">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        {% if not xray_available %}
            <div class="alert alert-warning border-0 shadow-sm">
                请安装 xray-core 后再进行真实检测，或设置环境变量 <code>XRAY_PATH</code> 指向 xray 可执行文件。未安装时仍会保留 TCP 端口检测。
            </div>
        {% endif %}

        <section class="card border-0 shadow-sm mb-4">
            <div class="card-header bg-white fw-semibold">批量导入 VLESS 节点</div>
            <div class="card-body">
                <form action="{{ url_for('import_nodes') }}" method="post" class="vstack gap-3">
                    <textarea
                        name="nodes"
                        class="form-control node-url"
                        rows="6"
                        placeholder="vless://uuid@ip:port?security=reality&flow=xtls-rprx-vision&pbk=xxx&sid=xxx&type=tcp&sni=xxx#name"
                    ></textarea>
                    <div class="d-flex flex-column flex-sm-row justify-content-between gap-2">
                        <div class="form-text">每行一个 VLESS 链接。导入时会先做 TCP 端口检测，端口开放后再用 Xray-core 访问 api.ipify.org 获取出口 IP。</div>
                        <button class="btn btn-primary mobile-full" type="submit">批量导入</button>
                    </div>
                </form>
            </div>
        </section>

        <section class="card border-0 shadow-sm">
            <div class="card-header bg-white d-flex flex-column flex-lg-row justify-content-between align-items-lg-center gap-2">
                <div>
                    <span class="fw-semibold">节点列表</span>
                    <span class="badge text-bg-light">{{ nodes|length }} items</span>
                </div>
            </div>
            <div class="table-responsive">
                <table class="table table-hover mb-0 node-table">
                    <thead class="table-light">
                        <tr>
                            <th class="cell-name">名称</th>
                            <th class="cell-small">协议</th>
                            <th class="cell-medium">服务器 IP</th>
                            <th class="cell-small">端口</th>
                            <th class="cell-large">SNI</th>
                            <th class="cell-large">Reality</th>
                            <th class="cell-small">端口状态</th>
                            <th class="cell-small">真实连接</th>
                            <th class="cell-medium">出口 IP</th>
                            <th class="cell-medium">出口国家</th>
                            <th class="cell-medium">出口州/地区</th>
                            <th class="cell-medium">出口城市</th>
                            <th class="cell-small">TCP 延迟</th>
                            <th class="cell-small">真实延迟</th>
                            <th class="cell-medium">最后检测</th>
                            <th class="cell-large">错误原因 / 检测消息</th>
                            <th class="cell-medium text-end">操作</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for node in nodes %}
                            <tr>
                                <td><div class="cell-compact" title="{{ node.name or '-' }}">{{ node.name or "-" }}</div></td>
                                <td><span class="badge text-bg-dark">{{ node.protocol or "-" }}</span></td>
                                <td><div class="cell-compact" title="{{ node.server_ip or '-' }}">{{ node.server_ip or "-" }}</div></td>
                                <td>{{ node.server_port or "-" }}</td>
                                <td><div class="cell-compact" title="{{ node.sni or '-' }}">{{ node.sni or "-" }}</div></td>
                                <td>
                                    <div class="cell-compact" title="security={{ node.security or '-' }} pbk={{ node.pbk or '-' }} sid={{ node.sid or '-' }} type={{ node.transport_type or '-' }} flow={{ node.flow or '-' }}">
                                        {{ node.security or "-" }} / {{ node.transport_type or "-" }}
                                    </div>
                                </td>
                                <td><span class="badge {{ node_status_badge_class(node.status) }}">{{ node.status }}</span></td>
                                <td><span class="badge {{ node_status_badge_class(node.real_status or '-') }}">{{ node.real_status or "-" }}</span></td>
                                <td><div class="cell-compact" title="{{ node.exit_ip or '-' }}">{{ node.exit_ip or "-" }}</div></td>
                                <td><div class="cell-compact" title="{{ node.exit_country or 'Unknown' }}">{{ display_location(node.exit_country) }}</div></td>
                                <td><div class="cell-compact" title="{{ node.exit_region or 'Unknown' }}">{{ display_location(node.exit_region) }}</div></td>
                                <td><div class="cell-compact" title="{{ node.exit_city or 'Unknown' }}">{{ display_location(node.exit_city) }}</div></td>
                                <td>{{ node.latency_ms if node.latency_ms is not none else "-" }}</td>
                                <td>{{ node.real_latency_ms if node.real_latency_ms is not none else "-" }}</td>
                                <td>{{ node.last_checked or "-" }}</td>
                                <td><div class="cell-compact" title="{{ node.check_message or node.last_message or '-' }}">{{ node.check_message or node.last_message or "-" }}</div></td>
                                <td>
                                    <div class="d-flex justify-content-end gap-1">
                                        <button class="btn btn-sm btn-outline-secondary copy-node-btn" type="button" data-node-url="{{ node.raw_url }}">复制</button>
                                        <form action="{{ url_for('check_node_route', node_id=node.id) }}" method="post">
                                            <button class="btn btn-sm btn-outline-primary" type="submit">检测</button>
                                        </form>
                                        <form action="{{ url_for('delete_node', node_id=node.id) }}" method="post" onsubmit="return confirm('删除这个节点？');">
                                            <button class="btn btn-sm btn-outline-danger" type="submit">删除</button>
                                        </form>
                                    </div>
                                </td>
                            </tr>
                        {% else %}
                            <tr>
                                <td colspan="17" class="text-center text-secondary py-5">暂无节点，请先导入 VLESS 链接。</td>
                            </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </section>
    </main>
    <script>
        document.querySelectorAll(".copy-node-btn").forEach((button) => {
            button.addEventListener("click", async () => {
                const text = button.dataset.nodeUrl || "";
                try {
                    await navigator.clipboard.writeText(text);
                    button.textContent = "已复制";
                    setTimeout(() => { button.textContent = "复制"; }, 1200);
                } catch (_error) {
                    const area = document.createElement("textarea");
                    area.value = text;
                    document.body.appendChild(area);
                    area.select();
                    document.execCommand("copy");
                    area.remove();
                    button.textContent = "已复制";
                    setTimeout(() => { button.textContent = "复制"; }, 1200);
                }
            });
        });
    </script>
</body>
</html>
"""

XRAY_STATUS_TEMPLATE = """
<!doctype html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ProxyManager Xray Status</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: #f4f6f9; }
        pre { white-space: pre-wrap; word-break: break-word; }
    </style>
</head>
<body>
    <main class="container py-4">
        <div class="d-flex flex-column flex-sm-row justify-content-between gap-2 mb-4">
            <div>
                <h1 class="h3 mb-1">Xray状态</h1>
                <div class="text-secondary">用于诊断 Docker 容器或本机环境是否能调用 xray-core。</div>
            </div>
            <a href="{{ url_for('nodes_page') }}" class="btn btn-outline-secondary align-self-sm-start">返回节点管理</a>
        </div>

        <section class="card border-0 shadow-sm">
            <div class="card-header bg-white fw-semibold">诊断结果</div>
            <div class="card-body">
                <div class="row g-3">
                    <div class="col-md-6">
                        <div class="text-secondary small">安装状态</div>
                        <div>
                            {% if details.installed %}
                                <span class="badge text-bg-success">已安装</span>
                            {% else %}
                                <span class="badge text-bg-danger">未安装</span>
                            {% endif %}
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="text-secondary small">使用路径</div>
                        <code>{{ details.resolved_path or "-" }}</code>
                    </div>
                    <div class="col-md-6">
                        <div class="text-secondary small">XRAY_PATH</div>
                        <code>{{ details.configured_path or "-" }}</code>
                    </div>
                    <div class="col-md-6">
                        <div class="text-secondary small">which xray</div>
                        <code>{{ details.which_path or "-" }}</code>
                    </div>
                    <div class="col-12">
                        <div class="text-secondary small">xray version</div>
                        <pre class="bg-light border rounded p-3 mb-0">{{ details.version or "-" }}</pre>
                    </div>
                </div>
            </div>
        </section>
    </main>
</body>
</html>
"""

ANALYTICS_TEMPLATE = """
<!doctype html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ProxyManager Analytics</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
    <style>
        body { background: #f4f6f9; }
        .chart-body { height: 260px; padding: 1rem 1.25rem; }
        .chart-body canvas { width: 100% !important; height: 100% !important; }
        @media (max-width: 575.98px) {
            main.container-fluid { padding-left: 0.75rem !important; padding-right: 0.75rem !important; }
            .mobile-full { width: 100%; }
            .chart-body { height: 220px; padding: 0.75rem; }
        }
    </style>
</head>
<body>
    <main class="container-fluid px-4 py-4">
        <div class="d-flex flex-column flex-lg-row justify-content-between gap-3 mb-4">
            <div>
                <h1 class="h3 mb-1">&#25968;&#25454;&#20998;&#26512;</h1>
                <div class="text-secondary">ProxyManager &#36235;&#21183;&#22270;&#12289;&#22269;&#23478;&#32479;&#35745;&#21644;&#21508;&#24030;&#20195;&#29702;&#25968;&#37327;&#12290;</div>
            </div>
            <div class="d-flex flex-column flex-sm-row gap-2">
                <a href="{{ url_for('index') }}" class="btn btn-outline-secondary mobile-full">&#36820;&#22238;&#39318;&#39029;</a>
            </div>
        </div>

        <section class="row g-3 mb-4">
            <div class="col-12 col-xl-4">
                <div class="card border-0 shadow-sm">
                    <div class="card-body">
                        <div class="text-secondary small">Top Provider</div>
                        <div class="fw-semibold text-break">{{ dashboard.top_provider or "-" }}</div>
                    </div>
                </div>
            </div>
            <div class="col-6 col-xl-4">
                <div class="card border-0 shadow-sm">
                    <div class="card-body">
                        <div class="text-secondary small">Provider Success Rate</div>
                        <div class="h3 mb-0">{{ dashboard.provider_success_rate }}%</div>
                    </div>
                </div>
            </div>
            <div class="col-6 col-xl-4">
                <div class="card border-0 shadow-sm">
                    <div class="card-body">
                        <div class="text-secondary small">Provider Latency</div>
                        <div class="h3 mb-0">{{ dashboard.provider_latency }} ms</div>
                    </div>
                </div>
            </div>
        </section>

        <section class="row g-4 mb-4">
            <div class="col-12 col-xl-6">
                <div class="card border-0 shadow-sm">
                    <div class="card-header bg-white fw-semibold">在线率趋势</div>
                    <div class="card-body chart-body"><canvas id="onlineRateChart"></canvas></div>
                </div>
            </div>
            <div class="col-12 col-xl-6">
                <div class="card border-0 shadow-sm">
                    <div class="card-header bg-white fw-semibold">代理增长</div>
                    <div class="card-body chart-body"><canvas id="proxyGrowthChart"></canvas></div>
                </div>
            </div>
            <div class="col-12 col-xl-6">
                <div class="card border-0 shadow-sm">
                    <div class="card-header bg-white fw-semibold">失败率</div>
                    <div class="card-body chart-body"><canvas id="failureRateChart"></canvas></div>
                </div>
            </div>
            <div class="col-12 col-xl-6">
                <div class="card border-0 shadow-sm">
                    <div class="card-header bg-white fw-semibold">国家统计</div>
                    <div class="card-body chart-body"><canvas id="countryChart"></canvas></div>
                </div>
            </div>
        </section>

        <section class="card border-0 shadow-sm mb-4">
            <div class="card-header bg-white fw-semibold">各州代理数量</div>
            <div class="card-body">
                <div class="row g-3">
                    {% for item in dashboard.state_counts %}
                        <div class="col-6 col-xl-3">
                            <div class="border rounded bg-light p-3">
                                <div class="text-secondary small">{{ display_location(item.state) }}</div>
                                <div class="h3 mb-0">{{ item.count }}</div>
                            </div>
                        </div>
                    {% endfor %}
                </div>
            </div>
        </section>

    <script>
        const chartData = {{ chart_data|tojson }};
        const commonChartOptions = {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: { boxWidth: 36, font: { size: 12 } }
                }
            }
        };
        const lineOptions = {
            ...commonChartOptions,
            scales: {
                x: { ticks: { maxRotation: 0, autoSkip: true } },
                y: { beginAtZero: true, max: 100 }
            }
        };
        new Chart(document.getElementById("onlineRateChart"), {
            type: "line",
            data: { labels: chartData.labels, datasets: [{ label: "在线率 %", data: chartData.online_rates, borderColor: "#0d6efd", tension: 0.25, pointRadius: 2 }] },
            options: lineOptions
        });
        new Chart(document.getElementById("proxyGrowthChart"), {
            type: "line",
            data: { labels: chartData.labels, datasets: [{ label: "代理数量", data: chartData.proxy_growth, borderColor: "#198754", tension: 0.25, pointRadius: 2 }] },
            options: {
                ...commonChartOptions,
                scales: {
                    x: { ticks: { maxRotation: 0, autoSkip: true } },
                    y: { beginAtZero: true }
                }
            }
        });
        new Chart(document.getElementById("failureRateChart"), {
            type: "bar",
            data: { labels: chartData.labels, datasets: [{ label: "失败率 %", data: chartData.failure_rates, backgroundColor: "#dc3545" }] },
            options: lineOptions
        });
        new Chart(document.getElementById("countryChart"), {
            type: "doughnut",
            data: { labels: chartData.country_labels, datasets: [{ data: chartData.country_counts, backgroundColor: ["#0d6efd", "#198754", "#ffc107", "#dc3545", "#6f42c1", "#20c997"] }] },
            options: {
                ...commonChartOptions,
                cutout: "58%",
                plugins: {
                    ...commonChartOptions.plugins,
                    legend: { position: "top", labels: { boxWidth: 28, font: { size: 12 } } }
                }
            }
        });
    </script>
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
            <div class="col-6 col-xl-3"><div class="card border-0 shadow-sm"><div class="card-body"><div class="text-secondary small">Customers</div><div class="display-6 fw-semibold">{{ metrics.total_customers }}</div></div></div></div>
            <div class="col-6 col-xl-3"><div class="card border-0 shadow-sm"><div class="card-body"><div class="text-secondary small">Total API Keys</div><div class="display-6 fw-semibold">{{ metrics.total_api_keys }}</div></div></div></div>
            <div class="col-6 col-xl-3"><div class="card border-0 shadow-sm"><div class="card-body"><div class="text-secondary small">Requests Today</div><div class="display-6 fw-semibold">{{ metrics.today_requests }}</div></div></div></div>
            <div class="col-6 col-xl-3"><div class="card border-0 shadow-sm"><div class="card-body"><div class="text-secondary small">Online Proxies</div><div class="display-6 fw-semibold text-success">{{ metrics.online_proxies }}</div></div></div></div>
        </section>
        <div class="card border-0 shadow-sm mb-4">
            <div class="card-header bg-white fw-semibold">Create API Key</div>
            <div class="card-body">
                <form action="{{ url_for('create_api_key') }}" method="post" class="row g-2 align-items-end">
                    <div class="col-12 col-md-5">
                        <label for="api_customer_id" class="form-label">绑定客户</label>
                        <select id="api_customer_id" name="customer_id" class="form-select">
                            <option value="">全池管理员 Key</option>
                            {% for customer in customers %}
                                <option value="{{ customer.id }}">{{ customer.name }}</option>
                            {% endfor %}
                        </select>
                    </div>
                    <div class="col-12 col-md-auto">
                        <button class="btn btn-primary mobile-full" type="submit">Create Key</button>
                    </div>
                </form>
            </div>
        </div>
        <div class="card border-0 shadow-sm">
            <div class="card-header bg-white fw-semibold">Your API Keys</div>
            <div class="table-responsive">
                <table class="table table-hover mb-0">
                    <thead class="table-light">
                        <tr><th>API Key</th><th>客户</th><th>Status</th><th>Created</th><th>Calls</th><th class="text-end">Actions</th></tr>
                    </thead>
                    <tbody>
                        {% for key in api_keys %}
                            <tr>
                                <td><code>{{ key.api_key }}</code></td>
                                <td>{{ key.customer_name or "全池" }}</td>
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
                            <tr><td colspan="6" class="text-center text-secondary py-5">No API keys yet.</td></tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </main>
</body>
</html>
"""

CUSTOMERS_TEMPLATE = """
<!doctype html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ProxyManager Customers</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: #f4f6f9; }
        .table td, .table th { vertical-align: middle; }
        @media (max-width: 575.98px) {
            main.container-fluid { padding-left: 0.75rem !important; padding-right: 0.75rem !important; }
            .mobile-full { width: 100%; }
        }
    </style>
</head>
<body>
    <main class="container-fluid px-4 py-4">
        <div class="d-flex flex-column flex-lg-row justify-content-between gap-3 mb-4">
            <div>
                <h1 class="h3 mb-1">客户管理</h1>
                <div class="text-secondary">客户用于分配代理和隔离 API Key 返回数据。</div>
            </div>
            <div class="d-flex flex-column flex-sm-row gap-2">
                <a href="{{ url_for('index') }}" class="btn btn-outline-secondary mobile-full">返回代理列表</a>
                <a href="{{ url_for('api_keys_page') }}" class="btn btn-outline-dark mobile-full">API Keys</a>
            </div>
        </div>
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for message in messages %}
                    <div class="alert alert-info">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        <section class="card border-0 shadow-sm mb-4">
            <div class="card-header bg-white fw-semibold">新增客户</div>
            <div class="card-body">
                <form action="{{ url_for('create_customer') }}" method="post" class="row g-2 align-items-end">
                    <div class="col-12 col-md-4">
                        <label for="name" class="form-label">客户名称</label>
                        <input id="name" name="name" class="form-control" placeholder="例如 Customer A" required>
                    </div>
                    <div class="col-12 col-md-5">
                        <label for="contact" class="form-label">联系方式/备注</label>
                        <input id="contact" name="contact" class="form-control" placeholder="邮箱、Telegram、合同编号等">
                    </div>
                    <div class="col-12 col-md-auto">
                        <button class="btn btn-primary mobile-full" type="submit">新增客户</button>
                    </div>
                </form>
            </div>
        </section>

        <section class="card border-0 shadow-sm">
            <div class="card-header bg-white fw-semibold">客户列表 <span class="badge text-bg-light">{{ stats|length }} items</span></div>
            <div class="table-responsive">
                <table class="table table-hover mb-0">
                    <thead class="table-light">
                        <tr>
                            <th>客户</th>
                            <th>联系方式</th>
                            <th>状态</th>
                            <th>代理数量</th>
                            <th>在线代理</th>
                            <th>API Key</th>
                            <th>创建时间</th>
                            <th class="text-end">操作</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for item in stats %}
                            <tr>
                                <td>
                                    <form action="{{ url_for('update_customer', customer_id=item.id) }}" method="post" class="row g-2">
                                        <div class="col-12">
                                            <input name="name" class="form-control form-control-sm" value="{{ item.name }}" required>
                                        </div>
                                </td>
                                <td><input name="contact" class="form-control form-control-sm" value="{{ item.contact }}"></td>
                                <td>
                                    <span class="badge {% if item.status == 'active' %}text-bg-success{% else %}text-bg-secondary{% endif %}">{{ item.status }}</span>
                                </td>
                                <td>{{ item.proxy_count }}</td>
                                <td>{{ item.online_count }}</td>
                                <td>{{ item.api_key_count }}</td>
                                <td>{{ item.created_at }}</td>
                                <td>
                                    <div class="d-flex justify-content-end gap-2">
                                        <button class="btn btn-sm btn-outline-primary" type="submit">保存</button>
                                    </form>
                                        {% if item.status == 'active' %}
                                            <form action="{{ url_for('disable_customer', customer_id=item.id) }}" method="post"><button class="btn btn-sm btn-outline-warning" type="submit">禁用</button></form>
                                        {% else %}
                                            <form action="{{ url_for('enable_customer', customer_id=item.id) }}" method="post"><button class="btn btn-sm btn-outline-success" type="submit">启用</button></form>
                                        {% endif %}
                                        <form action="{{ url_for('delete_customer', customer_id=item.id) }}" method="post" onsubmit="return confirm('删除客户后，该客户代理会变为未分配，API Key 会变为全池 Key。确认删除？');">
                                            <button class="btn btn-sm btn-outline-danger" type="submit">删除</button>
                                        </form>
                                    </div>
                                </td>
                            </tr>
                        {% else %}
                            <tr><td colspan="8" class="text-center text-secondary py-4">暂无客户</td></tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </section>
    </main>
</body>
</html>
"""

PROVIDERS_TEMPLATE = """
<!doctype html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>ProxyManager Providers</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: #f4f6f9; }
        .table td, .table th { vertical-align: middle; }
        @media (max-width: 575.98px) {
            main.container-fluid { padding-left: 0.75rem !important; padding-right: 0.75rem !important; }
            .mobile-full { width: 100%; }
        }
    </style>
</head>
<body>
    <main class="container-fluid px-4 py-4">
        <div class="d-flex flex-column flex-lg-row justify-content-between gap-3 mb-4">
            <div>
                <h1 class="h3 mb-1">代理来源管理</h1>
                <div class="text-secondary">管理 source_providers，并查看各来源质量统计。</div>
            </div>
            <div class="d-flex flex-column flex-sm-row gap-2">
                <a href="{{ url_for('index') }}" class="btn btn-outline-secondary mobile-full">返回后台</a>
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

        <section class="row g-4">
            <div class="col-12 col-xl-4">
                <div class="card border-0 shadow-sm">
                    <div class="card-header bg-white fw-semibold">新增来源</div>
                    <div class="card-body">
                        <form action="{{ url_for('create_provider') }}" method="post" class="vstack gap-3">
                            <div>
                                <label for="name" class="form-label">来源名称</label>
                                <input id="name" name="name" class="form-control" placeholder="FreeProxyList" required>
                            </div>
                            <div>
                                <label for="description" class="form-label">描述</label>
                                <textarea id="description" name="description" class="form-control" rows="4" placeholder="来源说明、抓取地址或备注"></textarea>
                            </div>
                            <button type="submit" class="btn btn-primary mobile-full">新增来源</button>
                        </form>
                    </div>
                </div>
            </div>

            <div class="col-12 col-xl-8">
                <div class="card border-0 shadow-sm mb-4">
                    <div class="card-header bg-white fw-semibold">来源统计</div>
                    <div class="table-responsive">
                        <table class="table table-hover mb-0">
                            <thead class="table-light">
                                <tr>
                                    <th>来源名称</th>
                                    <th>代理数量</th>
                                    <th>成功率</th>
                                    <th>平均延迟</th>
                                    <th>平均评分</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for item in stats %}
                                    <tr>
                                        <td>{{ item.name }}</td>
                                        <td>{{ item.proxy_count }}</td>
                                        <td>{{ item.success_rate or 0 }}%</td>
                                        <td>{{ item.avg_latency or "-" }}</td>
                                        <td>{{ item.avg_score or "-" }}</td>
                                    </tr>
                                {% else %}
                                    <tr><td colspan="5" class="text-center text-secondary py-4">暂无来源统计</td></tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="card border-0 shadow-sm">
                    <div class="card-header bg-white fw-semibold">来源列表</div>
                    <div class="table-responsive">
                        <table class="table table-striped mb-0">
                            <thead class="table-light">
                                <tr>
                                    <th>名称</th>
                                    <th>描述</th>
                                    <th>创建时间</th>
                                    <th class="text-end">操作</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for provider in providers %}
                                    <tr>
                                        <td colspan="4">
                                            <form action="{{ url_for('update_provider', provider_id=provider.id) }}" method="post" class="row g-2 align-items-center">
                                                <div class="col-12 col-md-3">
                                                    <input name="name" class="form-control" value="{{ provider.name }}" required>
                                                </div>
                                                <div class="col-12 col-md-4">
                                                    <input name="description" class="form-control" value="{{ provider.description }}">
                                                </div>
                                                <div class="col-12 col-md-2 text-secondary small">{{ provider.created_at }}</div>
                                                <div class="col-12 col-md-3">
                                                    <div class="d-flex justify-content-md-end gap-2">
                                                        <button type="submit" class="btn btn-sm btn-outline-primary mobile-full">保存</button>
                                                        <button
                                                            type="submit"
                                                            form="delete-provider-{{ provider.id }}"
                                                            class="btn btn-sm btn-outline-danger mobile-full"
                                                            {% if provider.id == 1 %}disabled{% endif %}
                                                        >
                                                            删除
                                                        </button>
                                                    </div>
                                                </div>
                                            </form>
                                            <form
                                                id="delete-provider-{{ provider.id }}"
                                                action="{{ url_for('delete_provider', provider_id=provider.id) }}"
                                                method="post"
                                                onsubmit="return confirm('删除来源后，该来源下代理会归入内置来源。确认删除？');"
                                            ></form>
                                        </td>
                                    </tr>
                                {% else %}
                                    <tr><td colspan="4" class="text-center text-secondary py-4">暂无来源</td></tr>
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
        database_path = Path(app.config["DATABASE"])
        if database_path.parent != Path("."):
            database_path.parent.mkdir(parents=True, exist_ok=True)
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
                detected_proxy_type TEXT NOT NULL DEFAULT '',
                username TEXT NOT NULL DEFAULT '',
                password TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'unknown',
                score INTEGER NOT NULL DEFAULT 100,
                consecutive_failures INTEGER NOT NULL DEFAULT 0,
                success_count INTEGER NOT NULL DEFAULT 0,
                failure_count INTEGER NOT NULL DEFAULT 0,
                exit_ip TEXT NOT NULL DEFAULT '',
                latency_ms INTEGER,
                isp TEXT NOT NULL DEFAULT '',
                asn TEXT NOT NULL DEFAULT '',
                failure_reason TEXT NOT NULL DEFAULT '',
                protocol_status TEXT NOT NULL DEFAULT '',
                provider_id INTEGER,
                customer_id INTEGER,
                label TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(provider_id) REFERENCES source_providers(id) ON DELETE SET NULL,
                FOREIGN KEY(customer_id) REFERENCES customers(id) ON DELETE SET NULL,
                UNIQUE(ip, port)
            );

            CREATE TABLE IF NOT EXISTS source_providers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS customers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                contact TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL
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
                failure_reason TEXT NOT NULL DEFAULT '',
                detected_proxy_type TEXT NOT NULL DEFAULT '',
                protocol_status TEXT NOT NULL DEFAULT '',
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

            CREATE TABLE IF NOT EXISTS nodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                protocol TEXT NOT NULL DEFAULT '',
                name TEXT NOT NULL DEFAULT '',
                server_ip TEXT NOT NULL DEFAULT '',
                server_port INTEGER,
                uuid TEXT NOT NULL DEFAULT '',
                security TEXT NOT NULL DEFAULT '',
                flow TEXT NOT NULL DEFAULT '',
                pbk TEXT NOT NULL DEFAULT '',
                sid TEXT NOT NULL DEFAULT '',
                transport_type TEXT NOT NULL DEFAULT '',
                sni TEXT NOT NULL DEFAULT '',
                raw_url TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT '配置正常',
                exit_ip TEXT NOT NULL DEFAULT '',
                exit_country TEXT NOT NULL DEFAULT 'Unknown',
                exit_region TEXT NOT NULL DEFAULT 'Unknown',
                exit_city TEXT NOT NULL DEFAULT 'Unknown',
                exit_isp TEXT NOT NULL DEFAULT 'Unknown',
                exit_asn TEXT NOT NULL DEFAULT 'Unknown',
                latency_ms INTEGER,
                real_status TEXT NOT NULL DEFAULT '',
                real_latency_ms INTEGER,
                check_message TEXT NOT NULL DEFAULT '',
                last_message TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                last_checked TEXT
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
                customer_id INTEGER,
                api_key TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(customer_id) REFERENCES customers(id) ON DELETE SET NULL
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
        seed_env_api_key(db)
        import_csv_if_empty(db)


def ensure_schema(db: sqlite3.Connection) -> None:
    ensure_table(
        db,
        "source_providers",
        """
        CREATE TABLE IF NOT EXISTS source_providers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        )
        """,
    )
    ensure_table(
        db,
        "customers",
        """
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            contact TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL
        )
        """,
    )
    db.execute(
        """
        INSERT OR IGNORE INTO source_providers (id, name, description, created_at)
        VALUES (1, 'IPRoyal', 'IPRoyal SOCKS5 认证代理来源。', ?)
        """,
        (current_time(),),
    )
    columns = {
        row["name"] for row in db.execute("PRAGMA table_info(proxies)").fetchall()
    }
    if "proxy_type" not in columns:
        db.execute("ALTER TABLE proxies ADD COLUMN proxy_type TEXT NOT NULL DEFAULT 'HTTP'")
    proxy_column_defaults = {
        "status": "TEXT NOT NULL DEFAULT 'unknown'",
        "detected_proxy_type": "TEXT NOT NULL DEFAULT ''",
        "username": "TEXT NOT NULL DEFAULT ''",
        "password": "TEXT NOT NULL DEFAULT ''",
        "score": "INTEGER NOT NULL DEFAULT 100",
        "consecutive_failures": "INTEGER NOT NULL DEFAULT 0",
        "success_count": "INTEGER NOT NULL DEFAULT 0",
        "failure_count": "INTEGER NOT NULL DEFAULT 0",
        "exit_ip": "TEXT NOT NULL DEFAULT ''",
        "latency_ms": "INTEGER",
        "isp": "TEXT NOT NULL DEFAULT ''",
        "asn": "TEXT NOT NULL DEFAULT ''",
        "failure_reason": "TEXT NOT NULL DEFAULT ''",
        "protocol_status": "TEXT NOT NULL DEFAULT ''",
        "provider_id": "INTEGER",
        "customer_id": "INTEGER",
    }
    for column, definition in proxy_column_defaults.items():
        if column not in columns:
            db.execute(f"ALTER TABLE proxies ADD COLUMN {column} {definition}")
    db.execute("UPDATE proxies SET provider_id = 1 WHERE provider_id IS NULL")
    check_columns = {
        row["name"] for row in db.execute("PRAGMA table_info(checks)").fetchall()
    }
    check_column_defaults = {
        "exit_ip": "TEXT NOT NULL DEFAULT ''",
        "latency_ms": "INTEGER",
        "isp": "TEXT NOT NULL DEFAULT ''",
        "asn": "TEXT NOT NULL DEFAULT ''",
        "failure_reason": "TEXT NOT NULL DEFAULT ''",
        "detected_proxy_type": "TEXT NOT NULL DEFAULT ''",
        "protocol_status": "TEXT NOT NULL DEFAULT ''",
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
            customer_id INTEGER,
            api_key TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(customer_id) REFERENCES customers(id) ON DELETE SET NULL
        )
        """,
    )
    api_key_columns = {
        row["name"] for row in db.execute("PRAGMA table_info(api_keys)").fetchall()
    }
    if "customer_id" not in api_key_columns:
        db.execute("ALTER TABLE api_keys ADD COLUMN customer_id INTEGER")
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
    ensure_table(
        db,
        "nodes",
        """
        CREATE TABLE IF NOT EXISTS nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            protocol TEXT NOT NULL DEFAULT '',
            name TEXT NOT NULL DEFAULT '',
            server_ip TEXT NOT NULL DEFAULT '',
            server_port INTEGER,
            uuid TEXT NOT NULL DEFAULT '',
            security TEXT NOT NULL DEFAULT '',
            flow TEXT NOT NULL DEFAULT '',
            pbk TEXT NOT NULL DEFAULT '',
            sid TEXT NOT NULL DEFAULT '',
            transport_type TEXT NOT NULL DEFAULT '',
            sni TEXT NOT NULL DEFAULT '',
            raw_url TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT '配置正常',
            exit_ip TEXT NOT NULL DEFAULT '',
            exit_country TEXT NOT NULL DEFAULT 'Unknown',
            exit_region TEXT NOT NULL DEFAULT 'Unknown',
            exit_city TEXT NOT NULL DEFAULT 'Unknown',
            exit_isp TEXT NOT NULL DEFAULT 'Unknown',
            exit_asn TEXT NOT NULL DEFAULT 'Unknown',
            latency_ms INTEGER,
            real_status TEXT NOT NULL DEFAULT '',
            real_latency_ms INTEGER,
            check_message TEXT NOT NULL DEFAULT '',
            last_message TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            last_checked TEXT
        )
        """,
    )
    node_columns = {
        row["name"] for row in db.execute("PRAGMA table_info(nodes)").fetchall()
    }
    node_column_defaults = {
        "exit_ip": "TEXT NOT NULL DEFAULT ''",
        "exit_country": "TEXT NOT NULL DEFAULT 'Unknown'",
        "exit_region": "TEXT NOT NULL DEFAULT 'Unknown'",
        "exit_city": "TEXT NOT NULL DEFAULT 'Unknown'",
        "exit_isp": "TEXT NOT NULL DEFAULT 'Unknown'",
        "exit_asn": "TEXT NOT NULL DEFAULT 'Unknown'",
        "real_status": "TEXT NOT NULL DEFAULT ''",
        "real_latency_ms": "INTEGER",
        "check_message": "TEXT NOT NULL DEFAULT ''",
        "last_message": "TEXT NOT NULL DEFAULT ''",
    }
    for column, definition in node_column_defaults.items():
        if column not in node_columns:
            db.execute(f"ALTER TABLE nodes ADD COLUMN {column} {definition}")
    db.execute(
        """
        UPDATE nodes
        SET real_status = status,
            real_latency_ms = latency_ms,
            check_message = COALESCE(NULLIF(check_message, ''), NULLIF(last_message, ''), '历史 Xray 检测结果'),
            status = ?
        WHERE status IN (?, ?)
          AND COALESCE(real_status, '') = ''
        """,
        (NODE_STATUS_PORT_OPEN, NODE_STATUS_AVAILABLE, NODE_STATUS_UNAVAILABLE),
    )


def ensure_table(db: sqlite3.Connection, _name: str, ddl: str) -> None:
    db.execute(ddl)


def seed_env_api_key(db: sqlite3.Connection) -> None:
    api_key = os.environ.get("API_KEY", "").strip()
    if not api_key:
        return
    now = current_time()
    cursor = db.execute(
        """
        INSERT OR IGNORE INTO users (username, password_hash, created_at)
        VALUES ('system', ?, ?)
        """,
        (generate_password_hash(secrets.token_urlsafe(24)), now),
    )
    user = db.execute("SELECT id FROM users WHERE username = 'system'").fetchone()
    if user is None:
        return
    db.execute(
        """
        INSERT OR IGNORE INTO api_keys (user_id, api_key, status, created_at)
        VALUES (?, ?, 'active', ?)
        """,
        (user["id"], api_key, now),
    )
    db.commit()


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
            INSERT OR IGNORE INTO proxies (ip, port, proxy_type, provider_id, label, created_at, updated_at)
            VALUES (?, ?, 'HTTP', 1, '', ?, ?)
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


def display_location(value: str | None) -> str:
    text = (value or "").strip()
    return LOCATION_DISPLAY_NAMES.get(text, text or "-")


def display_proxy_label(proxy: sqlite3.Row | dict[str, object]) -> str:
    label = str(proxy["label"] or "").strip()
    if label:
        return label
    username = str(proxy["username"] or "").strip() if "username" in proxy.keys() else ""
    proxy_type = str(proxy["proxy_type"] or "").strip() if "proxy_type" in proxy.keys() else ""
    if username:
        return f"IPRoyal {proxy_type or '代理'} 认证代理"
    return "-"


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


def proxy_url(proxy: sqlite3.Row, proxy_type: str | None = None) -> str:
    scheme = (proxy_type or proxy["proxy_type"]).lower()
    if scheme == "socks5":
        scheme = "socks5h"
    username = proxy["username"] if "username" in proxy.keys() else ""
    password = proxy["password"] if "password" in proxy.keys() else ""
    auth = ""
    if username or password:
        auth = f"{quote(username, safe='')}:{quote(password, safe='')}@"
    return f"{scheme}://{auth}{proxy['ip']}:{proxy['port']}"


def proxy_requests_config(proxy: sqlite3.Row, proxy_type: str | None = None) -> dict[str, str]:
    url = proxy_url(proxy, proxy_type)
    return {"http": url, "https": url}


def ordered_proxy_types(preferred: str) -> list[str]:
    preferred = normalize_proxy_type(preferred)
    return [preferred] + [proxy_type for proxy_type in PROXY_TYPES if proxy_type != preferred]


def tcp_port_status(ip: str, port: int) -> tuple[bool, str]:
    try:
        with socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT_SECONDS):
            return True, "端口开放"
    except socket.timeout:
        return False, "超时"
    except ConnectionRefusedError:
        return False, "无代理服务"
    except OSError as exc:
        text = str(exc).lower()
        if "timed out" in text or "timeout" in text:
            return False, "超时"
        if "reset" in text or "10054" in text:
            return False, "连接重置"
        return False, "无代理服务"


def parse_vless_node_url(raw_url: str) -> dict[str, object]:
    raw_url = raw_url.strip()
    parsed = urlparse(raw_url)
    try:
        parsed_port = parsed.port
    except ValueError:
        parsed_port = None
    if parsed.scheme.lower() != "vless" or not parsed.username or not parsed.hostname or not parsed_port:
        return {
            "protocol": parsed.scheme.lower() if parsed.scheme else "",
            "name": "",
            "server_ip": parsed.hostname or "",
            "server_port": parsed_port if parsed.hostname and parsed_port else None,
            "uuid": parsed.username or "",
            "security": "",
            "flow": "",
            "pbk": "",
            "sid": "",
            "transport_type": "",
            "sni": "",
            "raw_url": raw_url,
            "status": NODE_STATUS_PARSE_FAILED,
            "exit_ip": "",
            "exit_country": UNKNOWN,
            "exit_region": UNKNOWN,
            "exit_city": UNKNOWN,
            "exit_isp": UNKNOWN,
            "exit_asn": UNKNOWN,
            "latency_ms": None,
            "real_status": NODE_STATUS_UNAVAILABLE,
            "real_latency_ms": None,
            "check_message": "VLESS 链接解析失败",
            "last_message": "VLESS 链接解析失败",
            "last_checked": None,
        }

    query = parse_qs(parsed.query, keep_blank_values=True)

    def first_value(key: str) -> str:
        return query.get(key, [""])[0]

    name = unquote(parsed.fragment or "") or f"{parsed.hostname}:{parsed_port}"
    return {
        "protocol": parsed.scheme.lower(),
        "name": name,
        "server_ip": parsed.hostname,
        "server_port": parsed_port,
        "uuid": parsed.username,
        "security": first_value("security"),
        "flow": first_value("flow"),
        "pbk": first_value("pbk"),
        "sid": first_value("sid"),
        "transport_type": first_value("type"),
        "sni": first_value("sni"),
        "raw_url": raw_url,
        "status": NODE_STATUS_CONFIG_OK,
        "exit_ip": "",
        "exit_country": UNKNOWN,
        "exit_region": UNKNOWN,
        "exit_city": UNKNOWN,
        "exit_isp": UNKNOWN,
        "exit_asn": UNKNOWN,
        "latency_ms": None,
        "real_status": "",
        "real_latency_ms": None,
        "check_message": "配置解析成功",
        "last_message": "配置解析成功",
        "last_checked": None,
    }


def check_node_port(node: dict[str, object] | sqlite3.Row) -> tuple[str, int | None, str]:
    if not node["server_ip"] or not node["server_port"]:
        return NODE_STATUS_PARSE_FAILED, None, current_time()
    checked_at = current_time()
    started_at = time.monotonic()
    try:
        with socket.create_connection(
            (str(node["server_ip"]), int(node["server_port"])),
            timeout=CONNECT_TIMEOUT_SECONDS,
        ):
            latency_ms = int((time.monotonic() - started_at) * 1000)
            return NODE_STATUS_PORT_OPEN, latency_ms, checked_at
    except OSError:
        return NODE_STATUS_PORT_CLOSED, None, checked_at


def build_xray_config(node: dict[str, object] | sqlite3.Row, socks_port: int) -> dict[str, object]:
    stream_settings = {
        "network": node["transport_type"] or "tcp",
        "security": node["security"] or "reality",
    }
    if stream_settings["security"] == "reality":
        stream_settings["realitySettings"] = {
            "serverName": node["sni"] or "",
            "publicKey": node["pbk"] or "",
            "shortId": node["sid"] or "",
            "fingerprint": "chrome",
        }
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"udp": False, "auth": "noauth"},
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": node["server_ip"],
                            "port": int(node["server_port"]),
                            "users": [
                                {
                                    "id": node["uuid"],
                                    "encryption": "none",
                                    "flow": node["flow"] or "",
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": stream_settings,
            }
        ],
    }


def reserve_local_port(preferred_port: int | None = None) -> int:
    if preferred_port:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", preferred_port))
                return preferred_port
            except OSError:
                pass
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_local_port(port: int, timeout_seconds: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def xray_binary_path() -> str | None:
    configured_path = os.environ.get("XRAY_PATH", "").strip()
    if configured_path and Path(configured_path).exists():
        return configured_path
    bundled_name = "xray.exe" if os.name == "nt" else "xray"
    bundled_path = APP_DIR / "tools" / "xray" / bundled_name
    if bundled_path.exists():
        return str(bundled_path)
    return shutil.which("xray")


def is_xray_available() -> bool:
    return xray_binary_path() is not None


def xray_version_output(xray_path: str) -> str:
    try:
        completed = subprocess.run(
            [xray_path, "version"],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
    except Exception as exc:
        return f"版本检测失败：{exc}"
    output = "\n".join(
        part.strip()
        for part in (completed.stdout, completed.stderr)
        if part and part.strip()
    )
    return output or f"xray version 退出码：{completed.returncode}"


def xray_status_details() -> dict[str, object]:
    configured_path = os.environ.get("XRAY_PATH", "").strip()
    which_path = shutil.which("xray") or ""
    resolved_path = xray_binary_path() or ""
    version = xray_version_output(resolved_path) if resolved_path else ""
    return {
        "installed": bool(resolved_path),
        "configured_path": configured_path,
        "which_path": which_path,
        "resolved_path": resolved_path,
        "version": version,
    }


def xray_diagnostic_message() -> str:
    details = xray_status_details()
    installed = "已安装" if details["installed"] else "未安装"
    version_line = str(details["version"]).splitlines()[0] if details["version"] else "-"
    return (
        f"Xray状态：{installed}；"
        f"XRAY_PATH={details['configured_path'] or '-'}；"
        f"which xray={details['which_path'] or '-'}；"
        f"使用路径={details['resolved_path'] or '-'}；"
        f"xray version={version_line}"
    )


def unknown_exit_geo(message: str = "") -> dict[str, str]:
    return {
        "exit_country": UNKNOWN,
        "exit_region": UNKNOWN,
        "exit_city": UNKNOWN,
        "exit_isp": UNKNOWN,
        "exit_asn": UNKNOWN,
        "geo_message": message,
    }


def query_vless_exit_geo(exit_ip: str) -> dict[str, str]:
    if not exit_ip:
        return unknown_exit_geo("出口 IP 为空，跳过地理信息查询。")
    try:
        response = requests.get(IPWHOIS_URL.format(ip=exit_ip), timeout=10)
        response.raise_for_status()
        data = response.json()
    except Exception as exc:
        return unknown_exit_geo(f"出口 IP 地理信息查询失败：{exc}")

    if not data.get("success", False):
        return unknown_exit_geo(f"出口 IP 地理信息查询失败：{data.get('message') or 'Unknown error'}")

    connection = data.get("connection") or {}
    asn_value = connection.get("asn") or data.get("asn") or UNKNOWN
    if isinstance(asn_value, int):
        asn_value = f"AS{asn_value}"
    elif str(asn_value).isdigit():
        asn_value = f"AS{asn_value}"

    return {
        "exit_country": data.get("country") or UNKNOWN,
        "exit_region": data.get("region") or UNKNOWN,
        "exit_city": data.get("city") or UNKNOWN,
        "exit_isp": connection.get("isp") or connection.get("org") or UNKNOWN,
        "exit_asn": str(asn_value or UNKNOWN),
        "geo_message": "出口 IP 地理信息查询成功。",
    }


def check_node_with_xray(node: dict[str, object] | sqlite3.Row) -> dict[str, object]:
    checked_at = current_time()
    diagnostic = xray_diagnostic_message()
    if not node["server_ip"] or not node["server_port"] or not node["uuid"]:
        return {
            "real_status": NODE_STATUS_UNAVAILABLE,
            "real_latency_ms": None,
            "exit_ip": "",
            **unknown_exit_geo(),
            "last_checked": checked_at,
            "check_message": f"{diagnostic}；节点字段不完整，无法生成 Xray 配置。",
        }

    xray_path = xray_binary_path()
    if not xray_path:
        return {
            "real_status": NODE_STATUS_UNAVAILABLE,
            "real_latency_ms": None,
            "exit_ip": "",
            **unknown_exit_geo(),
            "last_checked": checked_at,
            "check_message": f"{diagnostic}；请安装 xray-core 后再进行真实检测，或设置 XRAY_PATH。",
        }

    socks_port = reserve_local_port(XRAY_SOCKS_TEST_PORT)
    config = build_xray_config(node, socks_port)
    process = None
    with tempfile.TemporaryDirectory(prefix="proxymanager-xray-") as tmpdir:
        config_path = Path(tmpdir) / "config.json"
        config_path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")
        started_at = time.monotonic()
        try:
            process = subprocess.Popen(
                [xray_path, "run", "-config", str(config_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            if not wait_for_local_port(socks_port):
                stderr = ""
                if process.poll() is not None and process.stderr:
                    stderr = process.stderr.read()[-300:]
                return {
                    "real_status": NODE_STATUS_UNAVAILABLE,
                    "real_latency_ms": None,
                    "exit_ip": "",
                    **unknown_exit_geo(),
                    "last_checked": checked_at,
                    "check_message": f"{diagnostic}；Xray SOCKS5 本地端口 127.0.0.1:{socks_port} 启动失败。{stderr}".strip(),
                }
            response = requests.get(
                IPIFY_URL,
                proxies={
                    "http": f"socks5h://127.0.0.1:{socks_port}",
                    "https": f"socks5h://127.0.0.1:{socks_port}",
                },
                timeout=XRAY_TEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            exit_ip = response.json().get("ip", "")
            if not exit_ip:
                return {
                    "real_status": NODE_STATUS_UNAVAILABLE,
                    "real_latency_ms": None,
                    "exit_ip": "",
                    **unknown_exit_geo(),
                    "last_checked": checked_at,
                    "check_message": f"{diagnostic}；api.ipify.org 未返回出口 IP。",
                }
            latency_ms = int((time.monotonic() - started_at) * 1000)
            geo = query_vless_exit_geo(exit_ip)
            return {
                "real_status": NODE_STATUS_AVAILABLE,
                "real_latency_ms": latency_ms,
                "exit_ip": exit_ip,
                "exit_country": geo["exit_country"],
                "exit_region": geo["exit_region"],
                "exit_city": geo["exit_city"],
                "exit_isp": geo["exit_isp"],
                "exit_asn": geo["exit_asn"],
                "last_checked": checked_at,
                "check_message": f"{diagnostic}；Xray 检测成功，本地 SOCKS5 端口 127.0.0.1:{socks_port}；{geo['geo_message']}",
            }
        except Exception as exc:
            return {
                "real_status": NODE_STATUS_UNAVAILABLE,
                "real_latency_ms": None,
                "exit_ip": "",
                **unknown_exit_geo(),
                "last_checked": checked_at,
                "check_message": f"{diagnostic}；{exc}",
            }
        finally:
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)


def node_status_badge_class(status: str) -> str:
    if not status or status == "-":
        return "text-bg-secondary"
    if status in {NODE_STATUS_CONFIG_OK, NODE_STATUS_PORT_OPEN, NODE_STATUS_AVAILABLE}:
        return "text-bg-success"
    if status == NODE_STATUS_PARSE_FAILED:
        return "text-bg-warning"
    return "text-bg-danger"


def protocol_status_from_error(error: BaseException | str, response: requests.Response | None = None) -> str:
    status_code = response.status_code if response is not None else None
    if status_code == 407 or status_code == 401:
        return "认证失败"
    text = str(error).lower()
    if "407" in text or "proxy authentication" in text or "authentication" in text:
        return "认证失败"
    if isinstance(error, (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.Timeout)):
        return "超时"
    if "timed out" in text or "timeout" in text:
        return "超时"
    if "connection reset" in text or "connectionreseterror" in text or "10054" in text or "remote end closed" in text:
        return "连接重置"
    if "connection refused" in text or "10061" in text:
        return "无代理服务"
    if isinstance(error, requests.exceptions.ProxyError):
        return "协议错误"
    if isinstance(error, requests.exceptions.SSLError) or isinstance(error, ssl.SSLError):
        return "协议错误"
    if status_code and status_code >= 400:
        return "协议错误"
    return "协议错误"


def choose_protocol_status(statuses: list[str], port_status: str) -> str:
    if port_status != "端口开放":
        return port_status
    for status in ("认证失败", "超时", "连接重置", "协议错误", "无代理服务"):
        if status in statuses:
            return status
    return "协议错误"


def auth_status(proxy: sqlite3.Row | dict[str, object]) -> str:
    username = proxy["username"] if "username" in proxy.keys() else ""
    password = proxy["password"] if "password" in proxy.keys() else ""
    if not username and not password:
        return "无认证"
    protocol_status = ""
    if "last_protocol_status" in proxy.keys() and proxy["last_protocol_status"]:
        protocol_status = str(proxy["last_protocol_status"])
    elif "protocol_status" in proxy.keys() and proxy["protocol_status"]:
        protocol_status = str(proxy["protocol_status"])
    last_connectable = proxy["last_connectable"] if "last_connectable" in proxy.keys() else None
    if protocol_status == "认证失败":
        return "认证失败"
    if last_connectable == 1:
        return "认证通过"
    return "已配置"


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


def classify_failure(error: BaseException | str, response: requests.Response | None = None) -> str:
    if response is not None and response.status_code >= 400:
        return "HTTP失败"

    text = str(error).lower()
    if isinstance(error, (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.Timeout)):
        return "连接超时"
    if isinstance(error, requests.exceptions.SSLError) or isinstance(error, ssl.SSLError):
        return "TLS失败"
    if isinstance(error, requests.exceptions.HTTPError):
        return "HTTP失败"
    if isinstance(error, socket.gaierror) or "name resolution" in text or "getaddrinfo" in text or "dns" in text:
        return "DNS失败"
    if "timed out" in text or "timeout" in text:
        return "连接超时"
    if "connection refused" in text or "actively refused" in text or "10061" in text:
        return "连接被拒绝"
    if "connection reset" in text or "connectionreseterror" in text or "10054" in text or "remote end closed" in text:
        return "连接重置"
    if "ssl" in text or "tls" in text or "certificate" in text:
        return "TLS失败"
    if "status code" in text or "bad status" in text:
        return "HTTP失败"
    return "HTTP失败"


def health_level(success_rate: float | int | None) -> str:
    rate = float(success_rate or 0)
    if rate >= 90:
        return "健康"
    if rate >= 70:
        return "一般"
    if rate >= 40:
        return "危险"
    return "失效"


def latency_recommend_score(latency_ms: int | float | None) -> float:
    if latency_ms is None:
        return 0
    latency = max(0, float(latency_ms))
    if latency <= 500:
        return 100
    if latency >= 5000:
        return 0
    return round(100 - ((latency - 500) / 4500 * 100), 2)


def recommend_score(proxy: sqlite3.Row | dict[str, object]) -> float:
    success_rate = float(proxy["success_rate"] or 0)
    latency_ms = proxy["latency_ms"]
    if "last_latency_ms" in proxy.keys() and proxy["last_latency_ms"] is not None:
        latency_ms = proxy["last_latency_ms"]
    return round(
        (success_rate * 0.5)
        + (latency_recommend_score(latency_ms) * 0.3)
        + (float(proxy["score"] or 0) * 0.2),
        2,
    )


def verify_proxy_once(proxy: sqlite3.Row) -> dict[str, object]:
    port_open, initial_protocol_status = tcp_port_status(proxy["ip"], proxy["port"])
    if not port_open:
        return {
            "connectable": False,
            "message": initial_protocol_status,
            "failure_reason": initial_protocol_status,
            "detected_proxy_type": "",
            "protocol_status": initial_protocol_status,
            "exit_ip": "",
            "latency_ms": None,
            "country": UNKNOWN,
            "state": UNKNOWN,
            "city": UNKNOWN,
            "isp": UNKNOWN,
            "asn": UNKNOWN,
        }

    errors: list[str] = []
    protocol_statuses: list[str] = []
    for candidate_type in ordered_proxy_types(proxy["proxy_type"]):
        started_at = datetime.now()
        try:
            response = requests.get(
                IPIFY_URL,
                proxies=proxy_requests_config(proxy, candidate_type),
                timeout=CONNECT_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            exit_ip = response.json().get("ip", "")
            if not exit_ip:
                return {
                    "connectable": False,
                    "message": "ipify response did not include ip",
                    "failure_reason": "出口IP获取失败",
                    "detected_proxy_type": candidate_type,
                    "protocol_status": "协议错误",
                    "exit_ip": "",
                    "latency_ms": None,
                    "country": UNKNOWN,
                    "state": UNKNOWN,
                    "city": UNKNOWN,
                    "isp": UNKNOWN,
                    "asn": UNKNOWN,
                }
        except requests.exceptions.HTTPError as exc:
            status = protocol_status_from_error(exc, exc.response)
            protocol_statuses.append(status)
            errors.append(f"{candidate_type}: {exc}")
            continue
        except (requests.RequestException, ValueError) as exc:
            status = protocol_status_from_error(exc)
            protocol_statuses.append(status)
            errors.append(f"{candidate_type}: {exc}")
            continue

        latency_ms = int((datetime.now() - started_at).total_seconds() * 1000)
        location = query_exit_location(exit_ip)
        message = f"proxy verified as {candidate_type}"
        failure_reason = ""
        protocol_status = "端口开放"
        if location["error"]:
            message = f"proxy verified as {candidate_type}; location: {location['error']}"
            failure_reason = "地理位置查询失败"

        return {
            "connectable": True,
            "message": message,
            "failure_reason": failure_reason,
            "detected_proxy_type": candidate_type,
            "protocol_status": protocol_status,
            "exit_ip": exit_ip,
            "latency_ms": latency_ms,
            "country": location["country"],
            "state": location["state"],
            "city": location["city"],
            "isp": location["isp"],
            "asn": location["asn"],
        }

    protocol_status = choose_protocol_status(protocol_statuses, initial_protocol_status)
    return {
        "connectable": False,
        "message": "; ".join(errors) or protocol_status,
        "failure_reason": protocol_status,
        "detected_proxy_type": "",
        "protocol_status": protocol_status,
        "exit_ip": "",
        "latency_ms": None,
        "country": UNKNOWN,
        "state": UNKNOWN,
        "city": UNKNOWN,
        "isp": UNKNOWN,
        "asn": UNKNOWN,
    }


def retry_failure_summary(attempt: int, result: dict[str, object]) -> str:
    reason = str(result.get("failure_reason") or result.get("protocol_status") or "检测失败")
    message = str(result.get("message") or reason)
    return f"第 {attempt} 次失败: {reason} - {message}"


def verify_proxy(proxy: sqlite3.Row) -> dict[str, object]:
    failures: list[str] = []
    last_result: dict[str, object] | None = None

    for attempt in range(1, PROXY_CHECK_RETRY_ATTEMPTS + 1):
        result = verify_proxy_once(proxy)
        if result["connectable"]:
            if failures:
                result["message"] = "; ".join([*failures, f"第 {attempt} 次成功: {result['message']}"])
            return result

        failures.append(retry_failure_summary(attempt, result))
        last_result = result
        if attempt < PROXY_CHECK_RETRY_ATTEMPTS:
            time.sleep(PROXY_CHECK_RETRY_DELAY_SECONDS)

    if last_result is None:
        last_result = {
            "connectable": False,
            "message": "检测失败",
            "failure_reason": "HTTP失败",
            "detected_proxy_type": "",
            "protocol_status": "协议错误",
            "exit_ip": "",
            "latency_ms": None,
            "country": UNKNOWN,
            "state": UNKNOWN,
            "city": UNKNOWN,
            "isp": UNKNOWN,
            "asn": UNKNOWN,
        }
    last_result["message"] = "; ".join(failures)
    return last_result


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
    failure_reason = str(result.get("failure_reason") or "")
    detected_proxy_type = str(result.get("detected_proxy_type") or "")
    protocol_status = str(result.get("protocol_status") or "")

    checked_at = current_time()
    db.execute(
        """
        INSERT INTO checks
            (proxy_id, checked_at, connectable, message, country, state, city, exit_ip, latency_ms, isp, asn, failure_reason, detected_proxy_type, protocol_status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            failure_reason,
            detected_proxy_type,
            protocol_status,
        ),
    )
    if connectable:
        new_status = "online"
        new_score = min(100, proxy["score"] + 1 + latency_score_bonus(result["latency_ms"]))
        db.execute(
            """
            UPDATE proxies
            SET
                proxy_type = ?,
                detected_proxy_type = ?,
                status = ?,
                score = ?,
                consecutive_failures = 0,
                success_count = success_count + 1,
                exit_ip = ?,
                latency_ms = ?,
                isp = ?,
                asn = ?,
                failure_reason = '',
                protocol_status = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                detected_proxy_type or proxy["proxy_type"],
                detected_proxy_type,
                new_status,
                new_score,
                result["exit_ip"],
                result["latency_ms"],
                result["isp"],
                result["asn"],
                protocol_status,
                checked_at,
                proxy["id"],
            ),
        )
    else:
        consecutive_failures = proxy["consecutive_failures"] + 1
        new_status = "invalid" if consecutive_failures >= INVALID_FAILURE_THRESHOLD else proxy["status"]
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
                failure_reason = ?,
                protocol_status = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (new_status, new_score, consecutive_failures, failure_reason, protocol_status, checked_at, proxy["id"]),
        )
    db.commit()
    return proxy


def fetch_proxies(
    query: str = "",
    state: str = "",
    sort_by: str = "",
    health_filter: str = "",
    failure_reason_filter: str = "",
    provider_id: int | None = None,
    customer_id: int | None = None,
    unassigned_only: bool = False,
) -> list[sqlite3.Row]:
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
            OR c.failure_reason LIKE ?
            OR sp.name LIKE ?
            OR cu.name LIKE ?
            )
            """
        )
        like_query = f"%{query}%"
        params.extend([like_query] * 10)
    if state:
        conditions.append("c.state = ?")
        params.append(state)
    if failure_reason_filter:
        conditions.append("COALESCE(NULLIF(c.failure_reason, ''), NULLIF(p.failure_reason, '')) = ?")
        params.append(failure_reason_filter)
    if provider_id:
        conditions.append("p.provider_id = ?")
        params.append(provider_id)
    if customer_id:
        conditions.append("p.customer_id = ?")
        params.append(customer_id)
    if unassigned_only:
        conditions.append("p.customer_id IS NULL")
    if conditions:
        where = "WHERE " + " AND ".join(conditions)

    order_by = "p.created_at DESC, p.id DESC"
    if sort_by == "score":
        order_by = "p.score DESC, p.created_at DESC"
    elif sort_by == "latency":
        order_by = "CASE WHEN p.latency_ms IS NULL THEN 1 ELSE 0 END, p.latency_ms ASC"
    elif sort_by == "success_rate":
        order_by = "success_rate DESC, p.created_at DESC"
    elif sort_by == "provider":
        order_by = "sp.name COLLATE NOCASE ASC, p.created_at DESC"

    rows = get_db().execute(
        """
        SELECT
            p.*,
            sp.name AS provider_name,
            sp.description AS provider_description,
            cu.name AS customer_name,
            cu.status AS customer_status,
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
            c.failure_reason AS last_failure_reason,
            c.detected_proxy_type AS last_detected_proxy_type,
            c.protocol_status AS last_protocol_status,
            CASE
                WHEN (p.success_count + p.failure_count) = 0 THEN 0
                ELSE ROUND((p.success_count * 100.0) / (p.success_count + p.failure_count), 1)
            END AS success_rate
        FROM proxies p
        LEFT JOIN source_providers sp ON sp.id = p.provider_id
        LEFT JOIN customers cu ON cu.id = p.customer_id
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
    if health_filter:
        rows = [row for row in rows if health_level(row["success_rate"]) == health_filter]
    return rows


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


def fetch_proxy_check_history(proxy_ids: list[int], limit_per_proxy: int = 10) -> dict[int, list[sqlite3.Row]]:
    if not proxy_ids:
        return {}
    placeholders = ",".join("?" for _ in proxy_ids)
    rows = get_db().execute(
        f"""
        SELECT *
        FROM (
            SELECT
                c.*,
                ROW_NUMBER() OVER (
                    PARTITION BY c.proxy_id
                    ORDER BY c.checked_at DESC, c.id DESC
                ) AS row_number
            FROM checks c
            WHERE c.proxy_id IN ({placeholders})
        )
        WHERE row_number <= ?
        ORDER BY proxy_id, checked_at DESC, id DESC
        """,
        [*proxy_ids, limit_per_proxy],
    ).fetchall()
    history: dict[int, list[sqlite3.Row]] = {proxy_id: [] for proxy_id in proxy_ids}
    for row in rows:
        history.setdefault(row["proxy_id"], []).append(row)
    return history


def recommend_ranked_proxies(proxies: list[sqlite3.Row]) -> list[sqlite3.Row]:
    return sorted(
        proxies,
        key=lambda proxy: (
            recommend_score(proxy),
            proxy["success_rate"] or 0,
            proxy["score"] or 0,
        ),
        reverse=True,
    )


def top_recommend_proxy_ids(proxies: list[sqlite3.Row], limit: int = 10) -> set[int]:
    candidates = [
        proxy for proxy in proxies
        if proxy["last_connectable"] == 1 and proxy["status"] == "online"
    ]
    return {proxy["id"] for proxy in recommend_ranked_proxies(candidates)[:limit]}


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
    isp_counts: dict[str, int] = {}
    for proxy in proxies:
        isp = proxy["isp"] or proxy["last_isp"] or ""
        if isp and isp != UNKNOWN:
            isp_counts[isp] = isp_counts.get(isp, 0) + 1
    top_isp = ""
    if isp_counts:
        top_isp_name, top_isp_count = max(isp_counts.items(), key=lambda item: item[1])
        top_isp = f"{top_isp_name} ({top_isp_count})"

    provider_rows = provider_stats()
    top_provider = ""
    provider_success_rate = 0
    provider_latency = 0
    if provider_rows:
        top_provider_row = max(provider_rows, key=lambda row: (row["proxy_count"], row["success_rate"] or 0))
        top_provider = f"{top_provider_row['name']} ({top_provider_row['proxy_count']})"
        success_rows = [row for row in provider_rows if row["proxy_count"]]
        if success_rows:
            provider_success_rate = round(
                sum(row["success_rate"] or 0 for row in success_rows) / len(success_rows),
                1,
            )
        latency_rows = [row for row in provider_rows if row["avg_latency"] is not None]
        if latency_rows:
            provider_latency = round(
                sum(row["avg_latency"] or 0 for row in latency_rows) / len(latency_rows)
            )

    best_proxy_candidates = [
        proxy for proxy in proxies
        if proxy["last_connectable"] == 1 and proxy["status"] == "online"
    ]
    best_proxy = recommend_ranked_proxies(best_proxy_candidates)[0] if best_proxy_candidates else None

    failure_reason_counts = {reason: 0 for reason in FAILURE_REASON_SUMMARY}
    for row in get_db().execute(
        """
        SELECT failure_reason, COUNT(*) AS count
        FROM (
            SELECT COALESCE(NULLIF(c.failure_reason, ''), NULLIF(p.failure_reason, '')) AS failure_reason
            FROM proxies p
            LEFT JOIN checks c ON c.id = (
                SELECT id FROM checks
                WHERE proxy_id = p.id
                ORDER BY checked_at DESC, id DESC
                LIMIT 1
            )
        )
        WHERE failure_reason IN (?, ?, ?, ?)
        GROUP BY failure_reason
        """,
        FAILURE_REASON_SUMMARY,
    ).fetchall():
        failure_reason_counts[row["failure_reason"]] = row["count"]

    return {
        "online_rate": round((online / total) * 100, 1) if total else 0,
        "last_checked_at": last_checked_at,
        "state_counts": state_counts,
        "avg_latency_ms": avg_latency_ms,
        "fastest_proxy": f"{fastest['ip']}:{fastest['port']} ({fastest['latency_ms']} ms)" if fastest else "",
        "slowest_proxy": f"{slowest['ip']}:{slowest['port']} ({slowest['latency_ms']} ms)" if slowest else "",
        "avg_success_rate": avg_success_rate,
        "top_isp": top_isp,
        "top_provider": top_provider,
        "provider_success_rate": provider_success_rate,
        "provider_latency": provider_latency,
        "best_proxy": best_proxy,
        "best_proxy_recommend_score": recommend_score(best_proxy) if best_proxy else 0,
        "failure_reason_counts": failure_reason_counts,
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
        "country_labels": [display_location(row["country"]) for row in country_rows] or [display_location(UNKNOWN)],
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
        "detected_proxy_type": proxy["detected_proxy_type"] if "detected_proxy_type" in proxy.keys() else "",
        "protocol_status": proxy["protocol_status"] if "protocol_status" in proxy.keys() else "",
        "auth_enabled": bool(proxy["username"] if "username" in proxy.keys() else ""),
        "auth_status": auth_status(proxy),
        "provider": proxy["provider_name"] if "provider_name" in proxy.keys() else "",
        "customer": proxy["customer_name"] if "customer_name" in proxy.keys() else "",
        "country": proxy["country"] or UNKNOWN,
        "state": proxy["state"] or UNKNOWN,
        "city": proxy["city"] or UNKNOWN,
        "exit_ip": proxy["exit_ip"] or "",
        "latency_ms": proxy["latency_ms"],
        "isp": proxy["isp"] or "",
        "asn": proxy["asn"] or "",
        "success_rate": proxy["success_rate"],
        "health_level": health_level(proxy["success_rate"]),
        "failure_reason": proxy["failure_reason"] if "failure_reason" in proxy.keys() else "",
        "recommend_score": recommend_score(proxy),
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
        SELECT k.*, u.username, c.name AS customer_name
        FROM api_keys k
        JOIN users u ON u.id = k.user_id
        LEFT JOIN customers c ON c.id = k.customer_id
        WHERE k.api_key = ?
          AND k.status = 'active'
          AND (k.customer_id IS NULL OR c.status = 'active')
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
    proxy_type: str | None = None,
    provider: str | None = None,
    customer_id: int | None = None,
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
    if proxy_type is not None:
        conditions.append("LOWER(p.proxy_type) = LOWER(?)")
        params.append(proxy_type)
    if provider is not None:
        conditions.append("LOWER(sp.name) = LOWER(?)")
        params.append(provider)
    if customer_id is not None:
        conditions.append("p.customer_id = ?")
        params.append(customer_id)

    return get_db().execute(
        """
        SELECT
            p.ip,
            p.port,
            p.proxy_type,
            p.username,
            p.password,
            sp.name AS provider_name,
            cu.name AS customer_name,
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
            c.failure_reason,
            c.detected_proxy_type,
            c.protocol_status,
            c.checked_at AS last_checked_at,
            CASE
                WHEN (p.success_count + p.failure_count) = 0 THEN 0
                ELSE ROUND((p.success_count * 100.0) / (p.success_count + p.failure_count), 1)
            END AS success_rate
        FROM proxies p
        LEFT JOIN source_providers sp ON sp.id = p.provider_id
        LEFT JOIN customers cu ON cu.id = p.customer_id
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


def api_key_customer_id(api_key: sqlite3.Row) -> int | None:
    return api_key["customer_id"] if "customer_id" in api_key.keys() and api_key["customer_id"] else None


def best_proxy_response(
    api_key: sqlite3.Row,
    *,
    proxy_type: str | None = None,
    provider: str | None = None,
    state: str | None = None,
):
    proxies = fetch_online_proxies(
        proxy_type=proxy_type,
        provider=provider,
        state=state,
        customer_id=api_key_customer_id(api_key),
    )
    if not proxies:
        return api_success(None, api_key)
    best_proxy = recommend_ranked_proxies(proxies)[0]
    return api_success(serialize_proxy(best_proxy), api_key)


def dashboard_metrics() -> dict[str, int]:
    today = datetime.now().strftime("%Y-%m-%d")
    return {
        "total_users": get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "total_api_keys": get_db().execute("SELECT COUNT(*) FROM api_keys").fetchone()[0],
        "total_customers": get_db().execute("SELECT COUNT(*) FROM customers").fetchone()[0],
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
            c.name AS customer_name,
            COUNT(l.id) AS call_count
        FROM api_keys k
        LEFT JOIN customers c ON c.id = k.customer_id
        LEFT JOIN api_logs l ON l.api_key_id = k.id
        WHERE k.user_id = ?
        GROUP BY k.id
        ORDER BY k.created_at DESC, k.id DESC
        """,
        (user_id,),
    ).fetchall()


def customers(include_inactive: bool = True) -> list[sqlite3.Row]:
    where = "" if include_inactive else "WHERE status = 'active'"
    return get_db().execute(
        """
        SELECT *
        FROM customers
        """ + where + """
        ORDER BY status = 'disabled' ASC, name COLLATE NOCASE ASC, id ASC
        """
    ).fetchall()


def valid_customer_id(customer_id_text: str, allow_empty: bool = True) -> int | None:
    try:
        customer_id = int(customer_id_text)
    except (TypeError, ValueError):
        return None if allow_empty else 0
    row = get_db().execute(
        "SELECT id FROM customers WHERE id = ?", (customer_id,)
    ).fetchone()
    return row["id"] if row else None


def source_providers() -> list[sqlite3.Row]:
    return get_db().execute(
        """
        SELECT *
        FROM source_providers
        ORDER BY name COLLATE NOCASE ASC, id ASC
        """
    ).fetchall()


def valid_provider_id(provider_id_text: str) -> int:
    try:
        provider_id = int(provider_id_text)
    except (TypeError, ValueError):
        return 1
    row = get_db().execute(
        "SELECT id FROM source_providers WHERE id = ?", (provider_id,)
    ).fetchone()
    return row["id"] if row else 1


def provider_stats() -> list[sqlite3.Row]:
    return get_db().execute(
        """
        SELECT
            sp.id,
            sp.name,
            COUNT(p.id) AS proxy_count,
            ROUND(
                CASE
                    WHEN SUM(COALESCE(p.success_count, 0) + COALESCE(p.failure_count, 0)) = 0 THEN 0
                    ELSE SUM(COALESCE(p.success_count, 0)) * 100.0 /
                         SUM(COALESCE(p.success_count, 0) + COALESCE(p.failure_count, 0))
                END,
                1
            ) AS success_rate,
            ROUND(AVG(p.latency_ms), 0) AS avg_latency,
            ROUND(AVG(p.score), 1) AS avg_score
        FROM source_providers sp
        LEFT JOIN proxies p ON p.provider_id = sp.id
        GROUP BY sp.id
        ORDER BY proxy_count DESC, success_rate DESC, sp.name COLLATE NOCASE ASC
        """
    ).fetchall()


def fetch_nodes() -> list[sqlite3.Row]:
    return get_db().execute(
        """
        SELECT *
        FROM nodes
        ORDER BY created_at DESC, id DESC
        """
    ).fetchall()


def insert_node(parsed_node: dict[str, object]) -> bool:
    now = current_time()
    try:
        get_db().execute(
            """
            INSERT INTO nodes (
                protocol, name, server_ip, server_port, uuid, security, flow,
                pbk, sid, transport_type, sni, raw_url, status, latency_ms,
                exit_ip, exit_country, exit_region, exit_city, exit_isp, exit_asn,
                real_status, real_latency_ms, check_message, last_message,
                created_at, last_checked
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                parsed_node["protocol"],
                parsed_node["name"],
                parsed_node["server_ip"],
                parsed_node["server_port"],
                parsed_node["uuid"],
                parsed_node["security"],
                parsed_node["flow"],
                parsed_node["pbk"],
                parsed_node["sid"],
                parsed_node["transport_type"],
                parsed_node["sni"],
                parsed_node["raw_url"],
                parsed_node["status"],
                parsed_node["latency_ms"],
                parsed_node.get("exit_ip", ""),
                parsed_node.get("exit_country", UNKNOWN),
                parsed_node.get("exit_region", UNKNOWN),
                parsed_node.get("exit_city", UNKNOWN),
                parsed_node.get("exit_isp", UNKNOWN),
                parsed_node.get("exit_asn", UNKNOWN),
                parsed_node.get("real_status", ""),
                parsed_node.get("real_latency_ms"),
                parsed_node.get("check_message", ""),
                parsed_node.get("last_message", ""),
                now,
                parsed_node["last_checked"],
            ),
        )
        get_db().commit()
        return True
    except sqlite3.IntegrityError:
        return False


def update_node_check(node_id: int) -> None:
    node = get_db().execute("SELECT * FROM nodes WHERE id = ?", (node_id,)).fetchone()
    if node is None:
        return
    port_status, port_latency_ms, port_checked_at = check_node_port(node)
    if port_status != NODE_STATUS_PORT_OPEN:
        get_db().execute(
            """
            UPDATE nodes
            SET status = ?, latency_ms = ?, real_status = ?, real_latency_ms = NULL,
                exit_ip = '', exit_country = ?, exit_region = ?, exit_city = ?,
                exit_isp = ?, exit_asn = ?, check_message = ?, last_message = ?, last_checked = ?
            WHERE id = ?
            """,
            (
                port_status,
                port_latency_ms,
                NODE_STATUS_UNAVAILABLE,
                UNKNOWN,
                UNKNOWN,
                UNKNOWN,
                UNKNOWN,
                UNKNOWN,
                f"端口检测结果：{port_status}，未执行 Xray 真实出口检测。",
                f"端口检测结果：{port_status}",
                port_checked_at,
                node_id,
            ),
        )
        get_db().commit()
        return
    result = check_node_with_xray(node)
    get_db().execute(
        """
        UPDATE nodes
        SET status = ?, latency_ms = ?, real_status = ?, real_latency_ms = ?,
            exit_ip = ?, exit_country = ?, exit_region = ?, exit_city = ?,
            exit_isp = ?, exit_asn = ?, check_message = ?, last_message = ?, last_checked = ?
        WHERE id = ?
        """,
        (
            port_status,
            port_latency_ms,
            result["real_status"],
            result["real_latency_ms"],
            result["exit_ip"],
            result.get("exit_country", UNKNOWN),
            result.get("exit_region", UNKNOWN),
            result.get("exit_city", UNKNOWN),
            result.get("exit_isp", UNKNOWN),
            result.get("exit_asn", UNKNOWN),
            result["check_message"],
            result["check_message"],
            result["last_checked"],
            node_id,
        ),
    )
    get_db().commit()


def customer_stats() -> list[sqlite3.Row]:
    return get_db().execute(
        """
        SELECT
            c.id,
            c.name,
            c.contact,
            c.status,
            c.created_at,
            COUNT(DISTINCT p.id) AS proxy_count,
            COUNT(DISTINCT CASE WHEN p.status = 'online' THEN p.id END) AS online_count,
            COUNT(DISTINCT k.id) AS api_key_count
        FROM customers c
        LEFT JOIN proxies p ON p.customer_id = c.id
        LEFT JOIN api_keys k ON k.customer_id = c.id
        GROUP BY c.id
        ORDER BY c.status = 'disabled' ASC, c.name COLLATE NOCASE ASC
        """
    ).fetchall()


def parse_proxy_line(line: str) -> tuple[str, str, str, str, str, str] | None:
    cleaned = line.strip()
    if not cleaned or cleaned.startswith("#"):
        return None

    label = ""
    username = ""
    password = ""
    colon_parts = cleaned.split(":")
    if len(colon_parts) == 4 and " " not in cleaned and "," not in cleaned:
        ip, port_text, username, password = [part.strip() for part in colon_parts]
        label = "IPRoyal SOCKS5 认证代理"
        return ip, port_text, "SOCKS5", label, username, password

    if "," in cleaned:
        parts = [part.strip() for part in cleaned.split(",", 3)]
        if len(parts) >= 2:
            ip, port_text = parts[0], parts[1]
            proxy_type = normalize_proxy_type(parts[2] if len(parts) >= 3 else "")
            label = parts[3] if len(parts) == 4 else ""
            if len(parts) == 3 and parts[2].upper() not in PROXY_TYPES:
                proxy_type = "HTTP"
                label = parts[2]
            return ip, port_text, proxy_type, label, username, password

    if ":" in cleaned and " " not in cleaned:
        ip, port_text = cleaned.rsplit(":", 1)
        return ip.strip(), port_text.strip(), "HTTP", label, username, password

    parts = cleaned.split(maxsplit=3)
    if len(parts) >= 2:
        ip, port_text = parts[0], parts[1]
        proxy_type = normalize_proxy_type(parts[2] if len(parts) >= 3 else "")
        label = parts[3] if len(parts) == 4 else ""
        if len(parts) == 3 and parts[2].upper() not in PROXY_TYPES:
            proxy_type = "HTTP"
            label = parts[2]
        return ip, port_text, proxy_type, label, username, password

    return None


def normalize_proxy_type(value: str) -> str:
    proxy_type = value.strip().upper()
    return proxy_type if proxy_type in PROXY_TYPES else "HTTP"


def insert_proxy(ip: str, port: int, proxy_type: str, label: str) -> bool:
    return insert_proxy_with_provider(ip, port, proxy_type, label, 1, "", "")


def insert_proxy_with_provider(
    ip: str,
    port: int,
    proxy_type: str,
    label: str,
    provider_id: int,
    username: str = "",
    password: str = "",
) -> bool:
    now = current_time()
    try:
        get_db().execute(
            """
            INSERT INTO proxies (ip, port, proxy_type, provider_id, username, password, label, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ip,
                port,
                normalize_proxy_type(proxy_type),
                provider_id,
                username.strip(),
                password,
                label,
                now,
                now,
            ),
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
    selected_health = request.args.get("health", "").strip()
    selected_failure_reason = request.args.get("failure_reason", "").strip()
    selected_provider_id = valid_provider_id(request.args.get("provider", "")) if request.args.get("provider") else 0
    selected_customer_filter = request.args.get("customer", "").strip()
    selected_customer_id = 0
    unassigned_only = selected_customer_filter == "unassigned"
    if selected_customer_filter and not unassigned_only:
        selected_customer_id = valid_customer_id(selected_customer_filter) or 0
    if selected_state not in STATE_FILTERS:
        selected_state = ""
    if selected_sort not in {"score", "latency", "success_rate", "provider"}:
        selected_sort = ""
    if selected_health not in HEALTH_LEVELS:
        selected_health = ""
    if selected_failure_reason not in FAILURE_REASONS:
        selected_failure_reason = ""
    all_proxies = fetch_proxies()
    proxies = fetch_proxies(
        query,
        selected_state,
        selected_sort,
        selected_health,
        selected_failure_reason,
        selected_provider_id or None,
        selected_customer_id or None,
        unassigned_only,
    )
    proxy_check_map = fetch_proxy_check_history([proxy["id"] for proxy in proxies])
    return render_template_string(
        PAGE_TEMPLATE,
        auth_status=auth_status,
        display_location=display_location,
        display_proxy_label=display_proxy_label,
        failure_reasons=FAILURE_REASONS,
        failure_summary_reasons=FAILURE_REASON_SUMMARY,
        health_level=health_level,
        health_levels=HEALTH_LEVELS,
        UNKNOWN=UNKNOWN,
        customers=customers(False),
        dashboard=build_dashboard_stats(all_proxies),
        invalid_proxies=[proxy for proxy in all_proxies if proxy["status"] == "invalid"],
        query=query,
        proxy_types=PROXY_TYPES,
        providers=source_providers(),
        proxy_check_map=proxy_check_map,
        proxies=proxies,
        recommend_score=recommend_score,
        recent_checks=fetch_recent_checks(),
        scheduler_config=scheduler_settings(),
        selected_failure_reason=selected_failure_reason,
        selected_health=selected_health,
        selected_customer_filter=selected_customer_filter,
        selected_customer_id=selected_customer_id,
        selected_provider_id=selected_provider_id,
        selected_state=selected_state,
        selected_sort=selected_sort,
        state_filters=STATE_FILTERS,
        stats=build_stats(proxies),
        top_proxy_ids=top_recommend_proxy_ids(all_proxies),
    )


@app.route("/analytics")
def analytics_page():
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
    all_proxies = fetch_proxies()
    return render_template_string(
        ANALYTICS_TEMPLATE,
        chart_data=build_chart_data(),
        dashboard=build_dashboard_stats(all_proxies),
        display_location=display_location,
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
        customers=customers(False),
        metrics=dashboard_metrics(),
    )


@app.route("/api-keys", methods=["POST"])
def create_api_key():
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
    user = get_current_user()
    customer_id = valid_customer_id(request.form.get("customer_id", "")) if request.form.get("customer_id") else None
    get_db().execute(
        """
        INSERT INTO api_keys (user_id, customer_id, api_key, status, created_at)
        VALUES (?, ?, ?, 'active', ?)
        """,
        (user["id"], customer_id, generate_api_key(), current_time()),
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


@app.route("/customers")
def customers_page():
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
    return render_template_string(
        CUSTOMERS_TEMPLATE,
        stats=customer_stats(),
    )


@app.route("/customers", methods=["POST"])
def create_customer():
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
    name = request.form.get("name", "").strip()
    contact = request.form.get("contact", "").strip()
    if not name:
        flash("客户名称不能为空。")
        return redirect(url_for("customers_page"))
    try:
        get_db().execute(
            """
            INSERT INTO customers (name, contact, status, created_at)
            VALUES (?, ?, 'active', ?)
            """,
            (name, contact, current_time()),
        )
        get_db().commit()
        flash("客户已创建。")
    except sqlite3.IntegrityError:
        flash("客户名称已存在。")
    return redirect(url_for("customers_page"))


@app.route("/customers/<int:customer_id>", methods=["POST"])
def update_customer(customer_id: int):
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
    name = request.form.get("name", "").strip()
    contact = request.form.get("contact", "").strip()
    if not name:
        flash("客户名称不能为空。")
        return redirect(url_for("customers_page"))
    try:
        get_db().execute(
            "UPDATE customers SET name = ?, contact = ? WHERE id = ?",
            (name, contact, customer_id),
        )
        get_db().commit()
        flash("客户已更新。")
    except sqlite3.IntegrityError:
        flash("客户名称已存在。")
    return redirect(url_for("customers_page"))


def update_customer_status(customer_id: int, status: str):
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
    get_db().execute("UPDATE customers SET status = ? WHERE id = ?", (status, customer_id))
    get_db().commit()
    flash(f"客户已{('启用' if status == 'active' else '禁用')}。")
    return redirect(url_for("customers_page"))


@app.route("/customers/<int:customer_id>/enable", methods=["POST"])
def enable_customer(customer_id: int):
    return update_customer_status(customer_id, "active")


@app.route("/customers/<int:customer_id>/disable", methods=["POST"])
def disable_customer(customer_id: int):
    return update_customer_status(customer_id, "disabled")


@app.route("/customers/<int:customer_id>/delete", methods=["POST"])
def delete_customer(customer_id: int):
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
    get_db().execute("UPDATE proxies SET customer_id = NULL WHERE customer_id = ?", (customer_id,))
    get_db().execute("UPDATE api_keys SET customer_id = NULL WHERE customer_id = ?", (customer_id,))
    get_db().execute("DELETE FROM customers WHERE id = ?", (customer_id,))
    get_db().commit()
    flash("客户已删除，相关代理已变为未分配。")
    return redirect(url_for("customers_page"))


@app.route("/proxies/<int:proxy_id>/assign-customer", methods=["POST"])
def assign_proxy_customer(proxy_id: int):
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
    customer_id = valid_customer_id(request.form.get("customer_id", "")) if request.form.get("customer_id") else None
    get_db().execute(
        "UPDATE proxies SET customer_id = ?, updated_at = ? WHERE id = ?",
        (customer_id, current_time(), proxy_id),
    )
    get_db().commit()
    flash("代理客户分配已更新。")
    return redirect(request.referrer or url_for("index"))


@app.route("/nodes")
def nodes_page():
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
    return render_template_string(
        NODES_TEMPLATE,
        nodes=fetch_nodes(),
        node_status_badge_class=node_status_badge_class,
        display_location=display_location,
        xray_available=is_xray_available(),
    )


@app.route("/nodes/xray-status")
def xray_status_page():
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
    return render_template_string(
        XRAY_STATUS_TEMPLATE,
        details=xray_status_details(),
    )


@app.route("/nodes/import", methods=["POST"])
def import_nodes():
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
    raw_lines = request.form.get("nodes", "").splitlines()
    imported = 0
    failed = 0
    for line in raw_lines:
        raw_url = line.strip()
        if not raw_url:
            continue
        parsed_node = parse_vless_node_url(raw_url)
        if parsed_node["status"] != NODE_STATUS_PARSE_FAILED:
            status, latency_ms, checked_at = check_node_port(parsed_node)
            parsed_node["status"] = status
            parsed_node["latency_ms"] = latency_ms
            parsed_node["last_checked"] = checked_at
            parsed_node["last_message"] = f"端口检测结果：{status}"
            parsed_node["check_message"] = f"端口检测结果：{status}"
            if status == NODE_STATUS_PORT_OPEN:
                xray_result = check_node_with_xray(parsed_node)
                parsed_node["real_status"] = xray_result["real_status"]
                parsed_node["real_latency_ms"] = xray_result["real_latency_ms"]
                parsed_node["exit_ip"] = xray_result["exit_ip"]
                parsed_node["exit_country"] = xray_result.get("exit_country", UNKNOWN)
                parsed_node["exit_region"] = xray_result.get("exit_region", UNKNOWN)
                parsed_node["exit_city"] = xray_result.get("exit_city", UNKNOWN)
                parsed_node["exit_isp"] = xray_result.get("exit_isp", UNKNOWN)
                parsed_node["exit_asn"] = xray_result.get("exit_asn", UNKNOWN)
                parsed_node["check_message"] = xray_result["check_message"]
                parsed_node["last_message"] = xray_result["check_message"]
                parsed_node["last_checked"] = xray_result["last_checked"]
            else:
                parsed_node["real_status"] = NODE_STATUS_UNAVAILABLE
                parsed_node["real_latency_ms"] = None
                parsed_node["exit_country"] = UNKNOWN
                parsed_node["exit_region"] = UNKNOWN
                parsed_node["exit_city"] = UNKNOWN
                parsed_node["exit_isp"] = UNKNOWN
                parsed_node["exit_asn"] = UNKNOWN
        else:
            failed += 1
        if insert_node(parsed_node):
            imported += 1
    flash(f"导入完成：新增 {imported} 个节点，解析失败 {failed} 个。")
    return redirect(url_for("nodes_page"))


@app.route("/nodes/<int:node_id>/check", methods=["POST"])
def check_node_route(node_id: int):
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
    update_node_check(node_id)
    flash("节点检测已完成。")
    return redirect(url_for("nodes_page"))


@app.route("/nodes/<int:node_id>/delete", methods=["POST"])
def delete_node(node_id: int):
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
    get_db().execute("DELETE FROM nodes WHERE id = ?", (node_id,))
    get_db().commit()
    flash("节点已删除。")
    return redirect(url_for("nodes_page"))


@app.route("/providers")
def providers_page():
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
    return render_template_string(
        PROVIDERS_TEMPLATE,
        providers=source_providers(),
        stats=provider_stats(),
    )


@app.route("/providers", methods=["POST"])
def create_provider():
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    if not name:
        flash("来源名称不能为空。")
        return redirect(url_for("providers_page"))
    try:
        get_db().execute(
            """
            INSERT INTO source_providers (name, description, created_at)
            VALUES (?, ?, ?)
            """,
            (name, description, current_time()),
        )
        get_db().commit()
        flash("来源已新增。")
    except sqlite3.IntegrityError:
        flash("来源名称已存在。")
    return redirect(url_for("providers_page"))


@app.route("/providers/<int:provider_id>", methods=["POST"])
def update_provider(provider_id: int):
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    if not name:
        flash("来源名称不能为空。")
        return redirect(url_for("providers_page"))
    try:
        get_db().execute(
            """
            UPDATE source_providers
            SET name = ?, description = ?
            WHERE id = ?
            """,
            (name, description, provider_id),
        )
        get_db().commit()
        flash("来源已保存。")
    except sqlite3.IntegrityError:
        flash("来源名称已存在。")
    return redirect(url_for("providers_page"))


@app.route("/providers/<int:provider_id>/delete", methods=["POST"])
def delete_provider(provider_id: int):
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
    if provider_id == 1:
        flash("内置来源不能删除。")
        return redirect(url_for("providers_page"))
    get_db().execute("UPDATE proxies SET provider_id = 1 WHERE provider_id = ?", (provider_id,))
    get_db().execute("DELETE FROM source_providers WHERE id = ?", (provider_id,))
    get_db().commit()
    flash("来源已删除，该来源下代理已归入内置来源。")
    return redirect(url_for("providers_page"))


@app.route("/proxies", methods=["POST"])
def create_proxy():
    auth_redirect = login_required()
    if auth_redirect:
        return auth_redirect
    ip = request.form.get("ip", "").strip()
    port_text = request.form.get("port", "").strip()
    label = request.form.get("label", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    proxy_type = normalize_proxy_type(request.form.get("proxy_type", "HTTP"))
    provider_id = valid_provider_id(request.form.get("provider_id", "1"))
    port, error = validate_proxy(ip, port_text)

    if error:
        flash(error)
        return redirect(url_for("index"))

    if insert_proxy_with_provider(ip, port, proxy_type, label, provider_id, username, password):
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
    provider_id = valid_provider_id(request.form.get("provider_id", "1"))
    added = 0
    skipped = 0
    invalid = 0

    for line in text.splitlines():
        parsed = parse_proxy_line(line)
        if parsed is None:
            if line.strip():
                invalid += 1
            continue

        ip, port_text, proxy_type, label, username, password = parsed
        port, error = validate_proxy(ip, port_text)
        if error or port is None:
            invalid += 1
            continue

        if insert_proxy_with_provider(ip, port, proxy_type, label, provider_id, username, password):
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
            "detected_proxy_type",
            "protocol_status",
            "auth_enabled",
            "auth_status",
            "username",
            "provider",
            "customer",
            "label",
            "last_checked_at",
            "connectable",
            "failure_reason",
            "health_level",
            "exit_ip",
            "latency_ms",
            "isp",
            "asn",
            "success_rate",
            "score",
            "recommend_score",
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
                proxy["last_detected_proxy_type"] or proxy["detected_proxy_type"] or "",
                proxy["last_protocol_status"] or proxy["protocol_status"] or "",
                1 if proxy["username"] else 0,
                auth_status(proxy),
                proxy["username"] or "",
                proxy["provider_name"] or "",
                proxy["customer_name"] or "",
                proxy["label"],
                proxy["last_checked_at"] or "",
                "" if proxy["last_connectable"] is None else proxy["last_connectable"],
                proxy["last_failure_reason"] or proxy["failure_reason"] or "",
                health_level(proxy["success_rate"]),
                proxy["last_exit_ip"] or proxy["exit_ip"] or "",
                proxy["last_latency_ms"] or proxy["latency_ms"] or "",
                proxy["last_isp"] or proxy["isp"] or "",
                proxy["last_asn"] or proxy["asn"] or "",
                proxy["success_rate"],
                proxy["score"],
                recommend_score(proxy),
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
        {"method": "GET", "path": "/api/best"},
        {"method": "GET", "path": "/api/best/http"},
        {"method": "GET", "path": "/api/best/socks5"},
        {"method": "GET", "path": "/api/best/provider/IPRoyal"},
        {"method": "GET", "path": "/api/best/state/California"},
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
    proxies = [
        serialize_proxy(proxy)
        for proxy in fetch_online_proxies(customer_id=api_key_customer_id(api_key))
    ]
    return api_success(proxies, api_key)


@app.route("/api/random")
def api_random():
    api_key, key_error = require_api_key()
    if key_error:
        return key_error
    proxies = fetch_online_proxies(customer_id=api_key_customer_id(api_key))
    if not proxies:
        return api_success(None, api_key)
    return api_success(serialize_proxy(random.choice(proxies)), api_key)


@app.route("/api/best")
def api_best():
    api_key, key_error = require_api_key()
    if key_error:
        return key_error
    return best_proxy_response(api_key)


@app.route("/api/best/http")
def api_best_http():
    api_key, key_error = require_api_key()
    if key_error:
        return key_error
    return best_proxy_response(api_key, proxy_type="HTTP")


@app.route("/api/best/socks5")
def api_best_socks5():
    api_key, key_error = require_api_key()
    if key_error:
        return key_error
    return best_proxy_response(api_key, proxy_type="SOCKS5")


@app.route("/api/best/provider/<path:provider>")
def api_best_provider(provider: str):
    api_key, key_error = require_api_key()
    if key_error:
        return key_error
    return best_proxy_response(api_key, provider=provider)


@app.route("/api/best/state/<path:state>")
def api_best_state(state: str):
    api_key, key_error = require_api_key()
    if key_error:
        return key_error
    return best_proxy_response(api_key, state=state)


@app.route("/api/country/<path:country>")
def api_country(country: str):
    api_key, key_error = require_api_key()
    if key_error:
        return key_error
    proxies = [
        serialize_proxy(proxy)
        for proxy in fetch_online_proxies(country=country, customer_id=api_key_customer_id(api_key))
    ]
    return api_success(proxies, api_key)


@app.route("/api/state/<path:state>")
def api_state(state: str):
    api_key, key_error = require_api_key()
    if key_error:
        return key_error
    proxies = [
        serialize_proxy(proxy)
        for proxy in fetch_online_proxies(state=state, customer_id=api_key_customer_id(api_key))
    ]
    return api_success(proxies, api_key)


@app.route("/api/city/<path:city>")
def api_city(city: str):
    api_key, key_error = require_api_key()
    if key_error:
        return key_error
    proxies = [
        serialize_proxy(proxy)
        for proxy in fetch_online_proxies(city=city, customer_id=api_key_customer_id(api_key))
    ]
    return api_success(proxies, api_key)


@app.route("/health")
def health():
    return {"status": "ok"}


init_db()


if __name__ == "__main__":
    start_scheduler()
    app.run(
        host=os.environ.get("APP_HOST", "127.0.0.1"),
        port=int(os.environ.get("APP_PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
        use_reloader=False,
    )
