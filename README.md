# ProxyManager

ProxyManager 是一个基于 Flask + SQLite 的代理 IP 管理后台，支持真实代理验证、代理池 API、用户与 API Key、自动检测、健康诊断、来源管理和推荐引擎。

## 功能

- Web 管理后台：添加、批量导入、删除、搜索和筛选代理。
- 真实代理验证：通过代理访问 `api.ipify.org` 获取出口 IP，并查询国家、州、城市、ISP、ASN。
- 代理类型：HTTP、HTTPS、SOCKS4、SOCKS5。
- 自动检测：支持定时循环检测，失败自动下线和隔离。
- 诊断系统：失败原因分类、健康等级、最近 10 次检测记录。
- 来源管理：维护代理来源，查看来源成功率、平均延迟和平均评分。
- 推荐引擎：按成功率、延迟、评分计算 `recommend_score`，提供最佳代理 API。
- API Key 鉴权：API 请求使用 `X-API-Key` Header。
- Docker 部署：提供 `Dockerfile`、`docker-compose.yml` 和启动脚本。

## 环境变量

复制示例配置：

```bash
cp .env.example .env
```

常用配置：

```env
SECRET_KEY=change-me-to-a-long-random-secret
API_KEY=proxymanager-v6-api-key
DATABASE_URL=sqlite:///proxy_manager.db
APP_HOST=127.0.0.1
APP_PORT=5000
FLASK_DEBUG=0
```

说明：

- `SECRET_KEY`：Flask Session 密钥，生产环境必须修改。
- `API_KEY`：启动时自动写入系统 API Key，可直接用于 API 调用。
- `DATABASE_URL`：SQLite 数据库地址。Docker 默认使用 `sqlite:////data/proxy_manager.db`。

## Windows 部署

```bat
git clone https://github.com/duanwu6888/ProxyManager.git
cd ProxyManager
copy .env.example .env
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
start.bat
```

访问：

```text
http://127.0.0.1:5000/
```

## Ubuntu 部署

```bash
git clone https://github.com/duanwu6888/ProxyManager.git
cd ProxyManager
cp .env.example .env
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
sh start.sh
```

访问：

```text
http://127.0.0.1:5000/
```

## Docker 部署

```bash
git clone https://github.com/duanwu6888/ProxyManager.git
cd ProxyManager
cp .env.example .env
docker compose up -d --build
```

访问：

```text
http://127.0.0.1:5000/
```

查看状态：

```bash
docker compose ps
docker compose logs -f
```

停止服务：

```bash
docker compose down
```

SQLite 数据保存在 Docker volume `proxymanager_data` 中。

## API 说明

所有代理池 API 使用 Header 鉴权：

```http
X-API-Key: proxymanager-v6-api-key
```

基础接口：

```text
GET /api/proxies
GET /api/random
GET /api/country/<country>
GET /api/state/<state>
GET /api/city/<city>
```

推荐接口：

```text
GET /api/best
GET /api/best/http
GET /api/best/socks5
GET /api/best/provider/<provider>
GET /api/best/state/<state>
```

示例：

```bash
curl -H "X-API-Key: proxymanager-v6-api-key" http://127.0.0.1:5000/api/best
```

返回字段包含：

```json
{
  "success": true,
  "count": 1,
  "data": {
    "ip": "1.2.3.4",
    "port": 8080,
    "proxy_type": "HTTP",
    "provider": "默认来源",
    "country": "United States",
    "state": "California",
    "city": "Los Angeles",
    "exit_ip": "1.2.3.4",
    "latency_ms": 300,
    "isp": "Example ISP",
    "asn": "AS12345",
    "success_rate": 95.0,
    "health_level": "健康",
    "failure_reason": "",
    "recommend_score": 96.2,
    "score": 100,
    "last_checked": "2026-06-07 10:00:00"
  }
}
```

## 健康检查

```text
GET /health
```

## 项目结构

```text
ProxyManager/
|-- main.py              # Flask 应用入口
|-- requirements.txt     # Python 依赖
|-- Dockerfile           # Docker 镜像构建
|-- docker-compose.yml   # Docker Compose 部署
|-- .env.example         # 环境变量示例
|-- start.sh             # Linux/macOS 启动脚本
|-- start.bat            # Windows 启动脚本
|-- LICENSE              # MIT License
`-- README.md            # 项目文档
```

## 截图位置

建议将截图放在：

```text
docs/screenshots/dashboard.png
```

## License

本项目采用 [MIT License](LICENSE)。
