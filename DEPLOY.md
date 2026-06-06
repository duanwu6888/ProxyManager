# ProxyManager VPS 部署文档

目标环境：Ubuntu 22.04 LTS  
部署方式：Docker Compose + Nginx 反向代理 + HTTPS  
项目仓库：https://github.com/duanwu6888/ProxyManager

本文假设你已经拥有：

- 一台 Ubuntu 22.04 VPS
- 一个已解析到 VPS 公网 IP 的域名，例如 `proxy.example.com`
- 一个可使用 `sudo` 的用户

下面命令中的域名、路径和密钥请按你的实际情况替换。

## 1. 系统初始化

```bash
sudo apt update
sudo apt upgrade -y
sudo apt install -y ca-certificates curl gnupg git nginx ufw
```

建议设置服务器时区：

```bash
sudo timedatectl set-timezone Asia/Shanghai
```

## 2. 安装 Docker

卸载旧版本 Docker 包：

```bash
for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do
  sudo apt remove -y "$pkg" || true
done
```

添加 Docker 官方 GPG key：

```bash
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
```

添加 Docker apt 仓库：

```bash
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
```

安装 Docker Engine：

```bash
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

启动并设置开机自启：

```bash
sudo systemctl enable --now docker
```

验证安装：

```bash
docker --version
docker compose version
sudo docker run --rm hello-world
```

可选：允许当前用户直接运行 Docker：

```bash
sudo usermod -aG docker $USER
newgrp docker
```

## 3. 安装 Docker Compose

如果你按上一步安装了 `docker-compose-plugin`，Docker Compose 已经安装完成。

验证：

```bash
docker compose version
```

后续命令使用新版格式：

```bash
docker compose up -d
```

不要使用旧格式 `docker-compose`，除非你单独安装了旧版二进制。

## 4. 克隆项目

建议部署到 `/opt`：

```bash
cd /opt
sudo git clone https://github.com/duanwu6888/ProxyManager.git
sudo chown -R $USER:$USER /opt/ProxyManager
cd /opt/ProxyManager
```

如果之后要更新代码：

```bash
cd /opt/ProxyManager
git pull
docker compose up -d --build
```

## 5. 配置 .env

复制环境变量模板：

```bash
cp .env.example .env
```

编辑配置：

```bash
nano .env
```

推荐生产配置：

```env
SECRET_KEY=replace-with-a-long-random-secret
API_KEY=replace-with-a-long-random-api-key
DATABASE_URL=sqlite:////data/proxy_manager.db
APP_PORT=5000
FLASK_DEBUG=0
```

生成随机密钥示例：

```bash
openssl rand -hex 32
```

说明：

- `SECRET_KEY`：Flask Session 密钥，必须修改。
- `API_KEY`：系统启动时会自动写入一个可用 API Key。
- `DATABASE_URL`：Docker 部署建议保持 `sqlite:////data/proxy_manager.db`。
- `APP_PORT`：宿主机映射端口，默认 `5000`。

保护配置文件权限：

```bash
chmod 600 .env
```

## 6. 启动服务

构建并启动：

```bash
docker compose up -d --build
```

查看容器：

```bash
docker compose ps
```

查看日志：

```bash
docker compose logs -f
```

验证健康检查：

```bash
curl http://127.0.0.1:5000/health
```

验证 API：

```bash
curl -H "X-API-Key: replace-with-a-long-random-api-key" \
  http://127.0.0.1:5000/api/proxies
```

## 7. 配置 Nginx

创建 Nginx 站点配置：

```bash
sudo nano /etc/nginx/sites-available/proxymanager
```

写入以下内容，将 `proxy.example.com` 替换为你的域名：

```nginx
server {
    listen 80;
    server_name proxy.example.com;

    client_max_body_size 20m;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
```

启用站点：

```bash
sudo ln -s /etc/nginx/sites-available/proxymanager /etc/nginx/sites-enabled/proxymanager
```

如果默认站点占用配置，可删除默认站点软链接：

```bash
sudo rm -f /etc/nginx/sites-enabled/default
```

测试 Nginx 配置：

```bash
sudo nginx -t
```

重载 Nginx：

```bash
sudo systemctl reload nginx
```

浏览器访问：

```text
http://proxy.example.com
```

## 8. 配置 HTTPS 证书

安装 Certbot：

```bash
sudo apt install -y snapd
sudo snap install core
sudo snap refresh core
sudo snap install --classic certbot
sudo ln -sf /snap/bin/certbot /usr/bin/certbot
```

签发证书并自动修改 Nginx 配置：

```bash
sudo certbot --nginx -d proxy.example.com
```

按提示选择是否强制跳转 HTTPS。建议选择强制跳转。

验证自动续期：

```bash
sudo certbot renew --dry-run
```

续期状态：

```bash
systemctl list-timers | grep certbot || true
```

访问：

```text
https://proxy.example.com
```

## 9. 防火墙配置

允许 SSH、HTTP、HTTPS：

```bash
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw enable
```

查看状态：

```bash
sudo ufw status verbose
```

安全建议：

- 不要对公网开放 `5000` 端口。
- 生产环境只通过 Nginx 暴露 `80` 和 `443`。
- 如果 Docker 端口绕过 UFW，请确保 `docker-compose.yml` 使用 `127.0.0.1:5000:5000` 形式绑定本机回环地址。

可将 `docker-compose.yml` 的 ports 改为：

```yaml
ports:
  - "127.0.0.1:${APP_PORT:-5000}:5000"
```

然后重启：

```bash
docker compose up -d
```

## 10. 自动重启配置

项目的 `docker-compose.yml` 已包含：

```yaml
restart: unless-stopped
```

这表示容器异常退出或服务器重启后会自动恢复。

确认 Docker 开机自启：

```bash
sudo systemctl enable docker
sudo systemctl is-enabled docker
```

确认容器重启策略：

```bash
docker inspect --format='{{.HostConfig.RestartPolicy.Name}}' proxymanager-proxymanager-1 2>/dev/null || docker compose ps
```

推荐额外创建 systemd unit，确保 VPS 重启后进入项目目录拉起 compose：

```bash
sudo nano /etc/systemd/system/proxymanager.service
```

写入：

```ini
[Unit]
Description=ProxyManager Docker Compose Service
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/opt/ProxyManager
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
RemainAfterExit=yes
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
```

启用：

```bash
sudo systemctl daemon-reload
sudo systemctl enable proxymanager
sudo systemctl start proxymanager
sudo systemctl status proxymanager
```

## 11. 数据库备份

Docker 部署默认数据库在容器内：

```text
/data/proxy_manager.db
```

该目录挂载到 Docker volume：

```text
proxymanager_data
```

### 手动备份

创建备份目录：

```bash
sudo mkdir -p /opt/proxymanager-backups
sudo chown -R $USER:$USER /opt/proxymanager-backups
```

执行备份：

```bash
docker compose exec -T proxymanager sh -c 'sqlite3 /data/proxy_manager.db ".backup /tmp/proxy_manager.db"'
docker cp "$(docker compose ps -q proxymanager):/tmp/proxy_manager.db" \
  "/opt/proxymanager-backups/proxy_manager_$(date +%Y%m%d_%H%M%S).db"
```

如果容器内没有 `sqlite3` 命令，可直接备份 Docker volume：

```bash
docker run --rm \
  -v proxymanager_data:/data \
  -v /opt/proxymanager-backups:/backup \
  alpine sh -c 'cp /data/proxy_manager.db /backup/proxy_manager_$(date +%Y%m%d_%H%M%S).db'
```

### 自动备份

创建脚本：

```bash
sudo nano /usr/local/bin/backup-proxymanager.sh
```

写入：

```bash
#!/usr/bin/env bash
set -euo pipefail

BACKUP_DIR="/opt/proxymanager-backups"
mkdir -p "$BACKUP_DIR"

docker run --rm \
  -v proxymanager_data:/data \
  -v "$BACKUP_DIR":/backup \
  alpine sh -c 'cp /data/proxy_manager.db /backup/proxy_manager_$(date +%Y%m%d_%H%M%S).db'

find "$BACKUP_DIR" -name "proxy_manager_*.db" -type f -mtime +14 -delete
```

授权：

```bash
sudo chmod +x /usr/local/bin/backup-proxymanager.sh
```

添加 cron：

```bash
sudo crontab -e
```

每天凌晨 3 点备份：

```cron
0 3 * * * /usr/local/bin/backup-proxymanager.sh >> /var/log/proxymanager-backup.log 2>&1
```

查看备份：

```bash
ls -lh /opt/proxymanager-backups
```

### 恢复数据库

停止服务：

```bash
cd /opt/ProxyManager
docker compose down
```

恢复备份：

```bash
docker run --rm \
  -v proxymanager_data:/data \
  -v /opt/proxymanager-backups:/backup \
  alpine sh -c 'cp /backup/proxy_manager_YYYYMMDD_HHMMSS.db /data/proxy_manager.db'
```

重新启动：

```bash
docker compose up -d
```

## 12. 常用运维命令

查看日志：

```bash
cd /opt/ProxyManager
docker compose logs -f
```

重启：

```bash
docker compose restart
```

更新项目：

```bash
cd /opt/ProxyManager
git pull
docker compose up -d --build
```

查看容器健康状态：

```bash
docker compose ps
curl http://127.0.0.1:5000/health
```

查看 Nginx 日志：

```bash
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log
```

## 13. 常见故障排查

### docker: command not found

说明 Docker 没有安装成功，或当前 shell 没有加载 Docker 命令。

检查：

```bash
docker --version
which docker
sudo systemctl status docker
```

处理：

```bash
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
```

### docker compose 命令不存在

新版 Docker Compose 是 Docker 插件，命令是 `docker compose`，不是 `docker-compose`。

检查：

```bash
docker compose version
```

处理：

```bash
sudo apt install -y docker-compose-plugin
```

### docker compose up 后容器反复重启

查看日志：

```bash
cd /opt/ProxyManager
docker compose ps
docker compose logs -f
```

常见原因：

- `.env` 配置错误。
- `DATABASE_URL` 路径不可写。
- 端口 `5000` 已被占用。
- 镜像构建中依赖安装失败。

检查端口：

```bash
sudo ss -lntp | grep 5000 || true
```

重新构建：

```bash
docker compose down
docker compose up -d --build
```

### 首页打不开

先检查本机服务：

```bash
curl http://127.0.0.1:5000/health
docker compose ps
```

如果本机正常但域名打不开，检查 Nginx：

```bash
sudo nginx -t
sudo systemctl status nginx
sudo tail -n 100 /var/log/nginx/error.log
```

确认域名解析：

```bash
dig +short proxy.example.com
curl -I http://proxy.example.com
```

### Nginx 502 Bad Gateway

通常是 Nginx 无法连接到后端容器。

检查后端：

```bash
curl http://127.0.0.1:5000/health
docker compose logs --tail=100 proxymanager
```

确认 Nginx 配置里的 `proxy_pass` 是：

```nginx
proxy_pass http://127.0.0.1:5000;
```

如果 `docker-compose.yml` 端口改过，请同步修改 Nginx 配置。

### HTTPS 证书申请失败

检查域名是否解析到当前 VPS：

```bash
dig +short proxy.example.com
curl -I http://proxy.example.com
```

检查 80 端口是否开放：

```bash
sudo ufw status
sudo ss -lntp | grep ':80'
```

重新运行：

```bash
sudo nginx -t
sudo systemctl reload nginx
sudo certbot --nginx -d proxy.example.com
```

### API 返回 401

说明 `X-API-Key` 不正确或没有传 Header。

检查 `.env`：

```bash
cat /opt/ProxyManager/.env
```

测试：

```bash
curl -H "X-API-Key: replace-with-a-long-random-api-key" \
  http://127.0.0.1:5000/api/proxies
```

如果修改了 `.env` 中的 `API_KEY`，需要重启服务：

```bash
docker compose restart
```

### 数据库无法写入

检查 Docker volume：

```bash
docker volume ls | grep proxymanager
docker compose exec proxymanager sh -c 'ls -lh /data && touch /data/write-test && rm /data/write-test'
```

如果使用自定义挂载目录，确认目录权限：

```bash
sudo chown -R 1000:1000 /path/to/data
```

### 防火墙开启后访问异常

确认只开放 SSH、HTTP、HTTPS：

```bash
sudo ufw status verbose
```

放行：

```bash
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw reload
```

生产环境不要直接开放 `5000` 到公网。

### 备份文件没有生成

手动执行备份脚本看错误：

```bash
sudo /usr/local/bin/backup-proxymanager.sh
tail -n 100 /var/log/proxymanager-backup.log
```

检查 cron：

```bash
sudo crontab -l
systemctl status cron
```

确认备份目录：

```bash
ls -lh /opt/proxymanager-backups
```

## 14. 安全检查清单

- 已修改 `.env` 中的 `SECRET_KEY`。
- 已修改 `.env` 中的 `API_KEY`。
- 防火墙只开放 SSH、80、443。
- Docker 应用端口只绑定到 `127.0.0.1`。
- 已启用 HTTPS。
- 已验证 Certbot 自动续期。
- 已配置数据库每日备份。
- 已确认 Docker 和 ProxyManager 可开机自启。

## 参考

- Docker Engine Ubuntu 官方安装文档：https://docs.docker.com/engine/install/ubuntu/
- Certbot 官方说明：https://certbot.eff.org/
- Ubuntu UFW 防火墙文档：https://documentation.ubuntu.com/server/how-to/security/firewalls/
