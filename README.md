# ProxyManager

ProxyManager 是一个基于 Flask 和 SQLite 的代理 IP 检测 Web 管理后台。它可以集中维护代理资产，检测 IP 与端口的连通性，查询 IP 地理位置，并保留最近检测记录，适合用于小型代理池管理、连通性巡检和结果归档。

## 功能说明

- 代理管理：添加、查看和删除代理 IP 与端口。
- 连通性检测：支持单个代理检测和批量检测。
- 状态统计：首页展示代理总数、可连接、不可连接和未检测数量。
- 检测记录：保存每次检测时间、状态、错误信息和地理位置。
- SQLite 存储：使用本地 `proxy_manager.db` 保存代理资产和检测记录。
- CSV 兼容：首次启动时可从旧版 `proxy_check_results.csv` 自动导入历史数据。
- 健康检查：提供 `/health` 接口用于服务状态检查。

## 安装方法

1. 克隆项目：

```bash
git clone https://github.com/duanwu6888/ProxyManager.git
cd ProxyManager
```

2. 创建并激活虚拟环境：

```bash
python -m venv .venv
.venv\Scripts\activate
```

3. 安装依赖：

```bash
pip install -r requirements.txt
```

## 使用方法

1. 启动 Web 管理后台：

```bash
python main.py
```

2. 在浏览器访问：

```text
http://127.0.0.1:5000/
```

3. 在后台页面中添加代理 IP 和端口。

4. 点击单个代理的“检测”按钮，或点击页面顶部的“批量检测”按钮。

5. 查看首页统计、代理列表和最近检测记录。

6. 健康检查接口：

```text
http://127.0.0.1:5000/health
```

## 示例截图位置

建议将后台截图放在以下位置：

```text
docs/screenshots/dashboard.png
```

放置截图后，可在 README 中启用以下展示：

```markdown
![ProxyManager 后台截图](docs/screenshots/dashboard.png)
```

## 项目结构

```text
ProxyManager/
|-- main.py                  # Flask 应用入口和后台页面
|-- requirements.txt         # Python 依赖
|-- proxy_check_results.csv  # 旧版 CSV 检测结果，可自动导入
|-- .gitignore               # Git 忽略规则
|-- LICENSE                  # MIT 开源协议
`-- README.md                # 项目说明文档
```

运行后会在本地生成 `proxy_manager.db`，该文件用于保存 SQLite 数据，默认不会提交到 Git。

## 开源协议

本项目采用 [MIT License](LICENSE) 开源协议。

你可以自由使用、复制、修改、合并、发布、分发、再授权和销售本项目代码，但需在副本中保留原始版权声明和许可声明。
