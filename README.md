# Auto Login GPT

可独立部署的账号管理和 Codex 授权工具，支持批量登录、账号安全操作，以及向 Sub2API 和 CRS 推送账号。

本项目基于 toSub2 的线上定制版本整理，包含应用、网页登录服务和 HTTPS 入口。新部署使用自己的账号、代理、密钥和数据库。

## 功能

- **直接授权 Codex**：使用现有授权刷新；需要登录时直接进入 Codex 授权流程
- **登录账号后授权 Codex**：需要登录时先建立网页账号会话，再完成 Codex 授权；兼容原 `legacy` 流程
- 单个或批量添加账号，支持仅保存资料、密码、TOTP、邮件验证码和代理配置
- 配置账号并发、优先级和目标分组，推送到 **Sub2API** 或 **CRS**
- **401 重登**：Sub2API 号池巡检，以及 CRS 调用的独立鉴权重登接口
- 在用账号可单个或批量移到**静置区**、**废号区**，保留资料与操作历史
- 定时任务、2FA 管理、退出账号设备、加密数据库和任务状态恢复

## Docker 部署

需要 Docker Compose v2、Python 3 和 OpenSSL。

```sh
git clone https://github.com/949n9/auto-login-gpt.git
cd auto-login-gpt
python3 tools/setup.py
docker compose up -d --build
```

初始化时交互设置网页登录密码。默认入口是 **https://localhost:8443**，用户名为 `admin`，只绑定本机回环地址。首次使用自签名证书，浏览器需要信任证书。

部署到服务器时使用自己的域名和监听地址：

```sh
python3 tools/setup.py --origin https://login.example.com:8443 --bind 0.0.0.0 --username admin
```

将 `private/tls/cert.pem` 和 `private/tls/key.pem` 替换为自己的证书与私钥。初始化脚本拒绝覆盖已有 `.env` 或 `private/`，更新代码时保留它们；账号数据和登录会话分别保存在独立 Docker 卷中。不要使用 `docker compose down -v` 删除需要保留的数据。

应用端口和密码验证端口只在 Compose 内网开放。用户通过网页登录后进入控制台；CRS 重登接口使用独立密钥和内网连接。

## 配置与使用

在控制台配置代理、验证码服务和目标平台，敏感设置保存在本机加密数据库。仓库中的 `.env.example` 仅包含空白配置和默认开关。

| 配置项 | 用途 |
| --- | --- |
| `PUBLIC_ORIGIN` | 网页实际访问的 HTTPS 根地址，须与浏览器地址一致 |
| `HTTPS_BIND` / `HTTPS_PORT` | HTTPS 监听地址与端口 |
| `TOSUB2_CONSOLE_TOKEN` | 内部控制台令牌，初始化时独立生成 |
| `CRS_LOGIN_BRIDGE_KEY` | CRS 401 重登接口的独立密钥，初始化时独立生成 |
| `TOSUB2_DEFAULT_OPERATION_PROXY_ENABLED` | 可选操作代理提取，默认 `0` |
| `TOSUB2_OPERATION_PROXY_URL` | 可选 HTTPS 提取接口，返回单条 `IP:端口`；原有美国出口校验保留 |
| `TOSUB2_DYNAMIC_PROXY_EXTRACTION` | 动态代理提取开关，默认 `0`；供应商密钥在控制台设置 |

代理提取默认关闭，使用前配置自己的代理或供应商。没有保存任何服务器专用地址、供应商密钥或账号资料。

### 推送到 Sub2API 与 CRS

- **Sub2API**：填写服务地址、管理员 API Key、目标号池及代理；账号并发和优先级在 Sub2API 配置中设置，留空时保留导入数据原值
- **CRS**：填写服务地址和管理员登录信息或 API Key；在账号列表或“批量设置 CRS”中设置分组、账号并发、优先级及 401 重登，再推送
- CRS 优先级使用目标接口的 `weight`（1–100）；Sub2API 使用 `priority`（0–10000）。两者的调度语义由各自平台定义
- 目标平台必须实现对应管理接口；CRS 的 401 重登开关需要支持 `credentialGuardian` 扩展的版本，内部字段名为兼容已有接口保留

详见 [401 重登接口](docs/401-relogin.md)。推送超时后先核对目标结果，避免重复导入。

### 账号分区

在账号行或批量操作中选择“移到静置区”“移到废号区”。移动只改变本地管理状态，不删除资料，也不向上游发送登出或停用请求。已经推送到目标平台的账号，不会因本地分区移动而自动被停用。

移入后暂停本地自动登录、代理续换和推送。正在执行登录、安全操作、定时任务或推送时，先结束任务或核对结果再移动。手动静置与已退出设备会分别显示；成功完成一次完整登录后恢复在用，刷新旧令牌不会解除静置或废号状态。

## 本机运行与开发

需要 Node.js **22.13+** 和 Python **3.10+**。建议使用 Python 虚拟环境：

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
npm ci
npm run build
TOSUB2_PYTHON="$PWD/.venv/bin/python" npm start
```

本机入口为 `http://127.0.0.1:4399`。这个开发入口会返回控制台令牌，只供本机访问；公网使用上面的 HTTPS 登录入口。

```sh
npm test                 # 构建及核心、推送、数据库、分区、认证回归
npm run check:login      # TLS 与登录协议回归
npm run check:security   # 账号安全操作回归
CHROME_BIN=/path/to/chrome npm run check:ui
```

测试使用临时数据库、合成账号和本地模拟服务，不需要真实平台密钥。

## 项目结构

```text
src/           登录、账号状态、加密存储与平台接口
web/           React 管理界面
auth/         独立网页登录服务及静态资源
deploy/       Nginx HTTPS 入口配置
tools/        新部署初始化脚本
test/         模拟服务、接口和界面回归
docs/         接口与维护说明
```

## 许可证

沿用上游 MIT 许可证，保留原作者署名。来源与第三方资源见 [UPSTREAM.md](UPSTREAM.md)。
