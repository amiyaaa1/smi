# SimplAI2API

SimplAI → OpenAI 格式中转，带账号池管理 UI、自动补号、余额刷新、轮询切换、项目 run limit 自动轮换。

## 默认信息

- 服务地址：`0.0.0.0:8031`
- 管理页面：`http://服务器IP:8031/`
- 管理密码：`Nishibaka114514.`
- OpenAI 接口：`http://服务器IP:8031/v1/chat/completions`
- 固定模型名：`claude-opus-4.6-simplai`

## 已包含

- Node.js 服务
- HTML 管理台
- PM2 配置
- Docker / Docker Compose 部署
- 自带 `third_party/CloakBrowser`
- 自带 `third_party/protocol_keygen.py`

## OpenAI 接口规则

实际使用：

- `messages`
- `stream`

`max_tokens` / `max_completion_tokens`、`temperature` 等其余参数兼容接收但不透传、不拼入提示词，也不做本地截断。

## 本机 PM2 部署

```bash
cd /root/simplai2api
npm install
python3 -m pip install --break-system-packages -r requirements.txt
python3 -m playwright install --with-deps chromium
npx pm2 start ecosystem.config.cjs
npx pm2 save
```

查看状态：

```bash
npx pm2 status simplai2api
npx pm2 logs simplai2api
```

## Docker 一键部署

```bash
cd /root/simplai2api
bash install.sh
```

或手动：

```bash
docker compose up -d --build
```

## Docker 持久化目录

- `./data`
- `./profiles`
- `./logs`
- `./cloakbrowser-cache`

## 账号与模板说明

管理页面支持：

- 新增 / 编辑 / 删除账号
- 设定模板账号
- 单账号刷新 token
- 单账号 / 全部账号刷新余额
- 手动执行对账 / 自动补号
- 最久未使用账号优先轮询

自动补号依赖“模板账号”的：

- `agentName`
- `agentPipelineId`

账号数据文件：

```text
data/accounts.json
```


## Zeabur 部署

本项目已新增 `zeabur.json`，Zeabur 会优先按 Dockerfile 构建并启动服务。

> 如果你的仓库根目录不是本目录（例如当前仓库是在上层目录里套了 `simplai2api-distribution-20260519_234840/` 子目录），请使用仓库根目录新增的 `Dockerfile` + `zeabur.json`（已适配子目录拷贝），避免 Zeabur 误判为静态服务。

### 1) 上传项目

- 在 Zeabur 新建项目并导入本仓库
- 选择服务目录：`simplai2api-distribution-20260519_234840`（如果你的仓库根目录就是该目录则无需额外设置）

### 2) 持久化目录（非常重要）

请在 Zeabur 的 Volume / Persistent Storage 中挂载这些路径：

- `/app/data`
- `/app/profiles`
- `/app/logs`
- `/app/cloakbrowser-cache`

### 3) 环境变量建议

- `SIMPLAI2API_ADMIN_PASSWORD`：后台登录密码（务必修改默认值）
- `SIMPLAI2API_PORT`：可选，默认 `8031`；在 Zeabur 中建议不设置，让平台 `PORT` 自动接管
- `SIMPLAI2API_HOST`：默认 `0.0.0.0`
- `SIMPLAI_PROFILE_BASE_DIR`：默认 `/app/profiles`
- `SIMPLAI2API_SEED_ACCOUNTS_IF_EMPTY`：默认 `true`；当 Zeabur 挂载空的 `/app/data` 时，会用镜像内置模板初始化账号池，从而触发自动补号
- `SIMPLAI2API_REGISTER_FAILURE_LIMIT`：默认 `3`；单次对账中自动注册遇到临时邮箱/跳转超时等瞬时错误时，会继续重试的失败次数上限

### 4) 访问

部署成功后：

- 管理页面：`https://<你的-zeabur-域名>/`
- OpenAI 接口：`https://<你的-zeabur-域名>/v1/chat/completions`

> 首次启动会安装 Playwright Chromium，构建时间会比普通 Node 服务更长，属于正常现象。


### 5) 单服务说明（无需多服务）

这个项目默认就是**单服务**可运行：

- Web 管理台（`/`）
- OpenAI 兼容接口（`/v1/chat/completions`）
- 账号池、自动补号、轮询等后台逻辑

都在同一个 Node 进程里，不需要在 Zeabur 再拆多个内部服务。

仅当你要启用可选的 WARP 代理（`USE_WARP_PROXY=true`）时，才需要额外准备代理地址；默认关闭该功能，不影响主流程。

### 6) 自动注册账号说明

Zeabur 挂载持久化目录时，空 Volume 会覆盖镜像里的 `/app/data`。本项目会在镜像内保留一份 `/app/default-data/accounts.json`，启动时如果发现 `/app/data/accounts.json` 不存在，或账号池为空且 `SIMPLAI2API_SEED_ACCOUNTS_IF_EMPTY` 未关闭，就会先写入模板账号，再由启动对账自动补号。

启动日志中应能看到；如果某次临时邮箱或验证链接跳转超时，服务会在同一轮对账中继续重试，最多由 `SIMPLAI2API_REGISTER_FAILURE_LIMIT` 控制：

```text
[accounts] initialized /app/data/accounts.json from seed /app/default-data/accounts.json
[reconcile] start reason=startup
[reconcile] finish reason=startup status=... registered=... errors=...
```

## 构建可分发 zip

```bash
cd /root/simplai2api
bash scripts/build_deploy_zip.sh
```

输出目录：

```text
/root/Simple-Cloud-Drive/Simple-Cloud-Drive/storage/
```

## OpenAI 调用示例

```bash
curl http://127.0.0.1:8031/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "anything",
    "messages": [
      {"role": "system", "content": "Be concise."},
      {"role": "user", "content": "Reply with OK only."}
    ],
    "stream": false
  }'
```
