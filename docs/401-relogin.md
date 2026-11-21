# 401 重登与 CRS 接口

桥接使用独立环境变量 `CRS_LOGIN_BRIDGE_KEY`，仅接受 `Authorization: Bearer …`。控制台 token、cookie 和查询字符串均不能替代服务凭证。公用部署的 HTTPS 入口会拒绝这些接口。将 CRS 接入本项目的 Docker 网络后，通过 `http://app:4399` 访问；调用方配置自己的独立服务密钥。CRS 需要支持 `credentialGuardian` 扩展，不适用于所有原版发行版。

`POST /api/integrations/crs/login` 接受不超过 16 KiB 的 JSON：`operationId`、`email`、可选 `password`、`totpSecret`、`proxyUrl`。密码和 TOTP 省略时复用已保存材料；空 TOTP 也视为省略。代理省略时保持当前/已保存代理，null 指定直连，非空字符串指定代理，不自动回退直连。

首次与重复 POST 均返回 HTTP 202 和当前 `{jobId,status}`；任务成功时同时包含 `credentials`，失败时包含通用 `error`。`GET /api/integrations/crs/login/:operationId` 返回同样的结果。终态只有 succeeded/failed；进行中为 pending/running。相同 ID 配不同参数返回 409，未知启动结果不自动重新执行。成功结果绑定到对应任务代次并快照，后续手动操作不会替换旧结果。

成功 OAuth 结果保留 24 小时，启动、访问以及每 60 秒清除过期凭证。清理后保留精简幂等记录并返回 failed，旧 operationId 不会再启动登录。默认最多 10000 个操作，单份凭证 32 KiB、全部保留结果共 64 MiB；达到上限明确拒绝，不自动删除幂等记录。容量需要后续显式归档/扩容；不要直接删除旧 ID 以免历史请求重放。所有记录继续使用现有数据库加密。

CRS 分组读取实际 options 接口；只有唯一忽略大小写的 openai 分组可默认选择。上传设置冻结在 `items[0].settings`，账号并发默认为 7，优先级使用 `weight`（1–100，默认 1）。401 重登的 `credentialGuardian` 仅发送 `{enabled}`，由 CRS 为新账号补默认策略、为已有账号保留测试/model/周期等定制字段。工具桥接完成只交还凭证，不自动上传，也不恢复 CRS 调度；降智停用后的测试、上号与恢复限制由 CRS 执行。

设置 `TOSUB2_STANDBY=1` 和 `TOSUB2_ACTIVATION_FILE` 时，进程先启动轻量控制端口，**不开数据库、不恢复工作目录、不运行队列**。GET `/api/integrations/crs/runtime/status` 返回 standby；POST `/runtime/activate` 返回 202，随后打开数据库并启动主服务，需继续等 status 返回 active。三个 runtime 路由前缀完整为 `/api/integrations/crs/runtime`。

运行实例支持 POST `/runtime/drain` 和 `/runtime/resume`。排空阻止新工作和新巡检，继续已接收的队列、上传和人工输入/取消；status 的 `readyToStop` 同时检查子进程、账号锁、元数据写入、HTTP 请求、巡检和 CRS worker。GET 可能持久化结果，最终代理交接必须排队全部普通请求。旧实例完全停止后才能激活共享数据库的新实例。

`TOSUB2_CONSOLE_TOKEN` 可由部署控制器从现有 bootstrap 获取并通过进程环境传入，以保持切换前后的已打开页面可用；格式为 32–128 个 base64url 字符。不得记录到部署输出。

本地 UI 验证：从项目根运行 `node test/manual-crs-ui.mjs`，打开 `http://127.0.0.1:43927`。数据、凭证、CRS 都是合成数据；Ctrl+C 会清理临时目录。

激活标记必须放在该候选独有、可持久写入的控制目录中，不能复用其他实例的标记。首次激活先持久化标记再确认；同一容器重启后直接恢复已激活状态，未激活候选重启仍待命。停旧写者与激活的顺序由部署控制器保证。
