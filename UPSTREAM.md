# 来源与许可

应用源自 [poxiao33/toSub2](https://github.com/poxiao33/toSub2)，沿用仓库中的 MIT 许可证及原作者署名。

本仓库的初始应用基线为已部署的 toSub2 1.9.2 定制版本；从运行文件核对源码后整理为独立的 Auto Login GPT 1.0.0。网页登录服务作为独立组件包含在 `auth/`。没有继承原部署的数据、账号、密钥、会话或 Git 历史。

源码目录保留既有职责：登录协议和任务执行位于 `src/`，管理界面位于 `web/`。为兼容既有加密数据和接口，环境变量、数据库记录与 API 中的 `tosub2`、`crs`、`credentialGuardian` 等标识继续使用；用户界面统一称为“401 重登”。

登录页使用 Inter 和 JetBrains Mono 字体，字体文件的许可文本位于 `auth/public/assets/`。依赖包使用各自许可证，版本由 `package-lock.json` 与 `requirements.txt` 指定。
