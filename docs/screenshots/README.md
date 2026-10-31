<!-- SPDX-License-Identifier: Apache-2.0 -->
# 桌面界面截图 / Desktop screenshots

采集日期：2026-11-01（Asia/Shanghai）。应用版本：0.1.0。图片尺寸：1280 × 720。

图片来自 `pnpm build` 生成的真实桌面前端，使用临时的本地命令桥连接 `AppCore`，在浏览器中操作并截图。
账号列表、条目详情、宿主检测、本机执行器和资源登记都由 Rust 核心返回；界面使用仓库中的原始样式。
原生 macOS 应用包已编译并启动；当前环境的原生窗口自动化持续超时，因此采用上述采集方式。
正式桌面配置及运行时的 `contentProtected` 保护均保持启用。

使用单独的临时账号库，包含四条虚构凭据、一个演示项目和两个测试资源。
所有服务地址使用 `example.com` 保留域名，密码保持掩码；未连接实际的 API 或数据库服务。
AI 工具列表来自本机实际检测，标识为“标准协议可接入”，不表示已完成这些宿主的端到端兼容验证。

| 图片 | 内容 |
| --- | --- |
| [02-vault.jpg](02-vault.jpg) | 按项目分组的账号库与隐藏密码的账号详情 |
| [03-ai-connections.jpg](03-ai-connections.jpg) | 本机 AI 工具检测与接入范围 |
| [04-executors.jpg](04-executors.jpg) | 本机执行器、兼容连接说明和演示资源 |
| [01-overview.jpg](01-overview.jpg) | 账号库、同步、执行器状态与恢复材料提醒 |

总览保留了运行中实际出现的恢复材料提醒：恢复验证与后台同步存在状态更新竞争，可能使验证标记丢失。
该并发问题需要单独修复，详见[桌面端限制](../../desktop/README.md#limitations)。

The screenshots show the compiled desktop frontend connected to the real local Rust core through a temporary
loopback bridge and captured in a browser. The vault and credentials are fictional; secrets remain masked.
The native macOS app was built and launched separately. Production screen-capture protection remains enabled.
