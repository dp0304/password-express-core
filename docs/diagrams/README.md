<!-- SPDX-License-Identifier: Apache-2.0 -->
# 软件架构与工作流程图

| 文件 | 内容 |
| --- | --- |
| [`architecture.png`](architecture.png) | 软件架构：组件、数据通道与部署方式 |
| [`authorization-workflow.png`](authorization-workflow.png) | 授权流程：请求校验、授权、执行与结果过滤 |
| [`architecture.en.png`](architecture.en.png) | 软件架构图英文版 |
| [`authorization-workflow.en.png`](authorization-workflow.en.png) | 授权流程图英文版 |

HPKE 凭证封装由 Broker 转交 Executor；执行结果沿 Executor → Broker → MCP / SDK → AI 宿主返回。
密文同步与服务调用使用独立通道。
