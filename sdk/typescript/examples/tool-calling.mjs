#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// 把 AI 通行证工具接入任意模型的函数调用循环 / Plug AI Pass tools into any model's tool loop.
//
// This example does not call a model API. It prints the tool definitions in OpenAI and Anthropic
// formats plus the system-prompt snippet, then dispatches the tool calls a model would emit and
// shows the exact tool-result payloads you would send back. Replace `modelToolCalls` with the
// tool calls from your model's response.
//
//   AIPASS_KEY_FILE=./lure-agent.key node examples/tool-calling.mjs
import {
  AIPassClient,
  anthropicTools,
  openAITools,
  systemPrompt,
  toAnthropicToolResult,
  toOpenAIToolMessage,
} from "@aipass/sdk";

const locale = (process.env.AIPASS_LOCALE ?? "").startsWith("en") ? "en" : "zh-CN";

// 1) Give these to your model.
const request = {
  system: systemPrompt({ locale }),
  openai_tools: openAITools({ locale }),
  anthropic_tools: anthropicTools({ locale }),
};
console.log(`system prompt:\n${request.system}\n`);
console.log(`tools: ${request.openai_tools.map((t) => t.function.name).join(", ")}\n`);

if (!process.env.AIPASS_KEY_FILE && !process.env.AIPASS_TOKEN) {
  console.log("Set AIPASS_KEY_FILE or AIPASS_TOKEN to also dispatch sample tool calls against your broker.");
  process.exit(0);
}

const client = process.env.AIPASS_TOKEN
  ? new AIPassClient({ bearerToken: process.env.AIPASS_TOKEN, locale })
  : AIPassClient.fromKeyFile(process.env.AIPASS_KEY_FILE, { locale });

try {
  // 2) Tool calls as your model would emit them (OpenAI sends `arguments` as a JSON string).
  const list = await client.handleToolCall("resources_list", "{}");
  console.log("resources_list →", list.text.slice(0, 300), "\n");
  const resource = list.structuredContent.resources?.find((r) => r.alias === "路亚站测试库");
  if (!resource) {
    console.log("路亚站测试库 not visible to this connection.");
  } else {
    const call = await client.handleToolCall("operations_request", {
      resource_id: resource.resource_id,
      operation: "postgres.query_view",
      parameters: { view: "analytics.subscription_daily", fields: ["day", "plan", "subscriptions"], period_days: 30 },
      idempotency_key: "tool-loop-demo-1",
    });
    // 3) Send this back to the model. `approval_required` is NOT an error: the hint tells the model
    //    to ask the user to approve on their phone and then call operations_status.
    console.log("OpenAI tool message:", JSON.stringify(toOpenAIToolMessage("call_1", call)));
    console.log("Anthropic tool_result:", JSON.stringify(toAnthropicToolResult("toolu_1", call)));
  }
} finally {
  client.close();
}
