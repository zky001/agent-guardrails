# agent-guardrails

LLM Agent 运行时安全围栏模块：以声明式策略驱动的工具调用管控、运行预算、人工审批与全程审计。

Runtime guardrails for LLM agents: a policy-driven tool-call firewall with budgets, human-approval gates, and a JSONL audit trail. Pure Python, zero required dependencies (`pyyaml` only if you use YAML policies).

## 它拦在哪里

Agent 的一次运行有五个可拦截面，本模块全部覆盖，核心是工具调用面：

```
用户输入 ──▶ [INPUT 围栏] ──▶ LLM ──▶ 工具调用 ──▶ [TOOL_CALL 围栏] ──▶ 工具执行
  注入/越狱检测                          │  白名单/参数校验/预算/审批        │
                                        │                                  ▼
最终回复 ◀── [OUTPUT 围栏] ◀── LLM ◀── [TOOL_RESULT 围栏] ◀────── 工具返回
              PII脱敏/敏感拦截            返回内容注入扫描(不可信输入)
```

- **TOOL_CALL**：工具白名单/黑名单（fnmatch 通配）、按参数的细粒度规则（正则必须/禁止、URL 域名白名单、长度上限）、高危工具人工审批、单次运行调用预算。
- **INPUT / TOOL_RESULT**：启发式提示注入检测（中英文模式 + 零宽字符 + 自定义正则），`deny` 或 `flag` 两种模式。
- **OUTPUT**：PII 脱敏（邮箱/手机号/身份证/卡号）与敏感模式硬拦截（如密钥格式）。
- **全程**：每个最终决策写入 JSONL 审计日志（含放行），支持内存尾部查询用于面板展示。

## 快速开始

```bash
pip install -e ".[yaml]"
python examples/demo.py        # 无需 LLM/网络，纯围栏行为演示
```

```python
from agent_guardrails import GuardrailEngine, MemoryApprovalGate, RunContext

gate = MemoryApprovalGate()
engine = GuardrailEngine.from_policy_file("examples/policy.yaml", approval_gate=gate)
ctx = RunContext(run_id="run-42", tenant_id="acme")

# 方式一：包装你的工具分发函数（推荐，一行接入）
guarded = engine.wrap(my_dispatch, ctx)      # my_dispatch(name, args) -> result
result = guarded("exec_sql_0", {"sql": "SELECT 1"})
# 违规时抛 GuardrailDenied；高危工具抛 ApprovalRequired（携带 approval_id）

# 方式二：逐面手动检查
engine.check_input(user_message, ctx)
engine.check_tool_call(call, ctx)
engine.check_tool_result(call, result_text, ctx)
engine.check_output(final_text, ctx)

engine.reset_run(ctx.run_id)                 # 运行结束释放预算/审批状态
```

## 决策模型

每次检查返回一个 `Verdict`，动作为四种之一：

| 动作 | 含义 |
|---|---|
| `allow` | 放行（可携带 `flags` 标记，如 tool_result 命中注入模式但策略为 flag） |
| `deny` | 拦截，`reason` 说明命中的规则 |
| `rewrite` | 改写后放行（如 OUTPUT 的 PII 脱敏、定制 checker 改写参数） |
| `require_approval` | 挂起等待人工审批，`approval_id` 标识请求 |

`fail_mode` 决定检查器自身异常时的行为：`closed`（默认，熔断拦截）或 `open`（放行并记录）。金融/高危场景保持 `closed`。

## 审批流

`require_approval` 的工具调用按 `(run_id, tool, args)` 指纹幂等登记，人工（或外部系统轮询 `gate.pending()`）调用 `gate.resolve(approval_id, True/False)` 后，**重放同一调用**即通过/拒绝——天然适配支持中断/恢复的 agent 运行时。已有审批 UI 的宿主可用 `CallbackApprovalGate` 同步决策。

## 策略文件

完整注释示例见 [`examples/policy.yaml`](examples/policy.yaml)。要点：

```yaml
fail_mode: closed
tools:
  default: deny                  # 客户交付建议白名单制
  allow: ["retrieval*", "web_search*"]
  deny: ["shell*"]               # 优先级最高
  rules:
    - tool: "exec_sql*"
      args:
        sql: {must_match: "(?i)^\\s*select\\b", deny_match: "(?i)\\b(drop|delete)\\b"}
    - tool: "crawler*"
      args: {url: {allowed_domains: ["arxiv.org"]}}
    - tool: "email*"
      action: require_approval
budgets:
  max_tool_calls_per_run: 20
  max_calls_per_tool: {web_search_0: 5}
input:        {injection_detection: true, mode: deny}
tool_result:  {injection_detection: true, mode: flag}
output:       {pii_redaction: true, deny_match: ["sk-[A-Za-z0-9]{20,}"]}
audit:        {path: guardrail_audit.jsonl}
```

正则在加载时编译，坏策略在启动时报错而不是运行中。工具名用 fnmatch 匹配，可覆盖运行时的带索引注册名（如 RAGFlow 的 `web_search_0`）。

## 审计日志

JSONL，一行一个最终决策：

```json
{"ts": "2026-08-13T00:31:51.932+00:00", "run_id": "demo-run", "tenant_id": "acme",
 "stage": "tool_call", "tool": "email_0", "args": {"to": "a@b.com"},
 "action": "allow", "checker": "approval", "reason": "approved by reviewer (id=4fac4c26)"}
```

超长字段自动截断；`engine.audit.recent(n)` 取内存尾部用于面板/接口展示。

## 集成

任何"有一个按名字分发工具调用的函数"的运行时都能一行接入 `engine.wrap`。以 RAGFlow 为例，Python 侧所有工具（含 MCP）收敛于 `LLMToolPluginCallSession` 统一分发，在该分发点外包一层 `wrap` 即覆盖全部工具调用；Go 侧（eino ReAct 循环）等价做法是在工具节点外加 middleware，本仓库的策略文件与审计格式可直接复用。OpenAI 式工具循环同理：执行 `tool_calls` 前过 `check_tool_call`，结果入上下文前过 `check_tool_result`。

## 定制检查器

```python
from agent_guardrails import Checker, Stage, Verdict

class MyChecker(Checker):
    name = "my_checker"
    stages = (Stage.TOOL_CALL,)
    def check(self, req, engine):
        ...  # 返回 None(无意见) 或 Verdict
engine.register(MyChecker())
```

内置启发式（注入正则、PII 正则）定位为第一道防线；接入模型型检测器（分类器/LLM judge）就是实现一个 `Checker` 的事。

## Roadmap

- 模型型注入/内容检测器接入示例（本地小分类模型、外部 API 两档）
- 审批网关的持久化实现（数据库/消息队列）与 Webhook 通知
- Go 版引擎（对齐同一策略文件格式）
- 策略热更新与按租户分发

## 开发

```bash
uv venv && uv pip install -e ".[dev]"
.venv/bin/pytest -q        # 44 tests
```
