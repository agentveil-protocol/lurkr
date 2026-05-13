# Lurkr Benchmark

This benchmark measures what Lurkr v0.2.2 reports on a pinned public
AI-agent reference corpus and on synthetic known-positive fixtures. It is
intended to make launch claims reproducible and bounded.

The benchmark does not classify public projects as vulnerable. Lurkr reports
repository-visible capability surfaces. A finding means "review this surface in
context", not "this project is exploitable."

## Methodology

The corpus has two tiers:

- **Tier 1: public references.** Twenty public AI-agent repositories selected
  from LangGraph, CrewAI, AG2/AutoGen, OpenAI, Anthropic, Gemini, and MCP
  reference implementations. Each entry is public, permissively licensed
  (MIT or Apache-2.0), has at least 50 stars at curation time, was active in
  the previous 12 months, and is pinned to an exact commit SHA in
  `benchmark/corpus.yaml`.
- **Tier 2: synthetic controls.** Ten adversarial fixtures with expected
  findings across all 14 Lurkr rules, plus five clean controls used for
  false-positive checks.

The runner clones Tier 1 repositories into `/tmp/lurkr-benchmark-clones` and
checks out the pinned commit SHA before scanning. The scan itself runs locally:

```bash
lurkr scan --path <checkout> --output <checkout>/lurkr-report.json
```

No network access is used by `lurkr scan`. Network access is only used by the
benchmark runner before scanning, when it fetches the public GitHub corpus.

Results are written to `benchmark/results.json`. `benchmark/analyze.py` reads
that file and renders a Markdown summary.

## Results: Tier 1 Public References

At the pinned snapshot in `benchmark/corpus.yaml`, Lurkr reported at least one
finding in **15 of 20** public reference repositories (**75.0%**).

Across the Tier 1 corpus, Lurkr reported **665** findings (median **3.5** per
repo, mean **33.25**). The distribution is right-skewed: 5 repos had no
findings, 8 had 1-10, 4 had 11-50, and 3 large framework codebases had more
than 50. Those three repos - `ag2ai/ag2`,
`modelcontextprotocol/python-sdk`, and `openai/openai-agents-python` -
contribute **83.8%** of total findings.

The high counts on framework repos reflect codebase scale. AG2, the MCP Python
SDK, and OpenAI Agents contain many tool implementations; high counts do not
mean those projects are "more vulnerable" than smaller templates. Use median
to estimate what a typical agent template looks like, and mean to estimate the
total review budget across this corpus.

Again, these are not vulnerability claims. They are high-severity capability
surfaces that Lurkr considers worth reviewing before deployment.

| Rule | Repos With Finding | Findings |
|---|---:|---:|
| `agent.credential_to_llm_context` | 2 | 3 |
| `agent.dynamic_prompt_from_user_input` | 9 | 71 |
| `agent.python_api_key_hardcoded` | 1 | 67 |
| `agent.python_tool_without_approval` | 10 | 487 |
| `agent.python_unrestricted_file_access` | 2 | 6 |
| `bypass.direct_github_token` | 5 | 21 |
| `workflow.deploy_without_approval` | 5 | 8 |
| `workflow.pull_request_target_secrets_risk` | 2 | 2 |

### Per-Framework Breakdown

Tier 1 repos grouped by primary framework category:

| Framework | Repos | Median Findings | Range | Total |
|---|---:|---:|---|---:|
| LangChain / LangGraph | 9 | 1 | 0-18 | 30 |
| OpenAI cookbook, agents, swarm | 3 | 20 | 4-101 | 125 |
| MCP Python SDK and servers | 2 | 111.5 | 25-198 | 223 |
| AutoGen / AG2 | 1 | 258 | 258-258 | 258 |
| Anthropic cookbook | 1 | 23 | 23-23 | 23 |
| Google Gemini | 1 | 4 | 4-4 | 4 |
| CrewAI | 1 | 0 | 0-0 | 0 |
| Mixed templates | 2 | 1 | 1-1 | 2 |

The LangChain/LangGraph cluster is the largest ecosystem in the corpus. Most
templates in that group are small, focused agent scaffolds; finding counts are
low and better represent typical user-facing template scale. MCP and AutoGen
rows include framework codebases, so they dominate raw count totals.

### Manual Audit Sample

To make Tier 1 numbers easier to interpret, 30 findings were manually labeled
by reading the underlying source context. The sample uses a deterministic
spread across sorted findings: 10 findings each from the three top-firing
rules, sampled evenly by repo, file, and line.

Labels:

- `real surface`: capability or prompt surface worth review in production.
- `expected example`: technically correct finding in test, notebook, cookbook,
  or demonstration code.
- `noise`: matched pattern is not a meaningful capability surface in context.

| # | Rule | Repo | File:Line | Label | Reason |
|---:|---|---|---|---|---|
| 1 | `agent.python_tool_without_approval` | `NicholasGoh/fastapi-mcp-langgraph-template` | `backend/shared_mcp/tools.py:11` | `real surface` | Template exposes an MCP tool without an approval marker. |
| 2 | `agent.python_tool_without_approval` | `ag2ai/ag2` | `notebook/mcp/math/math_server.py:9` | `expected example` | Notebook math server demonstrates MCP tool registration. |
| 3 | `agent.python_tool_without_approval` | `ag2ai/ag2` | `test/beta/test_watch_advanced.py:39` | `expected example` | Test-only dummy tool registration. |
| 4 | `agent.python_tool_without_approval` | `haris-musa/excel-mcp-server` | `src/excel_mcp/server.py:470` | `real surface` | MCP tool can delete worksheets; review is appropriate. |
| 5 | `agent.python_tool_without_approval` | `modelcontextprotocol/python-sdk` | `examples/servers/everything-server/mcp_everything_server/server.py:156` | `expected example` | SDK example server intentionally exposes sample tools. |
| 6 | `agent.python_tool_without_approval` | `modelcontextprotocol/python-sdk` | `tests/client/test_client.py:139` | `noise` | Expected `Tool(...)` object in a test assertion, not registration. |
| 7 | `agent.python_tool_without_approval` | `modelcontextprotocol/python-sdk` | `tests/server/mcpserver/test_title.py:48` | `expected example` | Test-only decorator used to validate title metadata. |
| 8 | `agent.python_tool_without_approval` | `modelcontextprotocol/python-sdk` | `tests/shared/test_streamable_http.py:1476` | `noise` | Expected `Tool(...)` object in fixture data, not a deployed tool. |
| 9 | `agent.python_tool_without_approval` | `openai/openai-agents-python` | `tests/mcp/test_mcp_util.py:1111` | `noise` | Test verifies approval conversion; no unreviewed runtime surface. |
| 10 | `agent.python_tool_without_approval` | `wassim249/fastapi-langgraph-agent-production-ready-template` | `app/core/langgraph/tools/ask_human.py:11` | `noise` | Human-interrupt helper is itself an approval path. |
| 11 | `agent.python_api_key_hardcoded` | `ag2ai/ag2` | `cli/tests/test_client.py:79` | `expected example` | Test fixture uses fake GitHub token value. |
| 12 | `agent.python_api_key_hardcoded` | `ag2ai/ag2` | `test/oai/test_client.py:645` | `expected example` | Mock OpenAI key used in config tests. |
| 13 | `agent.python_api_key_hardcoded` | `ag2ai/ag2` | `test/oai/test_client.py:1115` | `expected example` | Mock OpenAI key used in config tests. |
| 14 | `agent.python_api_key_hardcoded` | `ag2ai/ag2` | `test/oai/test_utils.py:603` | `expected example` | Fake key validates API-key format logic. |
| 15 | `agent.python_api_key_hardcoded` | `ag2ai/ag2` | `test/oai/test_utils.py:612` | `expected example` | Fake key validates API-key format logic. |
| 16 | `agent.python_api_key_hardcoded` | `ag2ai/ag2` | `test/test_llm_config.py:98` | `expected example` | Mock key asserted in LLM config tests. |
| 17 | `agent.python_api_key_hardcoded` | `ag2ai/ag2` | `test/test_llm_config.py:191` | `expected example` | Mock key used in parameterized config tests. |
| 18 | `agent.python_api_key_hardcoded` | `ag2ai/ag2` | `test/test_llm_config.py:463` | `expected example` | Mock key used in parameterized config tests. |
| 19 | `agent.python_api_key_hardcoded` | `ag2ai/ag2` | `test/test_llm_config.py:819` | `expected example` | Mock key used in config serialization tests. |
| 20 | `agent.python_api_key_hardcoded` | `ag2ai/ag2` | `test/test_logger_redaction.py:19` | `expected example` | Sentinel key exists to test redaction behavior. |
| 21 | `agent.dynamic_prompt_from_user_input` | `ag2ai/ag2` | `autogen/agentchat/contrib/agent_optimizer.py:290` | `real surface` | Runtime optimizer formats conversation history into a prompt. |
| 22 | `agent.dynamic_prompt_from_user_input` | `ag2ai/ag2` | `autogen/agentchat/group/safeguards/enforcer.py:615` | `real surface` | Masking prompt embeds content and category values directly. |
| 23 | `agent.dynamic_prompt_from_user_input` | `ag2ai/ag2` | `autogen/beta/policies/alert.py:85` | `real surface` | Alert messages are interpolated into LLM-visible prompt text. |
| 24 | `agent.dynamic_prompt_from_user_input` | `ag2ai/ag2` | `cli/src/ag2_cli/commands/create.py:449` | `real surface` | User project description is inserted into project-generation prompt. |
| 25 | `agent.dynamic_prompt_from_user_input` | `anthropics/anthropic-cookbook` | `capabilities/retrieval_augmented_generation/evaluation/prompts.py:180` | `expected example` | Cookbook RAG evaluation prompt demonstrates direct interpolation. |
| 26 | `agent.dynamic_prompt_from_user_input` | `anthropics/anthropic-cookbook` | `tool_use/memory_demo/sample_code/sql_query_builder.py:49` | `noise` | SQL query construction, not an LLM prompt surface. |
| 27 | `agent.dynamic_prompt_from_user_input` | `langchain-ai/local-deep-researcher` | `src/ollama_deep_researcher/graph.py:154` | `real surface` | Research topic is formatted into query-generation prompt. |
| 28 | `agent.dynamic_prompt_from_user_input` | `langchain-ai/open_deep_research` | `src/legacy/multi_agent.py:365` | `real surface` | Section and MCP prompt values feed the system prompt. |
| 29 | `agent.dynamic_prompt_from_user_input` | `modelcontextprotocol/python-sdk` | `examples/snippets/servers/sampling.py:10` | `expected example` | SDK snippet demonstrates LLM sampling with a topic prompt. |
| 30 | `agent.dynamic_prompt_from_user_input` | `openai/openai-cookbook` | `examples/partners/temporal_agents_with_knowledge_graphs/db_interface.py:166` | `noise` | SQL table query, not prompt construction. |

Aggregate sample labels:

| Label | Count |
|---|---:|
| `real surface` | 8 |
| `expected example` | 16 |
| `noise` | 6 |

This sample is illustrative, not statistical. It gives readers the texture
behind aggregate counts. For controlled detection checks, use Tier 2 synthetic
fixtures, where each rule has an expected dangerous fixture and matching clean
control.

### Tier 1 Corpus

| Repo | Category | Stars | License | Pinned SHA | Findings |
|---|---|---:|---|---|---:|
| `langchain-ai/react-agent` | langgraph | 730 | MIT | `9f06f66af4da` | 0 |
| `langchain-ai/retrieval-agent-template` | langgraph | 161 | MIT | `d3c39132ef23` | 0 |
| `langchain-ai/data-enrichment` | langgraph | 230 | MIT | `bb6eeb2d384b` | 0 |
| `langchain-ai/open_deep_research` | langgraph | 11375 | MIT | `0dd30bd47ed6` | 18 |
| `langchain-ai/local-deep-researcher` | langgraph | 9143 | MIT | `e1721099870b` | 3 |
| `langchain-ai/langgraph-supervisor-py` | langgraph | 1574 | MIT | `5d341ac33475` | 6 |
| `google-gemini/gemini-fullstack-langgraph-quickstart` | gemini | 18160 | Apache-2.0 | `e34e569de465` | 4 |
| `guy-hartstein/company-research-agent` | langgraph | 1887 | Apache-2.0 | `200383d0e7e0` | 1 |
| `wassim249/fastapi-langgraph-agent-production-ready-template` | langgraph | 2255 | MIT | `d97f375a07f1` | 2 |
| `vstorm-co/full-stack-ai-agent-template` | mixed | 1255 | MIT | `85a0ceb62e00` | 1 |
| `agentailor/fullstack-langgraph-nextjs-agent` | langgraph | 105 | MIT | `815db9ec5b8d` | 0 |
| `NicholasGoh/fastapi-mcp-langgraph-template` | mixed | 544 | MIT | `2bd004a51e5d` | 1 |
| `crewAIInc/crewAI-quickstarts` | crewai | 58 | MIT | `5adaa6223ca4` | 0 |
| `ag2ai/ag2` | autogen | 4536 | Apache-2.0 | `9b40fc1459a6` | 258 |
| `openai/openai-cookbook` | openai | 73473 | MIT | `9e312635c02b` | 20 |
| `openai/openai-agents-python` | openai | 26230 | MIT | `564584513f74` | 101 |
| `openai/swarm` | openai | 21479 | MIT | `6af0b4caf37d` | 4 |
| `anthropics/anthropic-cookbook` | anthropic | 42815 | MIT | `3f8bf356e779` | 23 |
| `modelcontextprotocol/python-sdk` | mcp | 22973 | MIT | `161834d4aee2` | 198 |
| `haris-musa/excel-mcp-server` | mcp | 3815 | MIT | `f51340ecd577` | 25 |

## Results: Tier 2 Synthetic Controls

The synthetic tier is the only tier with explicit expected findings. It is
used to check whether Lurkr detects known-positive cases and whether matching
clean controls stay clean.

Across ten adversarial fixtures, all expected rule classes were detected. The
five clean controls produced no findings.

| Rule | Expected | Observed | TP Rate | Extra Observed |
|---|---:|---:|---:|---:|
| `agent.credential_to_llm_context` | 1 | 1 | 100.0% | 0 |
| `agent.declared_vs_imported_delta` | 3 | 3 | 100.0% | 0 |
| `agent.dynamic_prompt_from_user_input` | 1 | 1 | 100.0% | 0 |
| `agent.python_api_key_hardcoded` | 1 | 1 | 100.0% | 0 |
| `agent.python_eval_exec_in_tool` | 1 | 1 | 100.0% | 0 |
| `agent.python_subprocess_in_tool` | 1 | 1 | 100.0% | 0 |
| `agent.python_tool_without_approval` | 3 | 3 | 100.0% | 0 |
| `agent.python_unrestricted_file_access` | 1 | 1 | 100.0% | 0 |
| `agent.unverified_mcp_endpoint` | 1 | 1 | 100.0% | 0 |
| `bypass.direct_github_token` | 1 | 1 | 100.0% | 0 |
| `identity.private_key_unencrypted` | 1 | 1 | 100.0% | 0 |
| `tool.shell_without_approval` | 1 | 1 | 100.0% | 0 |
| `workflow.deploy_without_approval` | 1 | 1 | 100.0% | 0 |
| `workflow.pull_request_target_secrets_risk` | 1 | 1 | 100.0% | 0 |

Clean-control false-positive rate: **0.0%** (0 of 5 clean controls had any
finding).

## Baseline Comparison

Lurkr v0.2.2 covers 14 high-severity repository-visible capability-risk
classes. These include GitHub workflow risks, manifest risks, identity risks,
Python tool risks, declared-vs-imported capability delta, credential flow into
LLM context, direct prompt interpolation, and external MCP endpoints.

`gitleaks` was not installed on the runner used for this snapshot, so the
baseline was skipped and is recorded as unavailable in `benchmark/results.json`.

When available, `gitleaks` should be interpreted as a complementary baseline,
not a direct competitor. It targets generic secret discovery. Lurkr targets AI
agent capability risk. Teams can run both side by side.

## Honest Gaps

This benchmark does not claim complete AI-agent security coverage. The main
gaps remain visible:

- LLM01 Prompt Injection is only partially covered. Lurkr detects direct
  prompt interpolation setup, not runtime prompt-injection exploitation.
- LLM05 Improper Output Handling is not covered.
- LLM07 System Prompt Leakage is not covered.
- LLM08 Vector and Embedding Weaknesses are not covered.
- Cross-file flow is not modeled.
- Dynamic runtime tool construction is not modeled.
- Closed-source competitors are not compared because their static scanners and
  corpora are not reproducible from this repository.
- Tier 1 findings are not manually classified as true positives or false
  positives. They are capability surfaces requiring review.

## Reproducibility

Re-run the benchmark from the repository root:

```bash
python3 benchmark/run.py
python3 benchmark/analyze.py
```

The public corpus is pinned to exact commit SHAs in `benchmark/corpus.yaml`.
The runner is idempotent: it reuses existing clones under
`/tmp/lurkr-benchmark-clones` when they already match the pinned commit.

Results may change only if:

- `benchmark/corpus.yaml` is edited,
- Lurkr rule logic changes,
- local optional tools such as `gitleaks` become available or unavailable, or
- the benchmark runner itself changes.

The committed snapshot is `benchmark/results.json`.
