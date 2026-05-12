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

Across the Tier 1 corpus, Lurkr reported **665** findings, averaging **33.25**
findings per repository.

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
