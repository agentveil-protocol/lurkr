from __future__ import annotations

from lurkr.scanner import scan_path


RULE_ID = "agent.dynamic_prompt_from_user_input"


def _findings(tmp_path):
    return [finding for finding in scan_path(tmp_path).findings if finding.rule_id == RULE_ID]


def test_placeholder_template_is_clean(tmp_path):
    (tmp_path / "agent.py").write_text(
        "from langchain_core.prompts import ChatPromptTemplate\n\n"
        "def build():\n"
        "    return ChatPromptTemplate.from_template('Summarize: {input}')\n",
        encoding="utf-8",
    )

    assert _findings(tmp_path) == []


def test_f_string_prompt_assignment_from_parameter_fires(tmp_path):
    (tmp_path / "agent.py").write_text(
        "def build(user_input):\n"
        "    prompt = f'Summarize this: {user_input}'\n"
        "    return prompt\n",
        encoding="utf-8",
    )

    findings = _findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].line == 2
    assert "user_input" in findings[0].message


def test_format_prompt_assignment_from_parameter_fires(tmp_path):
    (tmp_path / "agent.py").write_text(
        "def build(question):\n"
        "    system_prompt = 'Answer {}'.format(question)\n"
        "    return system_prompt\n",
        encoding="utf-8",
    )

    assert len(_findings(tmp_path)) == 1


def test_concat_prompt_assignment_from_parameter_fires(tmp_path):
    (tmp_path / "agent.py").write_text(
        "def build(user_text):\n"
        "    instruction = 'Review: ' + user_text\n"
        "    return instruction\n",
        encoding="utf-8",
    )

    assert len(_findings(tmp_path)) == 1


def test_percent_prompt_assignment_from_parameter_fires(tmp_path):
    (tmp_path / "agent.py").write_text(
        "def build(query):\n"
        "    prompt_template = 'Search for %s' % query\n"
        "    return prompt_template\n",
        encoding="utf-8",
    )

    assert len(_findings(tmp_path)) == 1


def test_langchain_dynamic_from_template_fires(tmp_path):
    (tmp_path / "agent.py").write_text(
        "from langchain_core.prompts import ChatPromptTemplate\n\n"
        "def build(topic):\n"
        "    return ChatPromptTemplate.from_template(f'Summarize {topic}')\n",
        encoding="utf-8",
    )

    findings = _findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].line == 4


def test_prompt_template_constructor_dynamic_keyword_fires(tmp_path):
    (tmp_path / "agent.py").write_text(
        "from langchain.prompts import PromptTemplate\n\n"
        "def build(question):\n"
        "    return PromptTemplate(template=f'Answer {question}', input_variables=['question'])\n",
        encoding="utf-8",
    )

    assert len(_findings(tmp_path)) == 1


def test_llm_invoke_prompt_keyword_dynamic_fires(tmp_path):
    (tmp_path / "agent.py").write_text(
        "from langchain_openai import ChatOpenAI\n\n"
        "def ask(user_input):\n"
        "    chat_model = ChatOpenAI()\n"
        "    return chat_model.invoke(prompt=f'Answer {user_input}')\n",
        encoding="utf-8",
    )

    assert len(_findings(tmp_path)) == 1


def test_non_prompt_f_string_logging_is_clean(tmp_path):
    (tmp_path / "agent.py").write_text(
        "import logging\n\n"
        "def handle(user_input):\n"
        "    logging.info(f'User entered {user_input}')\n",
        encoding="utf-8",
    )

    assert _findings(tmp_path) == []


def test_parameter_alias_in_prompt_f_string_fires(tmp_path):
    (tmp_path / "agent.py").write_text(
        "def build(raw_input):\n"
        "    safe_text = raw_input\n"
        "    user_message = f'Classify {safe_text}'\n"
        "    return user_message\n",
        encoding="utf-8",
    )

    findings = _findings(tmp_path)

    assert len(findings) == 1
    assert "raw_input" in findings[0].message


def test_hardcoded_prompt_assignment_is_clean(tmp_path):
    (tmp_path / "agent.py").write_text(
        "def build(user_input):\n"
        "    prompt = 'Summarize the provided document.'\n"
        "    return prompt\n",
        encoding="utf-8",
    )

    assert _findings(tmp_path) == []
