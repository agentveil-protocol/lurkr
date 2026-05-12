from __future__ import annotations

from lurkr.scanner import scan_path


RULE_ID = "agent.credential_to_llm_context"


def _findings(tmp_path):
    return [finding for finding in scan_path(tmp_path).findings if finding.rule_id == RULE_ID]


def test_credential_in_http_headers_is_out_of_scope(tmp_path):
    (tmp_path / "agent.py").write_text(
        "import os\n"
        "import requests\n\n"
        "def call_api():\n"
        "    token = os.getenv('API_TOKEN')\n"
        "    return requests.get('https://example.com', headers={'Authorization': token})\n",
        encoding="utf-8",
    )

    assert _findings(tmp_path) == []


def test_env_credential_in_openai_messages_fires(tmp_path):
    (tmp_path / "agent.py").write_text(
        "import os\n"
        "import openai\n\n"
        "def ask():\n"
        "    token = os.getenv('OPENAI_API_KEY')\n"
        "    return openai.chat.completions.create(\n"
        "        model='gpt-4o-mini',\n"
        "        messages=[{'role': 'user', 'content': token}],\n"
        "    )\n",
        encoding="utf-8",
    )

    findings = _findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].line == 6
    assert "token" in findings[0].message


def test_named_credential_variable_in_anthropic_messages_fires(tmp_path):
    (tmp_path / "agent.py").write_text(
        "def ask(client, user_token):\n"
        "    return client.messages.create(\n"
        "        model='claude-3-5-sonnet-latest',\n"
        "        messages=[{'role': 'user', 'content': user_token}],\n"
        "    )\n",
        encoding="utf-8",
    )

    findings = _findings(tmp_path)

    assert len(findings) == 1
    assert "user_token" in findings[0].message


def test_hardcoded_key_variable_in_message_fires_on_flow_not_literal(tmp_path):
    (tmp_path / "agent.py").write_text(
        "import openai\n\n"
        "def ask():\n"
        "    api_key = 'sk-1234567890abcdef'\n"
        "    return openai.chat.completions.create(messages=[{'role': 'user', 'content': api_key}])\n",
        encoding="utf-8",
    )

    findings = _findings(tmp_path)

    assert len(findings) == 1
    assert "api_key" in findings[0].message


def test_gemini_generate_content_with_credential_fires(tmp_path):
    (tmp_path / "agent.py").write_text(
        "def ask(model, auth_header):\n"
        "    return model.generate_content(['summarize', auth_header])\n",
        encoding="utf-8",
    )

    findings = _findings(tmp_path)

    assert len(findings) == 1
    assert "auth_header" in findings[0].message


def test_langchain_invoke_model_variable_with_credential_fires(tmp_path):
    (tmp_path / "agent.py").write_text(
        "from langchain_openai import ChatOpenAI\n\n"
        "def ask(secret):\n"
        "    chat_model = ChatOpenAI()\n"
        "    return chat_model.invoke(secret)\n",
        encoding="utf-8",
    )

    findings = _findings(tmp_path)

    assert len(findings) == 1
    assert "secret" in findings[0].message


def test_direct_chat_model_invoke_with_credential_fires(tmp_path):
    (tmp_path / "agent.py").write_text(
        "from langchain_openai import ChatOpenAI\n\n"
        "def ask(password):\n"
        "    return ChatOpenAI().invoke(password)\n",
        encoding="utf-8",
    )

    findings = _findings(tmp_path)

    assert len(findings) == 1
    assert "password" in findings[0].message


def test_f_string_interpolation_of_credential_into_message_fires(tmp_path):
    (tmp_path / "agent.py").write_text(
        "import os\n"
        "import openai\n\n"
        "def ask():\n"
        "    token = os.environ.get('SERVICE_TOKEN')\n"
        "    return openai.chat.completions.create(messages=[{'role': 'user', 'content': f'use {token}'}])\n",
        encoding="utf-8",
    )

    findings = _findings(tmp_path)

    assert len(findings) == 1
    assert "token" in findings[0].message


def test_derived_message_variable_from_credential_fires(tmp_path):
    (tmp_path / "agent.py").write_text(
        "import os\n"
        "import openai\n\n"
        "def ask():\n"
        "    token = os.getenv('SERVICE_TOKEN')\n"
        "    message = f'use {token}'\n"
        "    return openai.chat.completions.create(messages=[{'role': 'user', 'content': message}])\n",
        encoding="utf-8",
    )

    findings = _findings(tmp_path)

    assert len(findings) == 1
    assert "token" in findings[0].message


def test_non_credential_message_variable_does_not_fire(tmp_path):
    (tmp_path / "agent.py").write_text(
        "import openai\n\n"
        "def ask():\n"
        "    message = 'hello'\n"
        "    return openai.chat.completions.create(messages=[{'role': 'user', 'content': message}])\n",
        encoding="utf-8",
    )

    assert _findings(tmp_path) == []
