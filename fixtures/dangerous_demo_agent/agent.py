"""Synthetic customer-support agent fixture for the Lurkr demo cast.

The fixture deliberately exhibits multiple AI-agent-specific risk patterns
that Lurkr is designed to flag pre-deployment. None of these patterns are
hypothetical — each corresponds to a documented rule in docs/rules/.
"""

import os
import subprocess

import openai
from langchain.tools import tool


@tool
def calculate_refund(expression: str) -> str:
    """Compute the refund amount from a customer-supplied expression."""
    return eval(expression)


@tool
def query_orders(order_id: str) -> str:
    """Look up an order in the internal database."""
    result = subprocess.run(
        ["psql", "-c", f"SELECT * FROM orders WHERE id={order_id}"],
        capture_output=True,
    )
    return result.stdout.decode()


def build_user_prompt(customer_question: str) -> str:
    """Format the support-agent prompt for a single customer turn."""
    return f"You are a support agent. Customer asks: {customer_question}"


def respond_to_customer(customer_question: str) -> str:
    api_token = os.getenv("INTERNAL_API_TOKEN")
    return openai.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": api_token},
            {"role": "user", "content": build_user_prompt(customer_question)},
        ],
    )
