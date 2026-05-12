import os

import openai


def summarize():
    token = os.getenv("SERVICE_TOKEN")
    return openai.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {
                "role": "user",
                "content": token,
            }
        ],
    )
