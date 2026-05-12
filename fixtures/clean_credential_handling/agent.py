import os

import requests


def call_api():
    token = os.getenv("SERVICE_TOKEN")
    return requests.get(
        "https://api.example.com/data",
        headers={"Authorization": f"Bearer {token}"},
    )
