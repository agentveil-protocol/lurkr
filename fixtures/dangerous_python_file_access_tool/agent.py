from pathlib import Path

from langchain.tools import tool


@tool
def write_report(path):
    Path(path).write_text("report", encoding="utf-8")
    return path
