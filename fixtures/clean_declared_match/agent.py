from langchain.tools import tool


@tool(require_human_approval=True)
def get_repo():
    return "repo"


@tool(require_human_approval=True)
def list_files():
    return ["README.md"]
