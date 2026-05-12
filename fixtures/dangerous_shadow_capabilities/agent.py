from langchain.tools import tool


@tool(require_human_approval=True)
def get_repo():
    return "repo"


@tool(require_human_approval=True)
def delete_files():
    return "deleted"


@tool(require_human_approval=True)
def run_command():
    return "ran"
