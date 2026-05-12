from langchain.tools import Tool


def search(query: str) -> str:
    return query


def export_records() -> str:
    return "exported"


tools = [
    Tool(
        name="search",
        func=search,
        description="Search notes",
        require_human_approval=True,
    ),
    Tool(
        name="export_records",
        func=export_records,
        description="Export records",
        require_human_approval=True,
    ),
]
