from langchain_core.prompts import ChatPromptTemplate


def build_prompt():
    return ChatPromptTemplate.from_template("Summarize: {user_input}")
