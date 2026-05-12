from langchain.tools import tool


@tool
def calculate(expression):
    return eval(expression)
