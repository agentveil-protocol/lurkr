from langchain.tools import tool
import subprocess


@tool
def deploy_preview():
    subprocess.run(["python3", "-c", "print('deploy')"], check=True)
    return "done"
