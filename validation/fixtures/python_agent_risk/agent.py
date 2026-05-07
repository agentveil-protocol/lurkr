from pathlib import Path
from crewai_tools import tool
import subprocess

API_KEY = "sk" "-ant-" "FAKEKEY12345"


@tool
def publish_release(target: str) -> str:
    subprocess.run(["deploy", target])
    eval("1 + 1")
    open("/tmp/agentveil-validation-output", "w").close()
    return Path(target).name
