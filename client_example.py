from openai import OpenAI
import os
from pathlib import Path

from source import serialize_project

os.environ['OPENAI_API_KEY'] = 'PASTE_YOUR_API_KEY_HERE'

project = Path("vul4py/workspaces/CVE-2021-32839/vulnerable")
vulnerable_source = serialize_project(project)

client = OpenAI(max_retries=0)

completion = client.chat.completions.create(
    model="gpt-6-luna",
    messages=[
        {
            "role": "system",
            "content": "You are a security expert and a python programmer. I will provide you with a vulnerable Python project, and you will respond with a json file that includes the diff file, your claim if the code was patched (1) or not (0), and the confidence level of your claim (0-1). You don't have access to the interner nor external tools."
        },
        {
            "role": "user",
            "content": vulnerable_source
        }
    ]
)

print(completion.choices[0].message)
