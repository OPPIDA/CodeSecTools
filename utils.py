import csv
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import xml
from datetime import timedelta

import click
import humanize
import requests
import xmltodict
import yaml
import humanize
from git import Repo

# Differentiate project directory and this tool directory
WORKING_DIR = os.getcwd()
if sys.path[0]: os.chdir(sys.path[0])

# Display CAT output
def DEBUG():
    return os.environ.get("DEBUG", "0") == "1"

# Subprocess wrapper
def run_command(command: str, cwd):
    process = subprocess.Popen(
        command.split(" "),
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    stdout = ""

    for line in process.stdout:
        stdout += line
        if DEBUG():
            print(line, end='')

    return stdout