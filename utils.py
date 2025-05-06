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
import git
import humanize
import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import requests
import xmltodict
import yaml

# Matplotlib config
matplotlib.use("pgf")
matplotlib.rcParams.update({
    "pgf.texsystem": "pdflatex",
    'font.family': 'serif',
    'font.size' : 11,
    'text.usetex': True,
    'pgf.rcfonts': False,
})

# Replace default print with click.echo
print = click.echo

# Differentiate project directory and this tool directory
WORKING_DIR = os.getcwd()
if sys.path[0]: os.chdir(sys.path[0])

# Display CAT output
def DEBUG():
    return os.environ.get("DEBUG", "0") == "1"

# Import CWE
CWE = {}
for file_path in glob.glob(os.path.join("data", "CWE_*.csv")):
    with open(file_path, mode='r', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            CWE[int(row['CWE-ID'])] = row

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