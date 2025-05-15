import json
import os

import requests
import tqdm
import yaml

Semgrep_DATASET_DIR = os.path.join("datasets", "Semgrep")

R = requests.get("https://semgrep.dev/api/registry/rules").json()
print(f"{len(R)} Semgrep rules found:")
print(f"- {len([r for r in R if r['visibility'] == 'public'])} Free rules")
print(f"- {len([r for r in R if r['visibility'] == 'team_tier'])} Pro rules")

SEMGREP_TOKEN = os.environ.get("SEMGREP_TOKEN", None)

if not SEMGREP_TOKEN:
    raise Exception("Please provide a Semgrep auth token")

headers = {
    'authorization': f'Bearer {SEMGREP_TOKEN}'
}

dataset_path = os.path.join(Semgrep_DATASET_DIR, "Semgrep_all.json")
if os.path.isfile(dataset_path):
    with open(dataset_path, 'r') as f:
        SEMGREP_RULES = json.load(f)
else:
    SEMGREP_RULES = []

ignored = 0
for r in tqdm.tqdm(R):
    rule_id = r['id']
    if rule_id in [rule['id'] for rule in SEMGREP_RULES]:
        continue
    try:
        rule = requests.get(f"https://semgrep.dev/api/registry/rules/{rule_id}?definition=1&test_cases=1", headers=headers).json()
        SEMGREP_RULES.append(rule)
    except requests.exceptions.ConnectionError:
        ignored += 1

with open(dataset_path, 'w') as f:
    json.dump(SEMGREP_RULES, f)

print(f"{ignored} rule(s) was ignored because of connection error, re-run the script to download missing rules")