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

SEMGREP_TOKEN = os.environ.get("SEMGREP_TOKEN", None) or "eyJhbGciOiJIUzI1NiIsImtpZCI6IjljZGQzMGM3NTA0ODc1ODJlMDZjNGMyNWMwN2VhNmU3YWY0NjQyYjcwODcyNTI3OGRlYmE3NTk1MjQ2YWMzMGIiLCJ0eXAiOiJKV1QifQ.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTc0NzEzOTQ3MCwianRpIjoiMjcyNDU0MTYtY2E5Yi00MzY5LTg5ZjYtZGExZGRjNmZhZDVhIiwidHlwZSI6ImFjY2VzcyIsImlkZW50aXR5Ijp7ImF1dGhfcHJvdmlkZXJfdHlwZSI6ImdpdGh1YiIsImF1dGhfdXJsIjoiaHR0cHM6Ly9naXRodWIuY29tL2xvZ2luL29hdXRoIiwidXNlcl9pZCI6NzI2NjksInVzZXJuYW1lIjoibm9sbGl2MjIiLCJ1c2VyX2NyZWF0ZWRfYXQiOiJUdWUsIDEzIE1heSAyMDI1IDEyOjMxOjAyIEdNVCIsImVtYWlsIjoidmlsbG9uMmNoZW5AZ21haWwuY29tIiwib3JncyI6W3siaWQiOjQ3OTY5LCJuYW1lIjoidmlsbG9uMmNoZW4tcGVyc29uYWwtb3JnIiwiZGlzcGxheV9uYW1lIjoidmlsbG9uMmNoZW4tcGVyc29uYWwtb3JnIiwic2x1ZyI6InZpbGxvbjJjaGVuX3BlcnNvbmFsX29yZyIsInNvdXJjZV90eXBlIjoic2ltcGxlIiwiaGFzX2F1dG9maXgiOmZhbHNlLCJoYXNfZGVlcHNlbWdyZXAiOmZhbHNlLCJoYXNfdHJpYWdlX3ZpYV9jb21tZW50Ijp0cnVlLCJoYXNfZGVwZW5kZW5jeV9xdWVyeSI6dHJ1ZSwiZGVmYXVsdF91c2VyX3JvbGUiOiJhZG1pbiIsIm9yZ2FuaXphdGlvbl9pZCI6MTI5Njk0LCJzY21fbmFtZSI6InZpbGxvbjJjaGVuLXBlcnNvbmFsLW9yZyJ9XSwiZmxhZ3MiOnsiZmluZGluZ3NfdG91cl9zdGF0ZSI6MSwic3VwcGx5X2NoYWluX3RvdXJfc3RhdGUiOjEsInN1cHBseV9jaGFpbl9maW5kaW5nc190b3VyX3N0YXRlIjoxfSwicm9sZXMiOnt9LCJ0ZW5hbnQiOiJkZWZhdWx0IiwiYXZhaWxhYmxlX2VtYWlscyI6W3siZW1haWwiOiJ2aWxsb24yY2hlbkBnbWFpbC5jb20iLCJwcmltYXJ5Ijp0cnVlLCJ2ZXJpZmllZCI6ZmFsc2V9XSwicHJvZmlsZV9waG90byI6bnVsbH0sIm5iZiI6MTc0NzEzOTQ3MCwiaXNzIjoiYmFja2VuZEBkZWZhdWx0IiwiZXhwIjoxNzQ3NzQ0MjcwfQ._XmyLODSuxASvHZxyO2jIc4t49GkSvwhgQg-7cWwBtI"

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