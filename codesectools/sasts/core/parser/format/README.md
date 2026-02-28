# SAST Tool Analysis Result Formats: Pydantic Model

Generate a Pydantic model for a specific format using [datamodel-code-generator](https://github.com/koxudaxi/datamodel-code-generator).

## SARIF

```bash
datamodel-codegen \
  --url https://raw.githubusercontent.com/microsoft/sarif-python-om/refs/heads/main/sarif-schema-2.1.0.json \
  --output SARIF.py \
  --input-file-type jsonschema \
  --output-model-type pydantic_v2.BaseModel \
  --target-pydantic-version 2.11 \
  --use-root-model-type-alias \
  --use-annotated \
  --snake-case-field \
  --use-schema-description \
  --use-standard-collections \
  --use-union-operator \
  --target-python-version 3.12 \
  --enum-field-as-literal all \
  --custom-file-header '"""Static Analysis Results Interchange Format (SARIF) Version 2.1.0 data model."""'

ruff format SARIF.py
ruff check --unsafe-fixes --fix SARIF.py
ty check SARIF.py
```

## Coverity

```bash
cov-format-errors --dir $PROJECT_DIR --json-output-v10 coverity.json
datamodel-codegen \
  --input coverity.json \
  --output CoverityJsonOutputV10.py \
  --input-file-type json \
  --output-model-type pydantic_v2.BaseModel \
  --target-pydantic-version 2.11 \
  --use-root-model-type-alias \
  --use-annotated \
  --snake-case-field \
  --use-schema-description \
  --use-standard-collections \
  --use-union-operator \
  --target-python-version 3.12 \
  --enum-field-as-literal all \
  --class-name CoverityJsonOutputV10 \
  --custom-file-header '"""Coverity JSON Output V10 model."""'

# Use LLM to refine the model based on https://documentation.blackduck.com/bundle/coverity-docs/page/desktop-analysis/topics/desktop_analysis_json_output_syntax.html

ruff format CoverityJsonOutputV10.py
ruff check --unsafe-fixes --fix CoverityJsonOutputV10.py
ty check CoverityJsonOutputV10.py
```