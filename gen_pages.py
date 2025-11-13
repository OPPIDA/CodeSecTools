"""Generate Markdown documentation pages from YAML data files.

This script is intended to be run by the `mkdocs-gen-files` plugin. It
automates the creation of documentation pages for SAST tools and datasets.

The script finds all YAML files in `docs/sast/profiles/` and
`docs/dataset/profiles/`. For each profile file, it reads the YAML data,
renders a Jinja2 template to create a detailed profile page, and writes the
resulting Markdown to the corresponding `supported` subdirectory (e.g.,
`docs/sast/supported/`). It also generates `index.md` summary pages for both
SAST tools and datasets.
"""

from pathlib import Path

import yaml
from jinja2 import Environment, FileSystemLoader
from mkdocs_gen_files import open  # ty: ignore[unresolved-import]

DOCS_DIR = Path("docs")
TEMPLATE_DIR = DOCS_DIR / "templates"
SASTS_DIR = DOCS_DIR / "sast" / "profiles"
DATASETS_DIR = DOCS_DIR / "dataset" / "profiles"

env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
profile_template = env.get_template("profile.md.j2")
profiles_template = env.get_template("profiles.md.j2")

sast_profiles = []
for sast in SASTS_DIR.glob("*.yaml"):
    with open(Path("sast", "profiles", sast.name), "r") as data_file:
        sast_data = yaml.safe_load(data_file)
        sast_data["uri"] = f"{sast.stem}.j2.md"
        sast_profiles.append(sast_data)

    with open(Path("sast", "supported", f"{sast.stem}.j2.md"), "w") as md_file:
        md_file.write(profile_template.render(sast_data))

with open(Path("sast", "supported", "index.md"), "w") as md_file:
    md_file.write(
        profiles_template.render(
            name="SAST tools", profiles=sorted(sast_profiles, key=lambda p: p["name"])
        )
    )

dataset_profiles = []
for dataset in DATASETS_DIR.glob("*.yaml"):
    with open(Path("dataset", "profiles", dataset.name), "r") as data_file:
        dataset_data = yaml.safe_load(data_file)
        dataset_data["uri"] = f"{dataset.stem}.j2.md"
        dataset_profiles.append(dataset_data)

    with open(Path("dataset", "supported", f"{dataset.stem}.j2.md"), "w") as md_file:
        md_file.write(profile_template.render(dataset_data))

with open(Path("dataset", "supported", "index.md"), "w") as md_file:
    md_file.write(
        profiles_template.render(
            name="datasets", profiles=sorted(dataset_profiles, key=lambda p: p["name"])
        )
    )
