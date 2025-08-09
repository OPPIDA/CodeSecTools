from pathlib import Path

import yaml
from jinja2 import Environment, FileSystemLoader
from mkdocs_gen_files import open  # ty: ignore[unresolved-import]

DOCS_DIR = Path("docs")
TEMPLATE_DIR = DOCS_DIR / "templates"
SASTS_DIR = DOCS_DIR / "sasts" / "data"
DATASETS_DIR = DOCS_DIR / "datasets" / "data"

env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
sasts_template = env.get_template("sasts.md.j2")
datasets_template = env.get_template("datasets.md.j2")

for sast in SASTS_DIR.glob("*.yaml"):
    with open(Path("sasts", "data", sast.name), "r") as data_file:
        sast_data = yaml.safe_load(data_file)

    with open(Path("sasts", "data", f"{sast.stem}.md"), "w") as md_file:
        md_file.write(sasts_template.render(sast_data))

for dataset in DATASETS_DIR.glob("*.yaml"):
    with open(Path("datasets", "data", dataset.name), "r") as data_file:
        dataset_data = yaml.safe_load(data_file)

    with open(Path("datasets", "data", f"{dataset.stem}.md"), "w") as md_file:
        md_file.write(datasets_template.render(dataset_data))
