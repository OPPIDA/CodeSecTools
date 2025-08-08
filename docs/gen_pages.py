from pathlib import Path

import mkdocs_gen_files
import yaml
from jinja2 import Environment, FileSystemLoader

DOCS_DIR = Path("docs")
TEMPLATE_DIR = DOCS_DIR / "templates"
SASTS_DIR = DOCS_DIR / "sasts"
DATASETS_DIR = DOCS_DIR / "datasets"

env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
sasts_template = env.get_template("sasts.md.j2")
datasets_template = env.get_template("datasets.md.j2")

for sast in SASTS_DIR.glob("*.yaml"):
    with mkdocs_gen_files.open(Path("sasts", sast.name), "r") as data_file:  # ty: ignore[unresolved-attribute]
        sast_data = yaml.safe_load(data_file)

    with mkdocs_gen_files.open(Path("sasts", f"{sast.stem}.md"), "w") as md_file:  # ty: ignore[unresolved-attribute]
        md_file.write(sasts_template.render(sast_data))

for dataset in DATASETS_DIR.glob("*.yaml"):
    with mkdocs_gen_files.open(Path("datasets", dataset.name), "r") as data_file:  # ty: ignore[unresolved-attribute]
        dataset_data = yaml.safe_load(data_file)

    with mkdocs_gen_files.open(Path("datasets", f"{dataset.stem}.md"), "w") as md_file:  # ty: ignore[unresolved-attribute]
        md_file.write(datasets_template.render(dataset_data))
