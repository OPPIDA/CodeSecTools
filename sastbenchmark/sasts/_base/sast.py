import glob
import json
import os
import shutil
import tempfile
import time
from pathlib import Path

import click
import git
import humanize

from sastbenchmark.datasets import DATASETS_ALL
from sastbenchmark.datasets._base.dataset import Dataset, FileDataset, GitRepoDataset
from sastbenchmark.sasts._base.parser import AnalysisResult
from sastbenchmark.utils import (
    OUTPUT_DIR,
    PACKAGE_DIR,
    MissingFile,
    NonZeroExit,
    get_loc,
    run_command,
)

SASTS_DIR = PACKAGE_DIR / "sasts"
RESULTS_DIR = OUTPUT_DIR / "results"


class SAST:
    name = ""

    def __init__(
        self,
        commands: list[list[str]],
        analysis_files: list[tuple[str, bool]],
        parser: AnalysisResult,
        supported_languages: list[str],
        supported_datasets: list[type[Dataset]],
        color_mapping: dict,
    ) -> None:
        """analysis_files: (file_path_from_project_root, required)"""
        self.commands = commands
        self.analysis_files = analysis_files
        self.parser = parser
        self.directory = os.path.join(SASTS_DIR, self.name)
        self.result_dir = os.path.join(RESULTS_DIR, self.name)
        self.supported_languages = supported_languages
        self.supported_datasets = [DATASETS_ALL[d] for d in supported_datasets]
        self.color_mapping = color_mapping

    def check_commands(self) -> list:
        missing = []
        for command in self.commands:
            binary = command[0]
            if not shutil.which(binary):
                missing.append(binary)

        return missing

    def render_command(self, command: list[str], map: dict[str, str]) -> list[str]:
        _command = command.copy()
        for pattern, value in map.items():
            for i, arg in enumerate(_command):
                if pattern in arg:
                    _command[i] = arg.replace(pattern, value)
        return _command

    def run_analysis(self, lang: str, project_dir: Path, result_dir: str) -> None:
        if missing := self.check_commands():
            raise MissingFile(missing)

        command_output = ""
        start = time.time()
        for command in self.commands:
            rendered_command = self.render_command(command, {"{lang}": lang})
            retcode, out = run_command(rendered_command, project_dir)
            command_output += out
            if retcode != 0:
                raise NonZeroExit(rendered_command, command_output)
        end = time.time()

        loc = get_loc(project_dir, lang)

        extra = {"logs": command_output, "duration": end - start, "loc": loc}
        self.save_results(project_dir, result_dir, extra)

    def save_results(self, project_dir: str, result_dir: str, extra: dict) -> None:
        os.makedirs(result_dir, exist_ok=True)

        with open(os.path.join(result_dir, "sastb_cmdout.json"), "w") as f:
            json.dump(extra, f)

        missing_files = []
        for path_from_root, required in self.analysis_files:
            parent_dir, filename = os.path.split(path_from_root)
            if "*" not in filename:
                file_path = os.path.join(project_dir, parent_dir, filename)
                if os.path.isfile(file_path):
                    shutil.copy2(file_path, os.path.join(result_dir, filename))
                else:
                    if required:
                        missing_files.append(filename)
            else:
                file_paths = glob.glob(os.path.join(project_dir, parent_dir, filename))
                if file_paths:
                    for file_path in file_paths:
                        basename = os.path.basename(file_path)
                        shutil.copy2(file_path, os.path.join(result_dir, basename))
                else:
                    if required:
                        missing_files.append(filename)

        click.echo(f"Results are saved in {result_dir}")

    def analyze_files(self, dataset: FileDataset, overwrite: bool = False) -> None:
        result_path = os.path.join(self.result_dir, dataset.full_name)
        os.makedirs(result_path, exist_ok=True)

        if os.path.isdir(result_path):
            if os.listdir(result_path) and not overwrite:
                click.echo(
                    "Results already exist, please use --overwrite to delete old results"
                )
                return

        # Create temporary directory for the project
        temp_dir = tempfile.TemporaryDirectory()
        temp_path = temp_dir.name

        # Copy files into the temporary directory
        for file in dataset.files:
            file.save(temp_path)

        # Run analysis
        self.run_analysis(dataset.lang, temp_path, result_path)

        # Clear temporary directory
        temp_dir.cleanup()

    def analyze_repos(self, dataset: GitRepoDataset, overwrite: bool = False) -> None:
        base_result_path = os.path.join(self.result_dir, dataset.full_name)
        os.makedirs(base_result_path, exist_ok=True)
        click.echo(
            f"Max repo size for analysis: {humanize.naturalsize(dataset.max_repo_size)}"
        )

        for repo in dataset.repos:
            click.echo("=================================")
            click.echo(repo)

            result_path = os.path.join(base_result_path, repo.name)
            if os.path.isdir(result_path):
                if os.listdir(result_path) and not overwrite:
                    click.echo(
                        "Results already exist, please use --overwrite to delete old results"
                    )
                    return

            # Create temporary directory for the project
            temp_dir = tempfile.TemporaryDirectory()
            repo_path = temp_dir.name

            # Clone and checkout to the vulnerable commit
            try:
                repo.save(repo_path)
            except git.GitCommandError as e:
                click.echo(e, err=True)
                click.echo("Skipping")
                continue

            # Run analysis
            self.run_analysis(dataset.lang, repo_path, result_path)

            # Clear temporary directory
            temp_dir.cleanup()

    def list_supported_datasets(self) -> list[str]:
        all_datasets = []
        for dataset in self.supported_datasets:
            all_datasets.extend(dataset.list_dataset())
        return all_datasets

    def list_results(
        self, project: bool = False, dataset: bool = False, limit: int | None = None
    ) -> list[str]:
        # TODO: limit
        result_dirs = []
        if os.path.isdir(self.result_dir):
            for child in os.listdir(self.result_dir):
                child_path = os.path.join(self.result_dir, child)
                if os.path.isdir(child_path):
                    if (
                        any(child in d.list_dataset() for d in self.supported_datasets)
                        and dataset
                    ):
                        result_dirs.append(child)
                    elif (
                        not any(
                            child in d.list_dataset() for d in self.supported_datasets
                        )
                        and project
                    ):
                        result_dirs.append(child)

        result_dirs = sorted(result_dirs)
        return result_dirs
