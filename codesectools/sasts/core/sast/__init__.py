"""Defines the core abstract class and logic for SAST tool integrations.

This module provides the `SAST` abstract base class, which outlines the
common interface for running a static analysis tool, saving its results, and
performing benchmarks against datasets.
"""

import json
import os
import random
import shutil
import tempfile
import time
from pathlib import Path

import git
from rich import print
from rich.progress import Progress

from codesectools.datasets import DATASETS_ALL
from codesectools.datasets.core.dataset import Dataset, FileDataset, GitRepoDataset
from codesectools.sasts.core.parser import AnalysisResult
from codesectools.sasts.core.sast.properties import SASTProperties
from codesectools.sasts.core.sast.requirements import SASTRequirements
from codesectools.shared.cloc import Cloc
from codesectools.utils import (
    USER_OUTPUT_DIR,
    MissingFile,
    run_command,
)


class SAST:
    """Abstract base class for a SAST tool integration.

    Subclasses of this abstract class must define various class attributes to
    configure the integration with a specific SAST tool.

    Attributes:
        name (str): The name of the SAST tool.
        supported_languages (list[str]): A list of supported programming languages.
        supported_dataset_names (list[str]): Names of compatible datasets.
        supported_datasets (list[Dataset]): A list of supported dataset classes.
        properties (SASTProperties): The properties of the SAST tool.
        requirements (SASTRequirements): The requirements for the SAST tool.
        commands (list[list[str]]): Command-line templates to be executed.
        environ (dict[str, str]): Environment variables to set for commands.
        output_files (list[tuple[Path, bool]]): Expected output files and
            whether they are required.
        parser (type[AnalysisResult]): The parser class for the tool's results.
        color_mapping (dict): A mapping of result categories to colors for plotting.
        install_help (str | None): An optional string with installation help.
        output_dir (Path): (Instance attribute) The base directory for storing
            analysis results.
        status (str): (Instance attribute) The operational status ('full', 'partial',
            or 'none') determined by fulfilled requirements.
        missing (list): (Instance attribute) A list of unfulfilled
            requirements for the tool.

    """

    name: str
    supported_languages: list[str]
    supported_dataset_names: list[str]
    supported_datasets: list[Dataset]
    properties: SASTProperties
    requirements: SASTRequirements
    commands: list[list[str]]
    environ: dict[str, str] = {}
    output_files: list[tuple[Path, bool]]
    parser: AnalysisResult
    color_mapping: dict
    install_help: str | None = None

    def __init__(self) -> None:
        """Initialize the SAST instance.

        Set up the list of supported dataset objects based on the
        `supported_dataset_names` class attribute and define the tool-specific
        output directory.
        """
        self.supported_datasets = [
            DATASETS_ALL[d] for d in self.supported_dataset_names
        ]
        self.output_dir = USER_OUTPUT_DIR / self.name
        self.requirements.name = self.name
        self.status = self.requirements.get_status()
        self.missing = self.requirements.get_missing()

    def render_command(self, command: list[str], map: dict[str, str]) -> list[str]:
        """Render a command template by replacing placeholders with values.

        Args:
            command: The command template as a list of strings.
            map: A dictionary of placeholders to their replacement values.

        Returns:
            The rendered command as a list of strings.

        """
        _command = command.copy()
        for pattern, value in map.items():
            for i, arg in enumerate(_command):
                if pattern in arg:
                    _command[i] = arg.replace(pattern, value)
        return _command

    def run_analysis(self, lang: str, project_dir: Path, output_dir: Path) -> None:
        """Run the SAST analysis on a given project directory.

        Execute the tool's commands, time the analysis, calculate LoC,
        and save the results.

        Args:
            lang: The programming language of the project.
            project_dir: The path to the project's source code.
            output_dir: The path to save the analysis results.

        """
        command_output = ""
        start = time.time()
        for command in self.commands:
            rendered_command = self.render_command(command, {"{lang}": lang})
            retcode, out = run_command(rendered_command, project_dir, self.environ)
            command_output += out
        end = time.time()

        loc = Cloc(project_dir, lang).get_loc()

        extra = {
            "lang": lang,
            "logs": command_output,
            "duration": end - start,
            "loc": loc,
            "project_dir": str(project_dir.resolve()),
        }
        self.save_results(project_dir, output_dir, extra)

    def save_results(self, project_dir: Path, output_dir: Path, extra: dict) -> None:
        """Save the results of a SAST analysis.

        Copy the tool's output files and save any extra metadata to the result directory.

        Args:
            project_dir: The directory where the analysis was run.
            output_dir: The directory where results should be saved.
            extra: A dictionary of extra metadata to save as JSON.

        """
        output_dir.mkdir(exist_ok=True, parents=True)
        json.dump(extra, (output_dir / "cstools_output.json").open("w"))

        missing_files = []
        for path_from_root, required in self.output_files:
            parent_dir = path_from_root.parent
            filename = path_from_root.name
            if "*" not in filename:
                file_path = project_dir / parent_dir / filename
                if file_path.is_file():
                    shutil.copy2(file_path, output_dir / filename)
                else:
                    if required:
                        missing_files.append(filename)
            else:
                file_paths = (project_dir / parent_dir).glob(filename)
                if file_paths:
                    for file_path in file_paths:
                        shutil.copy2(file_path, output_dir / file_path.name)
                else:
                    if required:
                        missing_files.append(filename)

        if missing_files:
            raise MissingFile(missing_files)

        print(f"Results are saved in {output_dir}")

    def analyze_files(
        self, dataset: FileDataset, overwrite: bool = False, testing: bool = False
    ) -> None:
        """Analyze a dataset composed of individual files.

        Set up a temporary directory, save the dataset files, run the analysis,
        and clean up.

        Args:
            dataset: The `FileDataset` instance to analyze.
            overwrite: If True, overwrite existing results for this dataset.
            testing: If True, run analysis on a sample of two random files for testing purposes.

        """
        with Progress() as progress:
            progress.add_task(
                f"[b][{self.name}][/b] analyzing project: [i]{dataset.full_name}[/i]",
                total=None,
            )

            result_path = self.output_dir / dataset.full_name
            result_path.mkdir(exist_ok=True, parents=True)

            if result_path.is_dir():
                if os.listdir(result_path) and not overwrite:
                    print(
                        "Results already exist, please use --overwrite to delete old results"
                    )
                    return

            # Create temporary directory for the project
            temp_dir = tempfile.TemporaryDirectory()
            temp_path = Path(temp_dir.name)

            # Copy files into the temporary directory
            if testing:
                random.seed(os.environ.get("CONSTANT_RANDOM", os.urandom(16)))
                files = random.sample(dataset.files, k=2)
            else:
                files = dataset.files

            for file in files:
                file.save(temp_path)

            # Run analysis
            self.run_analysis(dataset.lang, temp_path, result_path)

            # Clear temporary directory
            temp_dir.cleanup()

    def analyze_repos(
        self, dataset: GitRepoDataset, overwrite: bool = False, testing: bool = False
    ) -> None:
        """Analyze a dataset composed of Git repositories.

        Iterate through each repository in the dataset, clone it, check out
        the specified commit, run the analysis, and save the results.

        Args:
            dataset: The `GitRepoDataset` instance to analyze.
            overwrite: If True, re-analyze repositories with existing results.
            testing: If True, run analysis on a sample of two small random repositories for testing purposes.

        """
        with Progress() as progress:
            progress.add_task(
                f"[b][{self.name}][/b] analyzing dataset: [i]{dataset.full_name}[/i]",
                total=None,
            )

            base_result_path = self.output_dir / dataset.full_name
            base_result_path.mkdir(exist_ok=True, parents=True)

            if testing:
                random.seed(os.environ.get("CONSTANT_RANDOM", os.urandom(16)))
                small_repos = [repo for repo in dataset.repos if repo.size < 1e6]
                repos = random.sample(small_repos, k=2)
            else:
                repos = dataset.repos

            for repo in repos:
                result_path = base_result_path / repo.name
                if result_path.is_dir():
                    if list(result_path.iterdir()) and not overwrite:
                        print(
                            "Results already exist, please use --overwrite to analyze again"
                        )
                        return

                # Create temporary directory for the project
                temp_dir = tempfile.TemporaryDirectory()
                repo_path = Path(temp_dir.name)

                # Clone and checkout to the vulnerable commit
                try:
                    repo.save(repo_path)
                except git.GitCommandError:
                    continue

                # Run analysis
                self.run_analysis(dataset.lang, repo_path, result_path)

                # Clear temporary directory
                temp_dir.cleanup()

    @property
    def supported_dataset_full_names(self) -> list[str]:
        """List all language-specific datasets supported by this SAST tool.

        Returns:
            A list of dataset name strings (e.g., "MyDataset_java").

        """
        datasets_full_name = []
        for dataset in self.supported_datasets:
            for dataset_full_name in dataset.list_dataset_full_names():
                dataset_name, lang = dataset_full_name.split("_")
                if lang in self.supported_languages:
                    datasets_full_name.append(dataset_full_name)
        return datasets_full_name

    def list_results(
        self, project: bool = False, dataset: bool = False, limit: int | None = None
    ) -> list[str]:
        """List the names of available analysis results.

        Args:
            project: If True, include results from local project analyses.
            dataset: If True, include results from dataset benchmarks.
            limit: An optional limit on the number of results to return.

        Returns:
            A sorted list of result directory names.

        """
        output_dirs = []
        if self.output_dir.is_dir():
            for result in self.output_dir.iterdir():
                if result.is_dir():
                    if (
                        any(
                            result.name in d.list_dataset_full_names()
                            for d in self.supported_datasets
                        )
                        and dataset
                    ):
                        output_dirs.append(result.name)
                    elif (
                        not any(
                            result.name in d.list_dataset_full_names()
                            for d in self.supported_datasets
                        )
                        and project
                    ):
                        output_dirs.append(result.name)

        output_dirs = sorted(output_dirs)
        return output_dirs
