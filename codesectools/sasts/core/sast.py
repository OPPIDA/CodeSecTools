"""Defines the core abstract class and logic for SAST tool integrations.

This module provides the `SAST` abstract base class, which outlines the
common interface for running a static analysis tool, saving its results, and
performing benchmarks against datasets.
"""

import json
import os
import shutil
import tempfile
import time
from pathlib import Path

import git
import humanize
import typer

from codesectools.datasets import DATASETS_ALL
from codesectools.datasets.core.dataset import FileDataset, GitRepoDataset
from codesectools.sasts.core.parser import AnalysisResult
from codesectools.shared.cloc import cloc_get_loc
from codesectools.utils import (
    USER_OUTPUT_DIR,
    MissingFile,
    run_command,
)


class SAST:
    """Abstract base class for a SAST tool integration.

    Attributes:
        name (str): The name of the SAST tool.
        supported_languages (list[str]): A list of supported programming languages.
        supported_dataset_names (list[str]): A list of names of compatible datasets.
        commands (list[list[str]]): A list of command-line templates to be executed.
        output_files (list[tuple[Path, bool]]): A list of expected output files and
            whether they are required.
        parser (type[AnalysisResult]): The parser class for the tool's results.
        color_mapping (dict): A mapping of result categories to colors for plotting.
        supported_datasets (list): Initialized in the constructor; a list of supported
            dataset classes based on `supported_dataset_names`.
        output_dir (Path): The base directory for storing analysis results, initialized
            in the constructor.

    """

    name: str
    supported_languages: list[str]
    supported_dataset_names: list[str]
    commands: list[list[str]]
    output_files: list[tuple[Path, bool]]
    parser: AnalysisResult
    color_mapping: dict

    def __init__(self) -> None:
        """Initialize the SAST instance.

        Sets up the list of supported dataset objects, defines the output directory,
        and verifies that the required command-line tools are available.

        Raises:
            MissingFile: If a required command-line tool is not found in the system's PATH.

        """
        self.supported_datasets = [
            DATASETS_ALL[d] for d in self.supported_dataset_names
        ]
        self.output_dir = USER_OUTPUT_DIR / self.name
        self.check_commands()

    def check_commands(self) -> None | MissingFile:
        """Check if the necessary command-line binaries for the tool are available.

        Raises:
            MissingFile: If a required command-line tool is not found in the system's PATH.

        """
        for command in self.commands:
            binary = command[0]
            if not shutil.which(binary):
                raise MissingFile([binary])

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

        Executes the tool's commands, times the analysis, calculates LoC,
        and saves the results.

        Args:
            lang: The programming language of the project.
            project_dir: The path to the project's source code.
            output_dir: The path to save the analysis results.

        """
        command_output = ""
        start = time.time()
        for command in self.commands:
            rendered_command = self.render_command(command, {"{lang}": lang})
            retcode, out = run_command(rendered_command, project_dir)
            command_output += out
        end = time.time()

        loc = cloc_get_loc(project_dir, lang)

        extra = {"logs": command_output, "duration": end - start, "loc": loc}
        self.save_results(project_dir, output_dir, extra)

    def save_results(self, project_dir: Path, output_dir: Path, extra: dict) -> None:
        """Save the results of a SAST analysis.

        Copies the tool's output files and saves any extra metadata to the result directory.

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

        typer.echo(f"Results are saved in {output_dir}")

    def analyze_files(self, dataset: FileDataset, overwrite: bool = False) -> None:
        """Analyze a dataset composed of individual files.

        Sets up a temporary directory, saves the dataset files, runs the analysis,
        and cleans up.

        Args:
            dataset: The `FileDataset` instance to analyze.
            overwrite: If True, overwrite existing results for this dataset.

        """
        result_path = self.output_dir / dataset.full_name
        result_path.mkdir(exist_ok=True, parents=True)

        if result_path.is_dir():
            if os.listdir(result_path) and not overwrite:
                typer.echo(
                    "Results already exist, please use --overwrite to delete old results"
                )
                return

        # Create temporary directory for the project
        temp_dir = tempfile.TemporaryDirectory()
        temp_path = Path(temp_dir.name)

        # Copy files into the temporary directory
        for file in dataset.files:
            file.save(temp_path)

        # Run analysis
        self.run_analysis(dataset.lang, temp_path, result_path)

        # Clear temporary directory
        temp_dir.cleanup()

    def analyze_repos(self, dataset: GitRepoDataset, overwrite: bool = False) -> None:
        """Analyze a dataset composed of Git repositories.

        Iterates through each repository in the dataset, clones it, checks out
        the specified commit, runs the analysis, and saves the results.

        Args:
            dataset: The `GitRepoDataset` instance to analyze.
            overwrite: If True, re-analyze repositories with existing results.

        """
        base_result_path = self.output_dir / dataset.full_name
        base_result_path.mkdir(exist_ok=True, parents=True)
        typer.echo(
            f"Max repo size for analysis: {humanize.naturalsize(dataset.max_repo_size)}"
        )

        for repo in dataset.repos:
            typer.echo("=================================")
            typer.echo(repo)

            result_path = base_result_path / repo.name
            if result_path.is_dir():
                if list(result_path.iterdir()) and not overwrite:
                    typer.echo(
                        "Results already exist, please use --overwrite to analyze again"
                    )

            # Create temporary directory for the project
            temp_dir = tempfile.TemporaryDirectory()
            repo_path = Path(temp_dir.name)

            # Clone and checkout to the vulnerable commit
            try:
                repo.save(repo_path)
            except git.GitCommandError as e:
                typer.echo(e)
                typer.echo("Skipping")
                continue

            # Run analysis
            self.run_analysis(dataset.lang, repo_path, result_path)

            # Clear temporary directory
            temp_dir.cleanup()

    def list_supported_datasets(self) -> list[str]:
        """List all language-specific datasets supported by this SAST tool.

        Returns:
            A list of dataset name strings (e.g., "MyDataset_java").

        """
        all_datasets = []
        for dataset in self.supported_datasets:
            all_datasets.extend(dataset.list_dataset())
        return all_datasets

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
            for child in os.listdir(self.output_dir):
                child_path = self.output_dir / child
                if child_path.is_dir():
                    if (
                        any(child in d.list_dataset() for d in self.supported_datasets)
                        and dataset
                    ):
                        output_dirs.append(child)
                    elif (
                        not any(
                            child in d.list_dataset() for d in self.supported_datasets
                        )
                        and project
                    ):
                        output_dirs.append(child)

        output_dirs = sorted(output_dirs)
        return output_dirs
