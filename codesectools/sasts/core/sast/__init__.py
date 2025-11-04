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
from abc import ABC
from pathlib import Path
from typing import Any, Literal, Union

import git
from rich import print
from rich.panel import Panel
from rich.progress import Progress

from codesectools.datasets import DATASETS_ALL
from codesectools.datasets.core.dataset import (
    Dataset,
    FileDataset,
    GitRepoDataset,
    PrebuiltFileDataset,
)
from codesectools.sasts.core.parser import AnalysisResult
from codesectools.sasts.core.sast.properties import SASTProperties
from codesectools.sasts.core.sast.requirements import SASTRequirements
from codesectools.shared.cloc import Cloc
from codesectools.utils import (
    USER_OUTPUT_DIR,
    MissingFile,
    NonZeroExit,
    run_command,
)


class SAST(ABC):
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
        commands (list[list[Union[str, tuple[str]]]]): The list of commands templates to be rendred and executed.
        valid_codes (list[int]): A list of exit codes indicating that the command did not fail.
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
    commands: list[list[Union[str, tuple[str]]]]
    valid_codes: list[int]
    environ: dict[str, str] = {}
    output_files: list[tuple[Path, bool]]
    parser: AnalysisResult
    color_mapping: dict
    install_help: str | None = None

    def __init__(self) -> None:
        """Initialize the SAST instance.

        Set up supported datasets, the output directory, and requirement status.
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
                # Check if optional argument can be used
                if isinstance(arg, tuple):
                    default_arg, optional_arg = arg
                    if pattern in optional_arg:
                        _command[i] = arg.replace(pattern, value)
                    else:
                        _command[i] = default_arg
                else:
                    if pattern in arg:
                        _command[i] = arg.replace(pattern, value)

        # Remove not rendered part of the command:
        __command = []
        for part in _command:
            if not ("{" in part and "}" in part):
                __command.append(part)

        return __command

    def run_analysis(
        self, lang: str, project_dir: Path, output_dir: Path, **kwargs: Any
    ) -> None:
        """Run the SAST analysis on a given project directory.

        Execute the tool's commands, time the analysis, calculate LoC,
        and save the results.

        Args:
            lang: The programming language of the project.
            project_dir: The path to the project's source code.
            output_dir: The path to save the analysis results.
            **kwargs: Additional tool-specific arguments.

        """
        render_variables = {"{lang}": lang}
        for k, v in kwargs.items():
            if v is None:
                continue
            to_replace = "{" + k + "}"
            if isinstance(v, str):
                render_variables[to_replace] = v
            elif isinstance(v, Path):
                render_variables[to_replace] = str(v.resolve())
            else:
                raise NotImplementedError(k, v)

        with Progress() as progress:
            progress.add_task(
                f"[b][{self.name}][/b] analyzing: [i]{project_dir.name}[/i]",
                total=None,
            )

            command_output = ""
            start = time.time()
            for command in self.commands:
                rendered_command = self.render_command(command, render_variables)
                retcode, out = run_command(rendered_command, project_dir, self.environ)
                command_output += out
                if retcode not in self.valid_codes:
                    raise NonZeroExit(rendered_command, command_output)
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
                filepath = project_dir / parent_dir / filename
                if filepath.is_file():
                    if not filepath == output_dir / filename:
                        shutil.copy2(filepath, output_dir / filename)
                else:
                    if required:
                        missing_files.append(filename)
            else:
                filepaths = (project_dir / parent_dir).glob(filename)
                if filepaths:
                    for filepath in filepaths:
                        if not filepath == output_dir / filename:
                            shutil.copy2(filepath, output_dir / filepath.name)
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
                    print(f"Results already exist for {repo.name}, skipping...")
                    print("Please use --overwrite to analyze again")

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


class BuildlessSAST(SAST):
    """Represent a SAST tool that analyzes source code directly without a build step."""

    pass


class PrebuiltSAST(SAST):
    """Represent a SAST tool that requires pre-built artifacts for analysis.

    Attributes:
        artefact_name (str): The name of the expected artifact (e.g., 'Java Bytecode').
        artefact_type (Literal["file", "directory"]): The type of artifact expected.

    """

    artefact_name: str
    artefact_type: Literal["file", "directory"]

    def analyze_files(
        self,
        dataset: PrebuiltFileDataset,
        overwrite: bool = False,
        testing: bool = False,
    ) -> None:
        """Analyze a pre-built file-based dataset.

        Check if the dataset has been built. If not, provide build instructions.
        Otherwise, run the analysis on the pre-built files.

        Args:
            dataset: The `PrebuiltFileDataset` instance to analyze.
            overwrite: If True, overwrite existing results for this dataset.
            testing: If True, run analysis on a sample of two random files for testing.

        """
        if not dataset.is_built():
            prebuilt_dir, prebuilt_glob = dataset.prebuilt_expected
            panel = Panel(
                f"""
Please build [b]{dataset.name}[/b] before running the benchmark
Build command: \t\t[b]{dataset.build_command}[/b]
Full command: \t\t[b](cd {dataset.directory} && {dataset.build_command})[/b]
Expected artefacts: \t[b]{str(dataset.directory / prebuilt_dir / prebuilt_glob)}[/b]""",
                title=f"[b]{self.name} - PrebuiltSAST[/b]",
            )
            print(panel)
            return

        # Adapted from base class
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
            prebuilt_files = random.sample(dataset.list_prebuilt_files(), k=2)
        else:
            prebuilt_files = dataset.list_prebuilt_files()

        for prebuilt_file in prebuilt_files:
            shutil.copy2(prebuilt_file, temp_path / prebuilt_file.name)

        # Run analysis
        self.run_analysis(
            dataset.lang, dataset.directory, result_path, artifacts=temp_path
        )

        # Clear temporary directory
        temp_dir.cleanup()


class PrebuiltBuildlessSAST(PrebuiltSAST, BuildlessSAST):
    """Represent a SAST tool that can analyze both source code and pre-built artifacts."""

    def run_analysis(
        self, lang: str, project_dir: Path, output_dir: Path, **kwargs: Any
    ) -> None:
        """Run analysis, deciding whether to use pre-built or buildless mode.

        If `artifacts` are provided in `kwargs`, it runs the analysis in pre-built mode.
        Otherwise, it falls back to the buildless mode, analyzing source code directly.

        Args:
            lang: The programming language of the project.
            project_dir: The path to the project's source code.
            output_dir: The path to save the analysis results.
            **kwargs: Additional tool-specific arguments, including optional 'artifacts'.

        """
        if kwargs.get("artifacts"):
            return PrebuiltSAST.run_analysis(
                self, lang, project_dir, output_dir, **kwargs
            )
        else:
            return BuildlessSAST.run_analysis(
                self, lang, project_dir, output_dir, **kwargs
            )
