"""Docker client wrapper module."""

import os
import sys
from hashlib import sha256
from pathlib import Path

from python_on_whales import DockerClient
from python_on_whales.client_config import ClientNotFoundError

from codesectools.utils import PACKAGE_DIR, USER_DIR

UID = os.getuid()
GID = os.getgid()


class Docker(DockerClient):
    """Wrapper around DockerClient to handle initialization errors."""

    def __init__(self) -> None:
        """Initialize the Docker client and verify availability."""
        try:
            super().__init__()
            self.info()
        except ClientNotFoundError as e:
            print(e)
            sys.exit(1)


class AnalysisEnvironment:
    """Manage the Docker environment for code analysis."""

    build_args = {"UID": str(UID), "GID": str(GID)}

    def __init__(self, isolation: bool) -> None:
        """Initialize the analysis environment."""
        self.isolation = isolation
        self.docker = Docker()
        self.dockerfile = PACKAGE_DIR.parent / "Dockerfile"
        self.name = "codesectools"

    def build(self) -> None:
        """Build the Docker image if it does not exist or if the file hash changed."""
        file_hash = sha256(self.dockerfile.read_bytes()).hexdigest()
        if not self.docker.images(
            all=True, filters={"label": f"file_hash={file_hash}"}
        ):
            self.docker.image.build(
                PACKAGE_DIR.parent,
                tags=self.name,
                labels={"file_hash": file_hash},
                file=self.dockerfile,
                build_args=self.build_args,
            )

    def start(self, target: Path) -> None:
        """Start the Docker container and attach to it.

        Build the image if necessary, then create and start a container
        with the target directory mounted. If a container for the target
        already exists, it starts and attaches to it.

        Args:
            target: The path to the directory to mount in the container.

        """
        self.build()

        if self.isolation:
            target_container_name = f"codesectools-{target.name}-isolated"
        else:
            target_container_name = f"codesectools-{target.name}"
        target_container_home = Path("/home/codesectools")
        target_container_workdir = target_container_home / target.name

        if containers := self.docker.ps(
            all=True,
            filters=[
                ("name", "codesectools-*"),
                ("label", f"target={str(target.resolve())}"),
                ("label", f"isolation={self.isolation}"),
            ],
        ):
            container = containers[0]
            if not container.state.running:
                self.docker.start(container)

            container.execute(
                ["/bin/bash"],
                interactive=True,
                tty=True,
            )
        else:
            container = self.docker.run(
                self.name,
                name=target_container_name,
                command=["/bin/bash"],
                labels={
                    "target": str(target.resolve()),
                    "isolation": str(self.isolation),
                },
                networks=["none"] if self.isolation else [],
                volumes=[
                    (target, target_container_workdir),
                    (USER_DIR, target_container_home / USER_DIR.name),
                ],
                interactive=True,
                tty=True,
            )
