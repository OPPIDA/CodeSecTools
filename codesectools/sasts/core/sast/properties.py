"""Define properties for SAST tool integrations."""


class SASTProperties:
    """Represent properties of a SAST tool."""

    def __init__(self, free: bool, offline: bool, buildless: bool) -> None:
        """Initialize a SASTProperties instance.

        Args:
            free: A boolean indicating if the tool is free to use.
            offline: A boolean indicating if the tool can run without an internet connection.
            buildless: A boolean indicating if the tool can analyze code without building it.

        """
        self.free = free
        self.offline = offline
        self.buildless = buildless
