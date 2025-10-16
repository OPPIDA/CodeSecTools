"""Define properties for SAST tool integrations."""


class SASTProperties:
    """Represent properties of a SAST tool."""

    def __init__(self, free: bool, offline: bool) -> None:
        """Initialize a SASTProperties instance.

        Args:
            free: A boolean indicating if the tool is free to use.
            offline: A boolean indicating if the tool can run without an internet connection.

        """
        # Usage
        self.free = free
        self.offline = offline
