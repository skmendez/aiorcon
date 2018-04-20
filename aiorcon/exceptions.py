class RCONError(Exception):
    """Base exception for all RCON-related errors."""


class RCONStateError(RCONError):
    """Raised to indicate improper state of protocol."""

    def __init__(self, expected, actual):
        super().__init__("Expected the protocol to be in the {} state, but it was in the {} state"
                         .format(expected.name.lower(), actual.name.lower()))
        self.expected = expected
        self.actual = actual


class RCONCommunicationError(RCONError):
    """Used for propagating socket-related errors."""


class RCONTimeoutError(RCONError):
    """Raised when a timeout occurs waiting for a response."""


class RCONAuthenticationError(RCONError):
    """Raised for failed authentication.
    :ivar bool banned: signifies whether the authentication failed due to
        being banned or for merely providing the wrong password.
    """

    def __init__(self, banned=False):
        super().__init__("Authentication failed: " +
                         ("Banned" if banned else "Wrong password"))
        self.banned = banned


class RCONMessageError(RCONError):
    """Raised for errors encoding or decoding RCON messages."""
