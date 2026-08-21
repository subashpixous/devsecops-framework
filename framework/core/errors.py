"""Framework error types.

Design rule: no error raised here may ever be swallowed in a way that lets a
security verdict become PASS. Callers convert these into ScannerResult failures,
which the status engine maps to NOT_VERIFIED.
"""


class FrameworkError(Exception):
    """Base class for all framework errors."""


class ConfigurationError(FrameworkError):
    """Required configuration (host, token, project key, policy) is missing or invalid."""


class CollectorError(FrameworkError):
    """A collector could not complete a scan or retrieve results."""


class TransportError(CollectorError):
    """Network/HTTP level failure while talking to a scanner backend."""


class MalformedResponseError(CollectorError):
    """Scanner backend returned a payload the adapter cannot trust."""


class PolicyError(FrameworkError):
    """Policy file missing, unparsable, or internally inconsistent."""
