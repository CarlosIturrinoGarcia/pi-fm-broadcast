"""Custom exceptions for the FM broadcast service."""


class BroadcastError(Exception):
    """Base exception for broadcast errors."""
    pass


class ConfigurationError(BroadcastError):
    """Raised when configuration is invalid."""
    pass


class ValidationError(BroadcastError):
    """Raised when input validation fails."""
    pass


class DownloadError(BroadcastError):
    """Raised when file download fails."""
    pass


class PlaybackError(BroadcastError):
    """Raised when playback fails."""
    pass


class PlaybackInterrupted(BroadcastError):
    """Raised when playback is interrupted by signal."""
    pass


class PlaybackTimeout(PlaybackError):
    """Raised when playback exceeds maximum duration."""
    pass


class SilenceError(BroadcastError):
    """Raised when silence carrier management fails."""
    pass


class MessageProcessingError(BroadcastError):
    """Raised when message processing fails."""
    pass
