"""Logging configuration for the reverse proxy detection.

Contains the logger configuration and different logging types.
"""

LOGGING_CONFIG = {
    "version": 1,
    "formatters": {
        "userFormatter": {
            "format": "%(message)s"
        },

        "fileFormatter": {
            "format": "%(asctime)s :: %(name)s :: %(levelname)s :: %(message)s",
            "datefmt": "%m/%d/%Y %I:%M:%S %p"
        },

        "debugFormatter": {
            "format": "%(levelname)s :: %(message)s"
        }
    },

    "handlers": {
        "consoleHandler": {
            "class": "logging.StreamHandler",
            "level": "INFO",
            "formatter": "userFormatter"
        },

        "fileHandler": {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "fileFormatter",
            "filename": "test_log.log",
            "backupCount": 10
        },

        "debugConsoleHandler": {
            "class": "logging.StreamHandler",
            "level": "DEBUG",
            "formatter": "debugFormatter"
        }
    },

    "loggers": {
        "user": {
            "level": "INFO",
            "handlers": ["consoleHandler", "fileHandler"],
            "propagate": False
        },

        "debug": {
            "level": "DEBUG",
            "handlers": ["debugConsoleHandler", "fileHandler"],
            "propagate": False
        }
    },

    "root": {
        "level": "DEBUG",
        "handlers": ["consoleHandler"]
    }
}
