import logging
import logging.config

# Default logging for Casbin.
DEFAULT_LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "casbin_formatter": {
            "format": "{asctime} {message}",
            "style": "{",
        }
    },
    "handlers": {
        "console": {
            "level": "INFO",
            "class": "logging.StreamHandler",
            "formatter": "casbin_formatter",
        },
    },
    "loggers": {
        "casbin": {
            "handlers": ["console"],
            "level": "INFO",
        },
        "casbin.policy": {
            "handlers": ["console"],
            "level": "WARNING",
            "propagate": False,
        },
        "casbin.enforcer": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
        "casbin.role": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
    },
}


def configure_logging(logging_config=None):
    if logging_config:
        logging.config.dictConfig(logging_config)
    else:
        logging.config.dictConfig(DEFAULT_LOGGING)


def disabled_logging():
    for logger_name in DEFAULT_LOGGING["loggers"].keys():
        logging.getLogger(logger_name).disabled = True
