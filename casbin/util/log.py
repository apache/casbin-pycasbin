# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

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
