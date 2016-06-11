#    Author: Denys Makogon
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import logging
import sys


def common_logger_setup(
        level=logging.DEBUG,
        filename='/tmp/pynfv.log',
        log_formatter='[%(asctime)s] - '
                      'PID: %(process)s - '
                      '%(name)s - '
                      '%(levelname)s - '
                      '{%(pathname)s:%(lineno)d} - '
                      '%(module)s - '
                      '%(funcName)s - '
                      '%(message)s',
        datetime_formatter='%Y-%m-%d %H:%M:%S',
        log_to_console=False):
    if log_to_console:
        log_handler = logging.StreamHandler(sys.stdout)
    else:
        log_handler = logging.FileHandler(filename)
    log_format = logging.Formatter(log_formatter, datetime_formatter)
    log_handler.setFormatter(log_format)
    return log_handler, level


def setup_logging(name, filename='/tmp/pynfv.log',
                  level=logging.DEBUG, log_to_console=False):
    log_file_handler, log_level = common_logger_setup(filename=filename,
                                                      level=level,
                                                      log_to_console=log_to_console)
    logger = logging.getLogger(name)
    logger.addHandler(log_file_handler)
    logger.setLevel(log_level)
    return logger


class Singleton(type):
    _instance = None

    def __call__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instance


class UnifiedLogger(metaclass=Singleton):

    def __init__(self, filename='/tmp/pynfv.log',
                 level=logging.DEBUG, log_to_console=False):
        self.filename = filename
        self.level = level
        self.log_to_console = log_to_console

    def setup_logger(self, name):
        return setup_logging(name, filename=self.filename,
                             level=self.level,
                             log_to_console=self.log_to_console)

    @classmethod
    def from_class(cls):
        if not cls._instance:
            raise Exception("Logger was not initialized.")
        return cls._instance
