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

import copy

from requests import status_codes

from pynfv.common import utils


class ExceptionLookupDict(status_codes.LookupDict):

    def is_not_raisable(self, http_code):
        return self.get(str(http_code), None) is not None

    def raise_from_code(self, http_code, message):
        exception_class = self.get(str(http_code))
        raise exception_class(message)


class _RESTconfException(Exception):

    http_code = 500
    reason = 'Unknown'

    def str_to_json(self, string):
        return utils.json.loads(string)

    def get_concrete_exception_reason(self, msg):
        return self.str_to_json(
            str(msg))['errors']['error'][0]['error-message']

    def __init__(self, message):
        super(_RESTconfException, self).__init__(message)


class ODLAPIException(_RESTconfException):

    def __init__(self, exception_instance):
        self.http_code = exception_instance.http_code
        self.reason = exception_instance.reason
        super(ODLAPIException, self).__init__(
            self.get_concrete_exception_reason(str(exception_instance)))


_exceptions = copy.copy(status_codes._codes)
client_exceptions = ExceptionLookupDict(name='http_response_codes')

for code, titles in _exceptions.items():
    if code in range(400, 511):
        main_title = list(titles)[0]
        exception_class_from_code = type(
            main_title.upper() + _RESTconfException.__name__,
            (_RESTconfException,), {})
        exception_class_from_code.http_code = code
        exception_class_from_code.reason = main_title
        setattr(client_exceptions, str(code), exception_class_from_code)
