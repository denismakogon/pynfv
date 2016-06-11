#    Copyright 2015 Brocade Communications System, Inc.
#    All Rights Reserved.
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

import functools
import requests

from pynfv.common import logger as pynfv_logger
from pynfv.common import exceptions
from pynfv.common import utils


def api_task(action):
    @functools.wraps(action)
    def wraps(*args, **kwargs):
        self = list(args)[0]
        self.logger.info("Executing action {0}. Pos-args: {1}. Kwargs: {2}."
                         .format(action.__name__, str(args), str(kwargs)))
        action_response = action(*args, **kwargs)
        self.logger.debug("Response.text {0}."
                          .format(str(action_response.text)))
        self.logger.debug("Response.content {0}."
                          .format(str(action_response.content)))
        self.logger.debug("Response.headers {0}."
                          .format(str(action_response.headers)))
        if not exceptions.client_exceptions.is_not_raisable(
                action_response.status_code):
            self.logger.info("Resulting JSON response: {0}."
                             .format(action_response.text))
            return utils.json.loads(action_response.text)
        exceptions.client_exceptions.raise_from_code(
            action_response.status_code, action_response.text)
    return wraps


class RESTconfResourceClient(object):

    # in seconds
    __default_request_timeout = 60

    def __init__(self, user, password, host, **kwargs):
        if 'logger' not in kwargs:
            self.logger = pynfv_logger.setup_logging(__name__)
        self.host = host
        self.auth = (user, password) if not kwargs.get(
            'skip_auth', False) else None
        if 'timeout' not in kwargs:
            self.timeout = self.__default_request_timeout
        for k, v in kwargs.items():
            setattr(self, k, v)

    def get(self, urlpath, **data):
        return self._request('GET', urlpath=urlpath, data=data)

    def post(self, urlpath, **data):
        return self._request('POST', urlpath=urlpath, data=data)

    def put(self, urlpath, **data):
        return self._request('PUT', urlpath=urlpath, data=data)

    def delete(self, urlpath, **data):
        return self._request('DELETE', urlpath=urlpath, data=data)

    def patch(self, urlpath, **data):
        return self._request('PATCH', urlpath=urlpath, data=data)

    @api_task
    def _request(self, method, urlpath='', data=None):
        headers = {'Content-Type': 'application/json'}
        url = '/'.join([self.host, urlpath])
        return requests.request(
            method, url=url, headers=headers, data=data,
            auth=self.auth,
            timeout=self.timeout)
