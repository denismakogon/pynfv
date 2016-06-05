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
import logging

LOG = logging.getLogger(__name__)


def api_task(action):
    @functools.wraps(action)
    def wraps(*args, **kwargs):
        action_response = action(*args, **kwargs)
        try:
            action_response.rise_for_status()
        except requests.HTTPError as ex:
            LOG.exception("%s. %s." % (action_response.text, str(ex)))
        else:
            return action_response
    return wraps


class RESTconfResourceClient(object):

    # in seconds
    __default_request_timeout = 60

    def __init__(self, user, password, host, **kwargs):
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
        LOG.debug(
            "Sending METHOD (%(method)s) URL (%(url)s) JSON (%(data)s)",
            {'method': method, 'url': url, 'data': data})
        return requests.request(
            method, url=url, headers=headers, data=data,
            auth=self.auth,
            timeout=self.timeout)
