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

import functools

from pynfv.common import restconf_client
from pynfv.common import exceptions

from pynfv.opendaylight.inventory import models


def odl_api_action(action):
    @functools.wraps(action)
    def wraps(*args, **kwargs):
        try:
            self = list(args)[0]
            self.logger.info("Action {0}. Pos-args: {1}, Kwargs: {2}"
                             .format(action.__name__, str(args), str(kwargs)))
            return action(*args, **kwargs)
        except exceptions._RESTconfException as e:
            raise exceptions.ODLAPIException(e)
    return wraps


class ODLNodesAPI(restconf_client.RESTconfResourceClient):

    def __init__(self, user, password, host, logger=None):
        self.logger = logger
        super(ODLNodesAPI, self).__init__(
            user, password, host, logger=logger, skip_auth=False)

    @odl_api_action
    def get_nodes(self):
        resulting_nodes = []
        nodes = self.get(
            'restconf/config/opendaylight-inventory:nodes')['nodes']
        for node_name, nodes_list in nodes.items():
            for node in nodes_list:
                resulting_nodes.append(models.ODLInventoryNode(node))
        return resulting_nodes

    @odl_api_action
    def get_node(self, node_id, operational=False, include_interfaces=False):
        if not operational:
            _node = self.get(
                'restconf/config/opendaylight-inventory:nodes/'
                'node/{0}'.format(node_id))['node'][0]
        else:
            _node = self.get('restconf/operational/'
                             'opendaylight-inventory:nodes/node/'
                             '{0}'.format(node_id))['node'][0]

        node = models.ODLInventoryNode(_node)

        if include_interfaces:
            interfaces = self._get_node_interfaces(node_id)
            node.setup_interfaces(interfaces)

        return node

    def _get_node_interfaces(self, node_id):
        interfaces = self.get('restconf/operational/'
                              'opendaylight-inventory:nodes/node/'
                              '{0}/yang-ext:mount/'
                              '{0}-interfaces-v1:interfaces'.format(node_id))
        return interfaces['interfaces']


class ODLInventoryAPI(restconf_client.RESTconfResourceClient):

    def __init__(self, user, password, host, logger=None):
        super(ODLInventoryAPI, self).__init__(user, password, host, skip_auth=False)
        self.nodes = ODLNodesAPI(user, password, host, logger=logger)
