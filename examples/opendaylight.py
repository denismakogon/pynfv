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

import click


from pynfv.common import logger
from pynfv.opendaylight.inventory import client as inventory


@click.command(name='odl-example')
@click.option('--host', default='localhost', help='ODL host')
@click.option('--port', default='8080', help='ODL port')
@click.option('--user', default='admin', help='ODL user')
@click.option('--password', default='admin', help='ODL password')
@click.option('--log-to-console', is_flag=True, default=True, help='Log everything to console')
@click.option('--log-file', default='/tmp/pynfv.log', help='PyNFV log file')
@click.option('--log-level', default='DEBUG', help='API service bind host.')
def main(host, port, user, password, log_to_console, log_file, log_level):
    odl_inventory = inventory.ODLInventoryAPI(
        user, password,
        '{0}:{1}'.format(host, port),
        logger=logger.UnifiedLogger(
            log_to_console=log_to_console,
            level=log_level,
            filename=log_file).setup_logger(__name__))

    nodes = odl_inventory.nodes.get_nodes()
    print(nodes)
    node = nodes[3]
    print(node.attributes)
    node_id = node.id
    extended_node = odl_inventory.nodes.get_node(node_id, operational=True,
                                                 include_interfaces=True)
    print(extended_node.attributes)
    ifaces = extended_node.interfaces
    print(ifaces)
    print(ifaces.attributes)
    print(ifaces.get_original_interface_name(ifaces.attributes[0]))
    print(ifaces.ethernet_ports_per_interface)
    print(extended_node.initial_capability.attributes)
    print(extended_node.initial_capability.protocols_api())
    print('\n')
    print(extended_node.initial_capability.policy_api())
    print('\n')
    print(extended_node.initial_capability.system_api())
    print('\n')
    print(extended_node.initial_capability.services_api())
    print('\n')
    print(extended_node.initial_capability.ietf_netconf_api())
    print('\n')
    print(extended_node.initial_capability.op_api())
    print('\n')
    print(extended_node.initial_capability.opd_api())
    print('\n')
    print(extended_node.initial_capability.interfaces_api())
    print('\n')
    print(extended_node.initial_capability.resources_api())
    print('\n')


if __name__ == "__main__":
    main()
