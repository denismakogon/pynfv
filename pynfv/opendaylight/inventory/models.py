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


class ODLBaseModel(dict):

    exclude_id_on_attributes = True

    def __getattr__(self, name):
        try:
            return self[name]
        except Exception as e:
            print(str(e))
            raise AttributeError(str(e))

    def __repr__(self):
        return self.template.format(self.id)

    @property
    def attributes(self):
        attrs = [item for item in list(self.keys())
                 if not item.startswith('_')]
        if self.exclude_id_on_attributes and 'id' in self:
            attrs.pop(attrs.index('id'))
        return attrs


class ODLInventoryNodeInterfaceEthernetPort(ODLBaseModel):

    """
    Interface ports are pinned to Node interfaces.
    This class represents a list of available ethernet
    ports on specific Interface.
    Each ethernet port represented by:
        - address
        - ip
        - ipv6
        - tagnode
        - vlan-protocol
        - mtu
    """
    template = "OpenDaylight Inventory Node '{0}' interface '{1}' '{2}' ethernet port."

    def __init__(self, node_id, iface, ethernet_port_info):
        self.id = node_id
        self.parent_interface = iface
        self.update(**ethernet_port_info)

    def __repr__(self):
        return self.template.format(self.id, self.parent_interface, self.tagnode)


class ODLInventoryNodeInterfaces(ODLBaseModel):

    """
    ODL Node interfaces class
    Represents operations over interfaces of a Node
    """
    template = "OpenDaylight Inventory Node {0} interfaces"

    def __init__(self, node_id, dct):
        self.update(id=node_id)
        __original_iface_names = {}
        for k, eths in dct.items():
            iface = k.replace('-', ':').replace(':', '_')
            __original_iface_names.update({iface: k})
            self.update({iface: [ODLInventoryNodeInterfaceEthernetPort(
                node_id, iface, eth) for eth in eths]})
        self.update(__original_iface_names=__original_iface_names)

    @property
    def ethernet_ports_per_interface(self):
        return [{iface: self[iface]} for iface in self.attributes]

    def get_original_interface_name(self, iface):
        return self['__original_iface_names'][iface]


class ODLInventoryNodeCapability(ODLBaseModel):
    """
    This class represents initial node capabilities
    available for operational mapping.
    Capability is defined by next attributes:
        - SOAP URN
        - version
        - revision
        - name
    """
    template = "OpenDaylight Inventory Node capability defined by {0}"

    def __init__(self, capability_string):
        urn_revision_version, name = capability_string.split(')')
        unpacked = urn_revision_version.split('?')
        # it may appear that there no revision date in URN
        if len(unpacked) == 1:
            urn_and_version, revision = unpacked[0], None
        else:
            urn_and_version, revision = unpacked
            revision = revision[9:]
        urn_name, version = urn_and_version[1:][4:], urn_and_version[-1:]
        if not version.isdigit():
            version = None
        if version == '0':
            index_of_double_dot = urn_and_version[::-1].index(':')
            version = urn_and_version[-index_of_double_dot:]
        self.update({
            'name': name,
            'revision': revision,
            'urn_name': urn_name,
            'version': version,
        })

    def __repr__(self):
        return self.template.format(str({
            'name': self.name,
            'revision': self.revision,
            'urn_name': self.urn_name,
            'version': self.version,
        }))


class ODLInventoryNodeAPI(ODLBaseModel):
    """
    This class represents initial node capabilities
    available for operational mapping.
    """

    template = "OpenDaylight Inventory Node capabilities"

    def __init__(self, capabilities):
        for capability in capabilities:
            _c = ODLInventoryNodeCapability(capability)
            self.update({_c.name: _c})

    def filter_by_name(self, key_part):
        return [_c_name for _c_name in self if key_part in _c_name]

    def protocols_api(self):
        return self.filter_by_name('-protocols-')

    def policy_api(self):
        return self.filter_by_name('-policy-')

    def security_api(self):
        return self.filter_by_name('-security-')

    def system_api(self):
        return self.filter_by_name('-system-')

    def services_api(self):
        return self.filter_by_name('-services-')

    def ietf_netconf_api(self):
        return self.filter_by_name('netconf')

    def op_api(self):
        return self.filter_by_name('-op-')

    def opd_api(self):
        return self.filter_by_name('-opd-')

    def interfaces_api(self):
        return self.filter_by_name('-interfaces-')

    def resources_api(self):
        return self.filter_by_name('-resources-')

    def __repr__(self):
        return self.template


class ODLInventoryNode(ODLBaseModel):

    """
    ODL Node representation class

    Regular ODL Node contains only its ID,
    but if 'operational=True' for 'get_node'
    ODL will return operational info for specific node.

    Typical node properties:
      - id: node ID
      - netconf_node_inventory_connected: reflects node connectivity state
      - netconf_node_inventory_initial_capability: represents node capabilities
    """
    template = "OpenDaylight Inventory Node {0}."
    exclude_id_on_attributes = False

    def __init__(self, dct):

        for k, v in dct.items():
            k = k if len(k.split(':')) == 1 else k.split(':')[1]
            if 'capability' in k:
                v = ODLInventoryNodeAPI(v)
            self.update({k.replace('-', '_'): v})

        super(ODLInventoryNode, self).__init__(dct)

    def setup_interfaces(self, raw_ifaces):
        ifaces = ODLInventoryNodeInterfaces(self.id, raw_ifaces)
        self['interfaces'] = ifaces
        self.update(interfaces=ifaces)
