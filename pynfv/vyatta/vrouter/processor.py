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

import six
import re
import netaddr
import logging

from urllib.parse import quote_plus
from pynfv.common import utils
from pynfv.vyatta.vrouter import exceptions

LOG = logging.getLogger(__name__)


class vRouterModel(object):

    _VROUTER_VSE_MODEL = 54
    _VROUTER_VR_MODEL = 56

    def _process_empty_version(self, version):
        if version is not None:
            ma = re.compile(
                ".+Description.+Brocade Vyatta\D+(\d+).+", re.DOTALL)
            _match = ma.match(version)
            if _match is not None:
                model = int(_match.group(1)) / 100
                return model if model in (self._VROUTER_VSE_MODEL,
                                          self._VROUTER_VR_MODEL) else None

    @property
    def vse_model(self):
        return self._VROUTER_VSE_MODEL

    @property
    def vr_model(self):
        return self._VROUTER_VR_MODEL

    def process_vrouter_model(self, version):
        model = None
        vrouter_model = self._process_empty_version(version)
        if vrouter_model is None:
            raise exceptions.VRouterOperationError(
                ip_address=self.host,
                reason='Unable to process vRouter model info: {0}'
                .format(model))
        return vrouter_model


class vRouterCachedState(vRouterModel):

    _EXTERNAL_GATEWAY_DESCR = 'External_Gateway'
    _ROUTER_INTERFACE_DESCR = 'Router_Interface'
    _ROUTER_IF_SUBNET_DICT = {}
    _MAX_NAT_FLOATING_IP_RULE_NUM = 4000
    _MAX_NAT_EXCLUDE_RULE_NUM = 8000
    _MAX_NAT_SUBNET_IP_RULE_NUM = 12000
    _FLOATING_IP_DICT = {}
    _ROUTER_SUBNET_NAT_EXCLUDE_DICT = {}
    _NAT_EXCLUDE_RULE_NUM = _MAX_NAT_FLOATING_IP_RULE_NUM
    _EXTERNAL_GW_INFO = None
    _NAT_SUBNET_IP_RULE_NUM = _MAX_NAT_EXCLUDE_RULE_NUM
    _NAT_FLOATING_IP_RULE_NUM = 0

    def _sync_cache(self, vrouter_model, configuration,
                    vrouter_vr_model, vrouter_vse_model):
        system_gw = None
        gateway_str = self._get_config_block("protocols", configuration)
        if gateway_str is not None:
            system_gw = self._parse_system_gateway(gateway_str)

        interfaces_str = self._get_config_block("interfaces", configuration)
        if interfaces_str is not None:
            self._process_interfaces(vrouter_model, vrouter_vse_model,
                                     interfaces_str, system_gw)

        if vrouter_model == vrouter_vr_model:
            configuration = self._get_config_block("service", configuration)

        nat_str = self._get_config_block("nat", configuration)
        if nat_str is not None:
            self._process_source_nat_rules(nat_str)

        LOG.info("Vyatta vRouter cache ext gw %s",
                 self._EXTERNAL_GW_INFO)

        LOG.info("Vyatta vRouter cache router if dict %s",
                 self._ROUTER_IF_SUBNET_DICT)
        LOG.info("Vyatta vRouter cache floating ip dict %s",
                 self._FLOATING_IP_DICT)
        LOG.info("Vyatta vRouter cache router nat-exclude dict %s",
                 self._ROUTER_SUBNET_NAT_EXCLUDE_DICT)
        LOG.info("Vyatta vRouter cache NAT floating ip %s",
                 self._NAT_FLOATING_IP_RULE_NUM)
        LOG.info("Vyatta vRouter cache NAT subnet ip %s",
                 self._NAT_SUBNET_IP_RULE_NUM)
        LOG.info("Vyatta vRouter cache NAT exclude rule num %s",
                 self._NAT_EXCLUDE_RULE_NUM)

    def _get_config_block(self, input_str, search_str):
        if search_str is not None:
            index = search_str.find(input_str)
            if index >= 0:
                block_start = search_str[index + len(input_str):]
                block_str = []
                for line in block_start.split('\n'):
                    if line.startswith('}'):
                        break
                    block_str.append(line)
                return ''.join(block_str)

    def _parse_system_gateway(self, search_str):
        result = re.compile(".+static.+route.+next-hop ([^ \n]+).+",
                            re.DOTALL).match(search_str)
        return result.group(1) if result is not None else None

    def _get_subnet_from_ip_address(self, ip_address):
        return str(netaddr.IPNetwork(ip_address).cidr)

    def _process_interfaces(self, vrouter_model, vrouter_vse_model,
                            search_str, system_gw_ip):
        if vrouter_model == vrouter_vse_model:
            ma = re.compile(
                ".+ethernet (eth\d+).+address ([^ \n]+).+description ([^ \n]+)"
                ".+", re.DOTALL)
        else:
            ma = re.compile(
                ".+dataplane (dp\d+s\d+).+address ([^ \n]+).+description"
                " ([^ \n]+).+", re.DOTALL)

        for paragraph in search_str.split('}'):
            result = ma.match(paragraph)
            if result is not None:
                eth_if_id, ip_address, description = (result.group(1),
                                                      result.group(2),
                                                      result.group(3))
                if description == self._EXTERNAL_GATEWAY_DESCR:
                    ext_gw_info = InterfaceInfo(eth_if_id,
                                                ip_address,
                                                system_gw_ip)
                    self._EXTERNAL_GW_INFO = ext_gw_info
                elif description == self._ROUTER_INTERFACE_DESCR:
                    router_if_subnet = self._get_subnet_from_ip_address(
                        ip_address)
                    self._ROUTER_IF_SUBNET_DICT[router_if_subnet] = None

    def _get_floating_ip_key(self, floating_ip, fixed_ip):
        return "{0}.{1}".format(floating_ip, fixed_ip)

    def _process_source_nat_rules(self, search_str):
        for paragraph in search_str.split('rule'):
            ma = re.compile(
                ".(\d+).+outbound-interface.+source.+address ([^ \n]+)"
                ".+translation.+address ([^ \n]+).+", re.DOTALL)
            result = ma.match(paragraph)
            if result is not None:
                rule_num = int(result.group(1))
                src_addr = result.group(2)
                translation_addr = result.group(3)
                if (self._MAX_NAT_EXCLUDE_RULE_NUM < rule_num <
                        self._MAX_NAT_SUBNET_IP_RULE_NUM and
                            src_addr in self._ROUTER_IF_SUBNET_DICT):
                    self._ROUTER_IF_SUBNET_DICT[src_addr] = rule_num
                    self._NAT_SUBNET_IP_RULE_NUM = rule_num
                elif (self._MAX_NAT_FLOATING_IP_RULE_NUM < rule_num <
                      self._MAX_NAT_EXCLUDE_RULE_NUM and
                      src_addr in self._ROUTER_IF_SUBNET_DICT):
                    pass
                elif rule_num < self._MAX_NAT_FLOATING_IP_RULE_NUM:
                    self._NAT_FLOATING_IP_RULE_NUM = rule_num
                    floating_ip = translation_addr
                    fixed_ip = src_addr
                    dict_key = self._get_floating_ip_key(floating_ip, fixed_ip)
                    self._FLOATING_IP_DICT[dict_key] = rule_num


class InterfaceInfo(object):

    def __init__(self, ethernet_if_id, ip_address,
                 gateway_ip=None):
        self._ethernet_if_id = ethernet_if_id
        self._ip_address = ip_address
        self._gateway_ip = gateway_ip
        self._ip_addr_without_cidr = None

    def get_ethernet_if_id(self):
        return self._ethernet_if_id

    def get_ip_address(self):
        return self._ip_address

    def get_ip_addr_without_cidr(self):
        return (str(netaddr.IPNetwork(self._ip_address).ip)
                if self._ip_addr_without_cidr is None
                else self._ip_addr_without_cidr)

    def get_gateway_ip(self):
        return self._gateway_ip

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__dict__ == other.__dict__
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return 'Eth if:{0} IP:{1} GW:{2}'.format(self._ethernet_if_id,
                                                 self._ip_address,
                                                 self._gateway_ip)

    def __repr(self):
        return self.__str__()


class VyattaAPICall(object):

    def __init__(self, api_call_type, api_call):
        self.api_call_type = api_call_type
        self.api_call = api_call

    def __repr__(self):
        return '{0} {1!r}'.format(self.api_call_type, self.api_call)

    def __eq__(self, other):
        if not isinstance(other, VyattaAPICall):
            return NotImplemented
        return (self.api_call_type, self.api_call) == (
            other.api_call_type, other.api_call)

    def __ne__(self, other):
        return not self.__eq__(other)

    def make_url(self, prefix):
        url = (prefix, self.api_call_type, self.api_call)
        return '/'.join(url)


class VyattaSetAPICall(VyattaAPICall):

    def __init__(self, cmd):
        super(VyattaSetAPICall, self).__init__("set", cmd)


class VyattaDeleteAPICall(VyattaAPICall):

    def __init__(self, cmd):
        super(VyattaDeleteAPICall, self).__init__("delete", cmd)


class EthernetIFProcessor(vRouterCachedState):

    IF_MAC_ADDRESS = 'mac_address'
    IF_IP_ADDRESS = 'ip_address'

    def get_ethernet_if_id(self, mac_address):
        LOG.debug('Vyatta vRouter:get_ethernet_if_id. Given MAC {0}'
                  .format(repr(mac_address)))
        iface = self.find_interface(mac_address)
        return iface['name']

    def get_ethernet_if_info(self, interface_info):
        gw_mac_address = interface_info[self.IF_MAC_ADDRESS]
        gw_ip_address = interface_info[self.IF_IP_ADDRESS]
        gw_if_id = self.get_ethernet_if_id(gw_mac_address)

        return gw_ip_address, gw_if_id

    def get_interface(self):
        if self.vrouter_model == self.vr_model:
            return "dataplane"
        else:
            return "ethernet"

    def get_interfaces(self):
        output = self.show('interfaces/detail')
        return utils.parse_interfaces(output)

    def find_interface(self, mac_address):
        mac_address = mac_address.strip().lower()
        ifaces = self.get_interfaces()
        for iface in ifaces:
            if iface['mac_address'] == mac_address:
                return iface

        raise exceptions.VRouterOperationError(
            ip_address=self.host,
            reason='Ethernet interface with Mac-address {0} does not exist'
            .format(mac_address))

    def set_ethernet_if(self, cmd_list, if_id,
                        ip_address, descr):
        if_cmd = self.get_interface()
        cmd_list.append(VyattaSetAPICall("interfaces/{0}/{1}/address/{2}"
                                         .format(if_cmd, if_id, quote_plus(ip_address))))
        cmd_list.append(VyattaSetAPICall("interfaces/{0}/{1}/description/{2}"
                                         .format(if_cmd, if_id, quote_plus(descr))))

    def delete_ethernet_if(self, cmd_list, if_id,
                           ip_address, descr):
            if_cmd = self.get_interface()
            cmd_list.append(VyattaDeleteAPICall("interfaces/{0}/{1}/address/{2}"
                                                .format(if_cmd, if_id, quote_plus(ip_address))))
            cmd_list.append(VyattaDeleteAPICall("interfaces/{0}/{1}/description/{2}"
                                                .format(if_cmd, if_id, quote_plus(descr))))
            cmd_list.append(VyattaDeleteAPICall("interfaces/{0}/{1}".
                                                format(if_cmd, if_id)))

    def delete_ethernet_ip(self, cmd_list, if_id, ip_address):
        if_cmd = self.get_interface()

        cmd_list.append(VyattaDeleteAPICall("interfaces/{0}/{1}/address/{2}"
                        .format(if_cmd, if_id, quote_plus(ip_address))))

    def set_ethernet_ip(self, cmd_list, if_id, ip_address):
        if_cmd = self.get_interface()

        cmd_list.append(VyattaSetAPICall("interfaces/{0}/{1}/address/{2}"
                                         .format(if_cmd, if_id, quote_plus(ip_address))))


class NATSNATDNATProcessor(vRouterCachedState):

    """
    NAT ServiceNAT Processor API
    """

    def get_nat(self):

        return 'service/nat' if (self.vrouter_model ==
                                 self.vr_model) else 'nat'

    def delete_snat_rule(self, cmd_list, rule_num):
        """Deletes the given SNAT rule."""

        cmd_list.append(VyattaDeleteAPICall("{0}/source/rule/{1}".
                        format(self.get_nat(), rule_num)))

    def get_next_nat_subnet_ip_rule_num(self):
        """Returns the next NAT rule number for subnet ip."""

        if self._NAT_SUBNET_IP_RULE_NUM >= self._MAX_NAT_SUBNET_IP_RULE_NUM:
            raise exceptions.VRouterOperationError(
                ip_address=self.host,
                reason='Max NAT Subnet IP rule count reached')

        self._NAT_SUBNET_IP_RULE_NUM += 1
        return self._NAT_SUBNET_IP_RULE_NUM

    def add_snat_rule(self, cmd_list, rule_num, ext_if_id,
                      src_addr, translation_addr):
        nat_cmd = self.get_nat()
        cmd_list.append(
            VyattaSetAPICall("{0}/source/rule/{1}".format(nat_cmd, rule_num)))
        cmd_list.append(VyattaSetAPICall("{0}/source/rule/{1}/outbound-interface/{2}"
                        .format(nat_cmd, rule_num, ext_if_id)))
        cmd_list.append(VyattaSetAPICall("{0}/source/rule/{1}/source/address/{2}"
                        .format(nat_cmd, rule_num, quote_plus(src_addr))))
        cmd_list.append(VyattaSetAPICall("{0}/source/rule/{1}/translation/address/{2}"
                        .format(nat_cmd, rule_num, quote_plus(translation_addr))))

    def add_snat_rule_for_router_if(self, cmd_list,
                                    router_if_subnet,
                                    ext_gw_info):

        rule_num = self.get_next_nat_subnet_ip_rule_num()

        self.add_snat_rule(cmd_list,
                           rule_num,
                           ext_gw_info.get_ethernet_if_id(),
                           router_if_subnet,
                           ext_gw_info.get_ip_addr_without_cidr())

        return rule_num

    def add_dnat_rule(self, cmd_list, rule_num, ext_if_id,
                      dest_addr, translation_addr):

        nat_cmd = self.get_nat()

        # Execute the commands
        cmd_list.append(
            VyattaSetAPICall("{0}/destination/rule/{1}".format(nat_cmd, rule_num)))
        cmd_list.append(VyattaSetAPICall("{0}/destination/rule/{1}/inbound-interface/{2}"
                        .format(nat_cmd, rule_num, ext_if_id)))
        cmd_list.append(VyattaSetAPICall("{0}/destination/rule/{1}/destination/"
                        "address/{2}".format(
            nat_cmd, rule_num, quote_plus(dest_addr))))
        cmd_list.append(VyattaSetAPICall("{0}/destination/rule/{1}/translation/"
                        "address/{2}".format(
            nat_cmd, rule_num, quote_plus(translation_addr))))

    def delete_dnat_rule(self, cmd_list, rule_num):
        cmd_list.append(VyattaDeleteAPICall("{0}/destination/rule/{1}".
                        format(self.get_nat(), rule_num)))


class GatewayProcessor(EthernetIFProcessor, NATSNATDNATProcessor):
    """
    Gateway Processor API
    """

    IF_GATEWAY_IP = 'gateway_ip'

    def clear_cached_gateway_info(self):
        # Clear the external gateway info from the cache
        self._EXTERNAL_GW_INFO = None

        # Remove NAT rules for the existing router interfaces
        for router_if_subnet in self._ROUTER_IF_SUBNET_DICT.keys():
            self._ROUTER_IF_SUBNET_DICT[router_if_subnet] = None

    def clear_gateway_configuration(self, cmd_list):
        # If external gateway info was cached before
        # then clear the gateway router info
        if self._EXTERNAL_GW_INFO is not None:
            self.delete_external_gateway_if(
                cmd_list, self._EXTERNAL_GW_INFO)
        else:
            raise exceptions.VRouterOperationError(
                ip_address=self.host,
                reason='External gateway not already configured')

        # Execute the configuration commands
        self.run_multiple(cmd_list)

    def delete_system_gateway(self, cmd_list, gateway_ip):
        cmd_list.append(VyattaDeleteAPICall("protocols/static/route/{0}".
                                            format(quote_plus('0.0.0.0/0'))))

    def delete_external_gateway_if(self, cmd_list, gw_info):
        self.delete_system_gateway(cmd_list,
                                   gw_info.get_gateway_ip())
        self.delete_ethernet_if(cmd_list,
                                gw_info.get_ethernet_if_id(),
                                gw_info.get_ip_address(),
                                self._EXTERNAL_GATEWAY_DESCR)
        for nat_rule in self._ROUTER_IF_SUBNET_DICT.values():
            self.delete_snat_rule(cmd_list, nat_rule)

    def get_gw_interface_info(self, external_gateway_info):
        (gw_ip_address,
         gw_if_id) = self.get_ethernet_if_info(external_gateway_info)
        gw_gateway_ip = external_gateway_info[self.IF_GATEWAY_IP]
        given_gw_info = InterfaceInfo(gw_if_id, gw_ip_address, gw_gateway_ip)
        return given_gw_info

    def update_gw_config_on_change(self, given_gw_info, cmd_list):
        # Check if the external gw info is already cached.
        # If the given external gw info is not equal to cached gw info
        # then we need to update the existing gw info.
        # So, clear old gw info and set new gw info.
        if (self._EXTERNAL_GW_INFO is not None and
                    given_gw_info != self._EXTERNAL_GW_INFO):
            LOG.debug("Vyatta vRouter REST API: Cached Gateway info is "
                      "not the same as given gateway info")
            self.delete_external_gateway_if(
                cmd_list, self._EXTERNAL_GW_INFO)

        nat_rules = self.set_external_gateway_if(
            cmd_list, given_gw_info)

        # Execute the configuration commands
        self.run_multiple(cmd_list)

        return nat_rules

    def set_external_gateway_if(self, cmd_list, gw_info):
        # Set the external gateway ip address
        self.set_ethernet_if(cmd_list,
                             gw_info.get_ethernet_if_id(),
                             gw_info.get_ip_address(),
                             self._EXTERNAL_GATEWAY_DESCR)

        self.set_system_gateway(cmd_list, gw_info.get_gateway_ip())

        # Add NAT rules for the existing router interfaces
        nat_rules = {}
        for router_if_subnet in self._ROUTER_IF_SUBNET_DICT.keys():
            if netaddr.IPNetwork(router_if_subnet).version != 4:
                continue

            rule_num = self.add_snat_rule_for_router_if(
                cmd_list, router_if_subnet, gw_info)
            nat_rules[router_if_subnet] = rule_num

        return nat_rules

    def set_system_gateway(self, cmd_list, gateway_ip):

        cmd_list.append(VyattaSetAPICall("protocols/static/route/{0}/next-hop/{1}"
                                         .format(quote_plus('0.0.0.0/0'),
                                                 quote_plus(gateway_ip))))

    def update_gw_cache_info(self, given_gw_info, nat_rules):
        self._EXTERNAL_GW_INFO = given_gw_info
        for router_if_subnet, rule_num in six.iteritems(nat_rules):
            self._ROUTER_IF_SUBNET_DICT[router_if_subnet] = rule_num

    def get_next_nat_floating_ip_rule_num(self):
        """Returns the next NAT rule number for floating ip."""

        if (self._NAT_FLOATING_IP_RULE_NUM >=
                self._MAX_NAT_FLOATING_IP_RULE_NUM):
            raise exceptions.VRouterOperationError(
                ip_address=self.host,
                reason='Max NAT Floating IP rule count reached')

        self._NAT_FLOATING_IP_RULE_NUM += 1
        return self._NAT_FLOATING_IP_RULE_NUM


class RouterProcessor(GatewayProcessor):

    @property
    def forwarding_is_enabled(self):
        """Retrieves Admin State."""
        output = self.show("ip/forwarding")
        LOG.info('Vyatta vRouter status : %s', output)
        return "IP forwarding is on" in output

    def set_router_name(self, cmd_list, router_name):
        if '_' in router_name:
            router_name = router_name.replace('_', '-')

        cmd_list.append(VyattaSetAPICall("system/host-name/{0}".
                        format(quote_plus(router_name))))

    def set_admin_state(self, cmd_list, admin_state):

        if admin_state:
            if not self.forwarding_is_enabled:
                cmd_list.append(VyattaDeleteAPICall("system/ip/disable-forwarding"))
        else:
            if self.forwarding_is_enabled:
                cmd_list.append(VyattaSetAPICall("system/ip/disable-forwarding"))

    def update_static_routes(self, routes_add, routes_del):
        def _get_route_type(dest):
            ip = netaddr.IPNetwork(rule.dest_cidr)
            if ip.version == 4:
                return 'route'
            else:
                return 'route6'

        cmd_list = []
        for rule in routes_add:
            cmd_list.append(VyattaSetAPICall(
                'protocols/static/{0}/{1}/next-hop/{2}'.format(
                    _get_route_type(rule.dest_cidr),
                    quote_plus(rule.dest_cidr),
                    quote_plus(rule.next_hop))))

        for rule in routes_del:
            cmd_list.append(VyattaDeleteAPICall(
                'protocols/static/{0}/{1}'.format(
                    _get_route_type(rule.dest_cidr),
                    quote_plus(rule.dest_cidr))))

        self.run_multiple(cmd_list)
