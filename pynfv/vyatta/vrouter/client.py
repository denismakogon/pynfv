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


import logging
import netaddr
import requests

from pynfv.common import restconf_client
from pynfv.common import utils
from pynfv.vyatta.vrouter import config
from pynfv.vyatta.vrouter import exceptions
from pynfv.vyatta.vrouter import processor


LOG = logging.getLogger(__name__)


class vRouterAPIMixin(restconf_client.RESTconfResourceClient,
                      processor.vRouterCachedState):

    def __init__(self, user, password, host, **kwargs):
        super(vRouterAPIMixin, self).__init__(
            user, password, host, skip_auth=True, **kwargs)
        self.vrouter_model = self.process_vrouter_model(self.show('version'))
        self._sync_cache(self.vrouter_model, self.show("configuration/all"),
                         self.vr_model, self.vse_model)

    def show(self, route):
        urlpath = '/rest/op/show/{0}'.format(route)
        response = self.post(urlpath=urlpath)
        location = response.headers['Location']
        if location is None:
            raise exceptions.VRouterOperationError(
                ip_address=self.host,
                reason='REST API Operation URL is empty')
        output = []
        while True:
            response = self.get(location)
            if response.status_code == requests.codes.GONE:
                break
            if response.text:
                output.append(response.text)
        self.delete(location)
        LOG.debug('API output: %s', ''.join(output))
        return ''.join(output)

    def run_multiple(self, user_cmd_list):
        response = self.post("rest/conf")

        config_url = response.headers['Location']
        if config_url is None:
            raise exceptions.VRouterOperationError(
                ip_address=self.host,
                reason='REST API configuration URL is null')

        for user_cmd in user_cmd_list:
            url = user_cmd.make_url(config_url)
            LOG.debug(
                "Vyatta vRouter REST API: Config command %s", url)
            self.put(url)
        self.post(config_url + "/commit")
        LOG.debug("Vyatta vRouter REST API: %s/commit", config_url)
        self.post(config_url + "/save")
        LOG.debug("Vyatta vRouter REST API: %s/save", config_url)
        self.delete(config_url)


class RouterAPI(vRouterAPIMixin, processor.RouterProcessor):

    def init_router(self, router_name, admin_state_up,
                    task_retries=1, task_retry_interval=1):
        api_sequence = []

        self.set_router_name(api_sequence, router_name)
        self.set_admin_state(api_sequence, admin_state_up)

        utils.retry(
            self.run_multiple,
            args=(api_sequence,),
            exceptions=(exceptions.VRouterOperationError,),
            task_retries=task_retries,
            task_retry_interval=task_retry_interval)

    def update_router(self, router_name=None,
                      admin_state_up=None,
                      external_gateway_info=None):
        cmd_list = []

        if router_name:
            self.set_router_name(cmd_list, router_name)

        if admin_state_up is not None:
            self.set_admin_state(cmd_list, admin_state_up)

        if external_gateway_info is not None:
            given_gw_info = self.get_gw_interface_info(external_gateway_info)
            nat_rules = self.update_gw_config_on_change(given_gw_info,
                                                        cmd_list)
            self.update_gw_cache_info(given_gw_info, nat_rules)
        else:
            self.clear_gateway_configuration(cmd_list)
            self.clear_cached_gateway_info()

    def add_interface_to_router(self, interface_info):
        (if_ip_address,
         eth_if_id) = self.get_ethernet_if_info(interface_info)

        cmd_list = []
        self.set_ethernet_if(cmd_list,
                             eth_if_id,
                             if_ip_address,
                             self._ROUTER_INTERFACE_DESCR)

        ip_network = netaddr.IPNetwork(if_ip_address)
        router_if_subnet = str(ip_network.cidr)
        rule_num = None
        if ip_network.version == 4 and self._EXTERNAL_GW_INFO is not None:
            rule_num = self.add_snat_rule_for_router_if(
                cmd_list, router_if_subnet, self._EXTERNAL_GW_INFO)

        self.run_multiple(cmd_list)
        if router_if_subnet not in self._ROUTER_IF_SUBNET_DICT:
            self._ROUTER_IF_SUBNET_DICT[router_if_subnet] = None

        if self._EXTERNAL_GW_INFO is not None:
            self._ROUTER_IF_SUBNET_DICT[router_if_subnet] = rule_num

    def remove_interface_from_router(self, interface_info):
        (if_ip_address,
         eth_if_id) = self.get_ethernet_if_info(interface_info)

        cmd_list = []
        self.delete_ethernet_if(cmd_list,
                                eth_if_id,
                                if_ip_address,
                                self._ROUTER_INTERFACE_DESCR)
        router_if_subnet = self._get_subnet_from_ip_address(if_ip_address)
        if router_if_subnet in self._ROUTER_IF_SUBNET_DICT:
            nat_rule = self._ROUTER_IF_SUBNET_DICT[router_if_subnet]
            if nat_rule is not None:
                self.delete_snat_rule(cmd_list, nat_rule)

        self.run_multiple(cmd_list)
        self._ROUTER_IF_SUBNET_DICT.pop(router_if_subnet, None)

    def get_config(self):
        raw_config = self.show('configuration/all')
        return config.RouterConfig.from_string(raw_config)

    def update_interface(self, interface_info):
        if_name = self.get_ethernet_if_id(interface_info.mac_address)
        router_config = self.get_config()
        if_config = router_config.find_interface(if_name)

        old_addrs = set(netaddr.IPNetwork(ip)
                        for ip in if_config.getlist('address'))
        new_addrs = set(interface_info.ip_addresses)

        cmd_list = []

        for ip in old_addrs - new_addrs:
            self.delete_ethernet_ip(cmd_list, if_name, str(ip))
            # TODO(asaprykin): Configure SNAT

        for ip in new_addrs - old_addrs:
            self.set_ethernet_ip(cmd_list, if_name, str(ip))
            # TODO(asaprykin): Configure SNAT

        self.run_multiple(cmd_list)

    def assign_floating_ip(self, floating_ip, fixed_ip):

        if self._EXTERNAL_GW_INFO is None:
            raise exceptions.VRouterOperationError(
                ip_address=self.host,
                reason='External gateway not configured')

        cmd_list = []

        ext_if_id = self._EXTERNAL_GW_INFO.get_ethernet_if_id()

        # Get the next NAT rule number and add the NAT rule
        nat_rule_num = self.get_next_nat_floating_ip_rule_num()
        self.add_snat_rule(cmd_list, nat_rule_num, ext_if_id,
                           fixed_ip, floating_ip)
        self.add_dnat_rule(cmd_list, nat_rule_num, ext_if_id,
                           floating_ip, fixed_ip)

        # Set the floating ip in external gateway interface
        gw_net = netaddr.IPNetwork(self._EXTERNAL_GW_INFO.get_ip_address())
        self.set_ethernet_ip(
            cmd_list, self._EXTERNAL_GW_INFO.get_ethernet_if_id(),
            '{0}/{1}'.format(floating_ip, gw_net.prefixlen))

        self.run_multiple(cmd_list)

        # Store SNAT and DNAT rule in cache
        dict_key = self._get_floating_ip_key(floating_ip, fixed_ip)
        self._FLOATING_IP_DICT[dict_key] = nat_rule_num

    def unassign_floating_ip(self, floating_ip, fixed_ip):

        if self._EXTERNAL_GW_INFO is None:
            raise exceptions.VRouterOperationError(
                ip_address=self.host,
                reason='External gateway not configured')

        cmd_list = []

        # Check the cache for nat rules
        dict_key = self._get_floating_ip_key(floating_ip, fixed_ip)
        if dict_key in self._FLOATING_IP_DICT:

            # Get the NAT rules from the cache and delete them
            nat_rule = self._FLOATING_IP_DICT[dict_key]
            self.delete_snat_rule(cmd_list, nat_rule)
            self.delete_dnat_rule(cmd_list, nat_rule)

            # Delete the floating ip in external gateway interface
            gw_net = netaddr.IPNetwork(self._EXTERNAL_GW_INFO.get_ip_address())
            self.delete_ethernet_ip(
                cmd_list, self._EXTERNAL_GW_INFO.get_ethernet_if_id(),
                '{0}/{1}'.format(floating_ip, gw_net.prefixlen))
        else:
            raise exceptions.VRouterOperationError(
                ip_address=self.host,
                reason='NAT rule not found for floating ip {0}'
                .format(floating_ip))

        self.run_multiple(cmd_list)

        if dict_key in self._FLOATING_IP_DICT:
            self._FLOATING_IP_DICT.pop(dict_key)
