# -*- encoding: utf-8; py-indent-offset: 4 -*-
#
# phion_service - Checks the number of active VPN users.
#
# Copyright (C) 2020  Marius Rieder <marius.rieder@scs.ch>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# Example excerpt from SNMP data:
# .1.3.6.1.4.1.10704.1.1.1.1.59.8.94.83.38.67.65.70.86 BFW1_ACS --> PHION-MIB::serverServiceName."BFW1_ACS"
# .1.3.6.1.4.1.10704.1.1.1.1.59.8.94.83.38.67.67.87.80 BFW1_FW1 --> PHION-MIB::serverServiceName."BFW1_FW1"
# .1.3.6.1.4.1.10704.1.1.1.1.59.8.94.83.38.67.83.49.78 BFW1_VPN --> PHION-MIB::serverServiceName."BFW1_VPN"
# .1.3.6.1.4.1.10704.1.1.1.2.59.8.94.83.38.67.65.70.86 1 --> PHION-MIB::serverServiceState."BFW1_ACS"
# .1.3.6.1.4.1.10704.1.1.1.2.59.8.94.83.38.67.67.87.80 1 --> PHION-MIB::serverServiceState."BFW1_FW1"
# .1.3.6.1.4.1.10704.1.1.1.2.59.8.94.83.38.67.83.49.78 1 --> PHION-MIB::serverServiceState."BFW1_VPN"

from .agent_based_api.v1 import (
    register,
    SNMPTree,
    exists,
    Service,
    Result,
    State,
)


def parse_phion_service(string_table):
    return {entry[0]: int(entry[1]) for entry in string_table}


register.snmp_section(
    name='phion_service',
    detect=exists('.1.3.6.1.4.1.10704.1.2'),
    fetch=SNMPTree(
        base='.1.3.6.1.4.1.10704.1.1.1',
        oids=[
            '1',  # PHION-MIB::serverServiceName
            '2',  # PHION-MIB::serverServiceState
        ],
    ),
    parse_function=parse_phion_service,
)

SERVICESTATEMAP = {
    0: 'down',
    2: 'block',
    3: 'wild',
    4: 'removed',
}


def discovery_phion_service(section):
    for service in section.keys():
        yield Service(item=service)


def check_phion_service(item, section):
    if item not in section:
        yield Result(state=State.UNKNOWN, summary='Service %s not found.' % item)
        return

    if section[item] == 1:
        yield Result(state=State.OK, summary='Service %s is up.' % item)
    else:
        yield Result(state=State.CRIT, summary='Service %s is %s.' % (item, SERVICESTATEMAP[section[item]]))


register.check_plugin(
    name='phion_service',
    service_name='Service %s',
    discovery_function=discovery_phion_service,
    check_function=check_phion_service,
)
