#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
#
# Checks based on the Phion-MIB for the Barracuda CloudGen Firewall.
#
# Copyright (C) 2021  Marius Rieder <marius.rieder@scs.ch>
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

# Example excerpt from SNMP data:
# .1.3.6.1.4.1.10704.1.11 47 --> PHION-MIB::vpnUsers

from cmk.agent_based.v2 import (
    SNMPTree,
    SimpleSNMPSection,
    CheckPlugin,
    exists,
    Service,
    check_levels,
    StringTable
)

Section = int | None


def parse_phion_vpnusers(string_table: StringTable) -> Section:
    if not string_table:
        return None
    return int(string_table[0][0])


snmp_section_phion_vpnusers = SimpleSNMPSection(
    name='phion_vpnusers',
    detect=exists('.1.3.6.1.4.1.10704.1.2'),
    fetch=SNMPTree(
        base='.1.3.6.1.4.1.10704.1',
        oids=[
            '11',  # PHION-MIB::vpnUsers
        ],
    ),
    parse_function=parse_phion_vpnusers,
)


def discovery_phion_vpnusers(section: Section):
    if section:
        yield Service()


def check_phion_vpnusers(params, section: Section):
    if section:
        yield from check_levels(
            section,
            levels_upper=params.get('users', None),
            label='VPN Users',
            metric_name='users',
            render_func=lambda v: "%d" % v
        )


check_plugin_phion_firewall = CheckPlugin(
    name='phion_vpnusers',
    service_name='VPN Users',
    discovery_function=discovery_phion_vpnusers,
    check_function=check_phion_vpnusers,
    check_ruleset_name='phion_vpnusers',
    check_default_parameters={},
)
