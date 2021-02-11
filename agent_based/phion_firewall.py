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
# .1.3.6.1.4.1.10704.1.10.1.1.115.8.116.102.97.119.116.83.0 725 --> PHION-MIB::firewallSessions.115.8.116.102.97.119.116.83.0
# .1.3.6.1.4.1.10704.1.10.1.2.115.8.116.102.97.119.116.83.0 2076 --> PHION-MIB::packetThroughput.115.8.116.102.97.119.116.83.0
# .1.3.6.1.4.1.10704.1.10.1.3.115.8.116.102.97.119.116.83.0 458372 --> PHION-MIB::dataThroughput.115.8.116.102.97.119.116.83.0

from .agent_based_api.v1 import (
    register,
    SNMPTree,
    exists,
    Service,
    check_levels,
    render
)


def parse_phion_firewall(string_table):
    return {
        'sessions': int(string_table[0][0]),
        'packages': int(string_table[0][1]),
        'traffic': int(string_table[0][2]),
    }


register.snmp_section(
    name='phion_firewall',
    detect=exists('.1.3.6.1.4.1.10704.1.2'),
    fetch=SNMPTree(
        base='.1.3.6.1.4.1.10704.1.10.1',
        oids=[
            '1',  # PHION-MIB::firewallSessions
            '2',  # PHION-MIB::packetThroughput
            '3',  # PHION-MIB::dataThroughput
        ],
    ),
    parse_function=parse_phion_firewall,
)


def discovery_phion_firewall(section):
    if 'sessions' in section:
        yield Service()


def check_phion_firewall(params, section):
    yield from check_levels(
        section['sessions'],
        levels_upper=params.get('sessions', None),
        label='Concurrent Sessions',
        metric_name='sessions',
        render_func=lambda v: "%d" % v
    )

    yield from check_levels(
        section['packages'],
        levels_upper=params.get('packages', None),
        label='Packet Throughput',
        metric_name='packages',
        render_func=lambda v: "%d/s" % v
    )

    yield from check_levels(
        section['traffic'],
        levels_upper=params.get('traffic', None),
        label='Data Throughput',
        metric_name='traffic',
        render_func=lambda v: render.networkbandwidth(v / 8)
    )


register.check_plugin(
    name='phion_firewall',
    service_name='Firewall',
    discovery_function=discovery_phion_firewall,
    check_function=check_phion_firewall,
    check_ruleset_name='phion_firewall',
    check_default_parameters={},
)
