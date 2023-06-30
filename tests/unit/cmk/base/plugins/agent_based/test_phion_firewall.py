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
#

import pytest  # type: ignore[import]
from cmk.base.plugins.agent_based.agent_based_api.v1 import (
    Metric,
    Result,
    Service,
    State,
)
from cmk.base.plugins.agent_based import phion_firewall


@pytest.mark.parametrize('string_table, result', [
    ([], {}),
    ([[10, 20, 30]], {'sessions': 10, 'packages': 20, 'traffic': 30}),
])
def test_parse_phion_firewall(string_table, result):
    assert phion_firewall.parse_phion_firewall(string_table) == result


@pytest.mark.parametrize('section, result', [
    ({}, []),
    ({'sessions': 10, 'packages': 20, 'traffic': 30}, [Service()]),
])
def test_discovery_phion_firewall(section, result):
    assert list(phion_firewall.discovery_phion_firewall(section)) == result


@pytest.mark.parametrize('param, section, result', [
    (
        {},
        {'sessions': 10, 'packages': 20, 'traffic': 30},
        [
            Result(state=State.OK, summary='Concurrent Sessions: 10'),
            Metric('sessions', 10.0),
            Result(state=State.OK, summary='Packet Throughput: 20/s'),
            Metric('packages', 20.0),
            Result(state=State.OK, summary='Data Throughput: 30.0 Bit/s'),
            Metric('traffic', 30.0)
        ]
    ),
    (
        {'sessions': (20, 30), 'packages': (30, 40), 'traffic': (40, 50)},
        {'sessions': 10, 'packages': 20, 'traffic': 30},
        [
            Result(state=State.OK, summary='Concurrent Sessions: 10'),
            Metric('sessions', 10.0, levels=(20.0, 30.0)),
            Result(state=State.OK, summary='Packet Throughput: 20/s'),
            Metric('packages', 20.0, levels=(30.0, 40.0)),
            Result(state=State.OK, summary='Data Throughput: 30.0 Bit/s'),
            Metric('traffic', 30.0, levels=(40.0, 50.0))
        ]
    ),
    (
        {'sessions': (0, 30), 'packages': (10, 40), 'traffic': (20, 50)},
        {'sessions': 10, 'packages': 20, 'traffic': 30},
        [
            Result(state=State.WARN, summary='Concurrent Sessions: 10 (warn/crit at 0/30)'),
            Metric('sessions', 10.0, levels=(0.0, 30.0)),
            Result(state=State.WARN, summary='Packet Throughput: 20/s (warn/crit at 10/s/40/s)'),
            Metric('packages', 20.0, levels=(10.0, 40.0)),
            Result(state=State.WARN, summary='Data Throughput: 30.0 Bit/s (warn/crit at 20.0 Bit/s/50.0 Bit/s)'),
            Metric('traffic', 30.0, levels=(20.0, 50.0))
        ]
    ),
    (
        {'sessions': (0, 10), 'packages': (10, 20), 'traffic': (20, 30)},
        {'sessions': 10, 'packages': 20, 'traffic': 30},
        [
            Result(state=State.CRIT, summary='Concurrent Sessions: 10 (warn/crit at 0/10)'),
            Metric('sessions', 10.0, levels=(0.0, 10.0)),
            Result(state=State.CRIT, summary='Packet Throughput: 20/s (warn/crit at 10/s/20/s)'),
            Metric('packages', 20.0, levels=(10.0, 20.0)),
            Result(state=State.CRIT, summary='Data Throughput: 30.0 Bit/s (warn/crit at 20.0 Bit/s/30.0 Bit/s)'),
            Metric('traffic', 30.0, levels=(20.0, 30.0))
        ]
    ),
])
def test_check_phion_firewall(param, section, result):
    assert list(phion_firewall.check_phion_firewall(param, section)) == result
