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
from cmk.base.plugins.agent_based import phion_vpnusers


@pytest.mark.parametrize('section, result', [
    ([], []),
    ([[24]], [Service()]),
])
def test_discovery_phion_vpnusers(section, result):
    assert list(phion_vpnusers.discovery_phion_vpnusers(section)) == result


@pytest.mark.parametrize('params, section, result', [
    (
        {},
        [[24]],
        [
            Result(state=State.OK, summary='VPN Users: 24'),
            Metric('users', 24.0)
        ]
    ),
    (
        {'users': (30, 40)},
        [[24]],
        [
            Result(state=State.OK, summary='VPN Users: 24'),
            Metric('users', 24.0, levels=(30.0, 40.0))
        ]
    ),
    (
        {'users': (10, 40)},
        [[24]],
        [
            Result(state=State.WARN, summary='VPN Users: 24 (warn/crit at 10/40)'),
            Metric('users', 24.0, levels=(10.0, 40.0))
        ]
    ),
    (
        {'users': (10, 20)},
        [[24]],
        [
            Result(state=State.CRIT, summary='VPN Users: 24 (warn/crit at 10/20)'),
            Metric('users', 24.0, levels=(10.0, 20.0))
        ]
    ),
])
def test_check_phion_vpnusers(params, section, result):
    assert list(phion_vpnusers.check_phion_vpnusers(params, section)) == result
