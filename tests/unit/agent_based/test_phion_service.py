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
from cmk.agent_based.v2 import (
    Result,
    Service,
    State,
)
from cmk_addons.plugins.phion.agent_based import phion_service


@pytest.mark.parametrize('string_table, result', [
    ([], {}),
    ([['BFW1_ACS', '1']], {'BFW1_ACS': 1}),
])
def test_parse_phion_service(string_table, result):
    assert phion_service.parse_phion_service(string_table) == result


@pytest.mark.parametrize('section, result', [
    ({}, []),
    ({'BFW1_ACS': 1}, [Service(item='BFW1_ACS')]),
])
def test_discovery_phion_service(section, result):
    assert list(phion_service.discovery_phion_service(section)) == result


@pytest.mark.parametrize('item, section, result', [
    (
        'FOO',
        {'BFW1_ACS': 1},
        []
    ),
    (
        'BFW1_ACS',
        {'BFW1_ACS': 1},
        [
            Result(state=State.OK, summary='Service BFW1_ACS is up.')
        ]
    ),
    (
        'BFW1_ACS',
        {'BFW1_ACS': 0},
        [
            Result(state=State.CRIT, summary='Service BFW1_ACS is down.')
        ]
    ),
    (
        'BFW1_ACS',
        {'BFW1_ACS': 2},
        [
            Result(state=State.CRIT, summary='Service BFW1_ACS is block.')
        ]
    ),
])
def test_check_phion_service(item, section, result):
    assert list(phion_service.check_phion_service(item, section)) == result
