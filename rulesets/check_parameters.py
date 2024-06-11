#!/usr/bin/env python
# -*- encoding: utf-8; py-indent-offset: 4 -*-
#
# Copyright (C) 2021-2024  Marius Rieder <marius.rieder@durchmesser.ch>
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

from cmk.rulesets.v1 import Title
from cmk.rulesets.v1.form_specs import (
    DataSize,
    DefaultValue,
    DictElement,
    Dictionary,
    IECMagnitude,
    InputHint,
    Integer,
    LevelDirection,
    LevelsType,
    migrate_to_integer_simple_levels,
    SimpleLevels,
)
from cmk.rulesets.v1.rule_specs import CheckParameters, Topic, HostCondition


def _parameter_form_phion_firewall():
    return Dictionary(
        elements={
            'sessions': DictElement(
                parameter_form=SimpleLevels(
                    title=Title('Levels for concurrent sessions'),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Integer(),
                    migrate=migrate_to_integer_simple_levels,
                    prefill_levels_type=DefaultValue(LevelsType.NONE),
                    prefill_fixed_levels=InputHint(value=(0, 0)),
                ),
                required=False,
            ),
            'packages': DictElement(
                parameter_form=SimpleLevels(
                    title=Title('Levels for rate of packets'),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Integer(unit_symbol='packets / second',),
                    migrate=migrate_to_integer_simple_levels,
                    prefill_levels_type=DefaultValue(LevelsType.NONE),
                    prefill_fixed_levels=InputHint(value=(0, 0)),
                ),
                required=False,
            ),
            'traffic': DictElement(
                parameter_form=SimpleLevels(
                    title=Title('Levels for traffic'),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=DataSize(displayed_magnitudes=IECMagnitude),
                    migrate=migrate_to_integer_simple_levels,
                    prefill_levels_type=DefaultValue(LevelsType.NONE),
                    prefill_fixed_levels=InputHint(value=(0, 0)),
                ),
                required=False,
            ),
        }
    )


rule_spec_phion_firewall = CheckParameters(
    name='phion_firewall',
    topic=Topic.NETWORKING,
    parameter_form=_parameter_form_phion_firewall,
    title=Title('Phion/Barracuda Firewall'),
    condition=HostCondition(),
)


def _parameter_form_phion_vpnusers():
    return Dictionary(
        elements={
            'users': DictElement(
                parameter_form=SimpleLevels(
                    title=Title('Levels for number of Phion VPN Users'),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Integer(),
                    migrate=migrate_to_integer_simple_levels,
                    prefill_levels_type=DefaultValue(LevelsType.NONE),
                    prefill_fixed_levels=InputHint(value=(0, 0)),
                ),
                required=False,
            ),
        }
    )


rule_spec_phion_vpnusers = CheckParameters(
    name='phion_vpnusers',
    topic=Topic.NETWORKING,
    parameter_form=_parameter_form_phion_vpnusers,
    title=Title('Phion/Barracuda VPN Users'),
    condition=HostCondition(),
)
