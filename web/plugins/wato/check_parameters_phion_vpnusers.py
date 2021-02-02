#!/usr/bin/env python
# -*- encoding: utf-8; py-indent-offset: 4 -*-
#
# Copyright (C) 2021  Marius Rieder <marius.rieder@durchmesser.ch>
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

from cmk.gui.i18n import _
from cmk.gui.valuespec import (
    Alternative,
    Dictionary,
    FixedValue,
    Integer,
    Tuple,
)

from cmk.gui.plugins.wato import (
    CheckParameterRulespecWithoutItem,
    rulespec_registry,
    RulespecGroupCheckParametersApplications,
)


def _parameter_valuespec_phion_vpnusers():
    return Dictionary(elements=[
        (
            'users',
            Alternative(
                title=_('Levels for number of Phion VPN Users'),
                elements=[
                    FixedValue(
                        None,
                        title=_('No Levels'),
                        totext=_('Do not impose levels, always be OK'),
                    ),
                    Tuple(
                        title=_('Fixed Levels'),
                        elements=[
                            Integer(
                                title=_('Warning at'),
                            ),
                            Integer(
                                title=_('Critical at'),
                            ),
                        ],
                    ),
                ],
            ),
        ),
    ])


rulespec_registry.register(
    CheckParameterRulespecWithoutItem(
        check_group_name='phion_vpnusers',
        group=RulespecGroupCheckParametersApplications,
        parameter_valuespec=_parameter_valuespec_phion_vpnusers,
        title=lambda: _('Phion/Barracuda VPN Users'),
    )
)
