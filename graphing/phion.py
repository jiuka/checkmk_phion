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

from cmk.graphing.v1 import (
    metrics,
    perfometers,
    translations,
)


translation_phion_firewall = translations.Translation(
    name='phion_firewall',
    check_commands=[translations.PassiveCheck('phion_firewall')],
    translations={
        'sessions': translations.RenameTo('phion_firewall_sessions'),
        'traffic': translations.RenameTo('phion_firewall_traffic'),
        'packets': translations.RenameTo('phion_firewall_packets'),
    }
)

translation_phion_vpnusers = translations.Translation(
    name='phion_vpnusers',
    check_commands=[translations.PassiveCheck('phion_vpnusers')],
    translations={
        'users': translations.RenameTo('phion_vpnusers'),
    }
)

metric_veeam_phion_vpnusers = metrics.Metric(
    name='phion_vpnusers',
    title=metrics.Title('Concurrent VPN Users'),
    unit=metrics.Unit(metrics.DecimalNotation(""), metrics.StrictPrecision(0)),
    color=metrics.Color.BLUE,
)

metric_veeam_phion_firewall_sessions = metrics.Metric(
    name='phion_firewall_sessions',
    title=metrics.Title('Concurrent Sessions'),
    unit=metrics.Unit(metrics.DecimalNotation(""), metrics.StrictPrecision(0)),
    color=metrics.Color.BLUE,
)

metric_veeam_phion_firewall_traffic = metrics.Metric(
    name='phion_firewall_traffic',
    title=metrics.Title('Bandwidth'),
    unit=metrics.Unit(metrics.IECNotation("bps")),
    color=metrics.Color.BLUE,
)

metric_veeam_phion_firewall_packets = metrics.Metric(
    name='phion_firewall_packets',
    title=metrics.Title('Packets'),
    unit=metrics.Unit(metrics.DecimalNotation("1/s"), metrics.StrictPrecision(0)),
    color=metrics.Color.GREEN,
)

perfometer_phion_vpnusers = perfometers.Perfometer(
    name='phion_vpnusers',
    focus_range=perfometers.FocusRange(perfometers.Closed(0), perfometers.Open(10)),
    segments=['phion_vpnusers'],
)

perfometer_phion_firewall = perfometers.Stacked(
    name='phion_firewall',
    upper=perfometers.Perfometer(
        name='phion_firewall_sessions',
        focus_range=perfometers.FocusRange(perfometers.Closed(0), perfometers.Open(10)),
        segments=['phion_firewall_sessions'],
    ),
    lower=perfometers.Perfometer(
        name='phion_firewall_traffic',
        focus_range=perfometers.FocusRange(perfometers.Closed(0), perfometers.Open(10)),
        segments=['phion_firewall_traffic'],
    ),
)
