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

import cmk.utils.render

from cmk.gui.plugins.views.perfometers import (
    perfometers,
    perfometer_logarithmic,
    perfometer_logarithmic_dual_independent,
)


def perfometer_phion_firewall(row, check_command, perf_data):
    for graph in perf_data:
        if graph[0] == "traffic":
            traffic = int(graph[1])
        if graph[0] == "packages":
            packages = int(graph[1])
    h = perfometer_logarithmic_dual_independent(traffic, '#54b948', 10000000, 2,
                                                packages, '#2098cb', 500, 2)

    return "%s/s&nbsp;&nbsp;&nbsp;%s pkt/s" % (cmk.utils.render.fmt_bytes(traffic/8), packages), h


def perfometer_phion_vpnusers(row, check_command, perf_data):
    color = '#80f000'
    return "%d" % int(perf_data[0][1]), perfometer_logarithmic(perf_data[0][1], 50000, 6, color)


perfometers['check_mk-phion_firewall'] = perfometer_phion_firewall
perfometers['check_mk-phion_vpnusers'] = perfometer_phion_vpnusers
