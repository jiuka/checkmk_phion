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

from cmk.gui.plugins.metrics import metric_info, check_metrics, perfometer_info, MB

metric_info["phion_vpnusers"] = {
    "title": _("Concurrent VPN Users"),
    "unit": "count",
    "color": "#1DB1FF",
}

metric_info["phion_firewall_sessions"] = {
    "title": _("Concurrent Sessions"),
    "unit": "count",
    "color": "#1DB1FF",
}

metric_info["phion_firewall_traffic"] = {
    "title": _("Bandwidth"),
    "unit": "bits/s",
    "color": "#0088CE",
}

metric_info["phion_firewall_packets"] = {
    "title": _("Packets"),
    "unit": "1/s",
    "color": "#00e060",
}

check_metrics["check_mk-phion_firewall"] = {
    "sessions": {
        "name": "phion_firewall_sessions",
    },
    "traffic": {
        "name": "phion_firewall_traffic",
    },
    "packets": {
        "name": "phion_firewall_packets",
    },
}

check_metrics["check_mk-phion_vpnusers"] = {
    "users": {
        "name": "phion_vpnusers",
    },
}

perfometer_info.append({
    "type": "logarithmic",
    "metric": "phion_vpnusers",
    "half_value": 10,
    "exponent": 2,
})

perfometer_info.append({
    "type": "stacked",
    "perfometers": [{
        "type": "logarithmic",
        "metric": "phion_firewall_sessions",
        "half_value": 10,
        "exponent": 2,
    }, {
        "type": "logarithmic",
        "metric": "phion_firewall_traffic",
        "half_value": MB,
        "exponent": 2
    }],
})
