#!/usr/bin/env python3

"""
Zabbix vulnerability assessment plugin.

Script will create these objects in Zabbix using the API:
    - A template; through which data will be collected from the servers.
    - Zabbix hosts; for obtaining data on vulnerabilities.
    - Dashboard; for their display.
    - Action; for run the command fixes the vulnerability.
"""

__version__ = "2.1"


import sys
import argparse
import subprocess
import config
from time import sleep
from random import randint
from datetime import datetime, timedelta
from pyzabbix import ZabbixAPI


MEDIAN_GRAPH_NAME = "Median CVSS Score"
SCORE_GRAPH_NAME = "CVSS Score ratio by servers"
COLORS = [
    "DD0000",
    "EE0000",
    "FF3333",
    "EEEE00",
    "FFFF66",
    "00EEEE",
    "00DDDD",
    "3333FF",
    "6666FF",
    "00DD00",
    "33FF33",
]

timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
host_start_time = datetime.now() + timedelta(minutes=randint(60, 1380))
ztc_start_time = host_start_time + timedelta(minutes=10)
delay_report = host_start_time.strftime("0;wd1-7h%Hm%M")
delay_ztc = ztc_start_time.strftime("0;wd1-7h%Hm%M")

min_zapi_version = 5.0


def check_zabbix_utils(check_type, host_conn):
    output, exitcode, command = 1, 1, ""
    if check_type == "agent":
        check_key = "CheckRemoteCommand"
        command = (
            "{zabbix_get_bin} "
            "-s {host_conn} "
            '-k system.run["echo {check_key}"]'.format(
                zabbix_get_bin=config.zabbix_get_bin,
                host_conn=host_conn,
                check_key=check_key,
            )
        )
    elif check_type == "server":
        check_key = '"response":"success"'
        command = (
            "{zabbix_sender_bin} "
            "-z {host_conn} "
            "-p {port} "
            "-s zabbix_sender_ztc_test "
            "-k zabbix_sender_ztc_test "
            "-o 1 "
            "-vv".format(
                zabbix_sender_bin=config.zabbix_sender_bin,
                host_conn=host_conn,
                port=config.zbx_server_port,
                check_key=check_key,
            )
        )
    else:
        return False, output, command

    proc = subprocess.Popen(
        command, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, shell=True
    )
    output = proc.communicate()[0].decode("utf8")
    if output.find(check_key) != -1:
        return True, output, command
    else:
        return False, output, command


def create_zbx_host(
    host,
    name,
    group_id,
    app_name,
    lld_name,
    lld_key,
    item_proto_name,
    item_proto_key,
    trig_proto_expression,
    trig_proto_desc,
    trig_proto_url,
    trig_proto_comment,
):

    host_id = get_zabbix_obj('host', {"host": host, "name": name}, 'hostid')
    if host_id:
        host_id = host_id[0]["hostid"]
        bkp_host = host + ".bkp-" + timestamp
        bkp_name = name + ".bkp-" + timestamp
        zapi.host.update(hostid=host_id, host=bkp_host, name=bkp_name, status=1)
        print(
            'Host "{}" (id: {}) was renamed to "{}" and deactivated.'.format(name, host_id, bkp_name)
        )

    host_id = zapi.host.create(
        host=host,
        name=name,
        groups=[{"groupid": group_id}],
        tags=[{"tag": "vulners", "value": app_name}],
        macros=[{"macro": "{$SCORE.MIN}", "value": str(config.min_cvss)}],
        interfaces=[
            {
                "type": 1,
                "main": 1,
                "useip": host_use_ip,
                "ip": "127.0.0.1",
                "dns": config.zbx_server_fqdn,
                "port": "10050",
            }
        ],
    )["hostids"][0]

    lld_id = zapi.discoveryrule.create(
        type=2,
        hostid=host_id,
        name=lld_name,
        key_=lld_key,
        value_type="4",
        trapper_hosts="",
        units="",
        lifetime="0",
    )["itemids"][0]

    zapi.itemprototype.create(
        {
            "hostid": host_id,
            "ruleid": lld_id,
            "name": item_proto_name,
            "key_": item_proto_key,
            "delay": "0",
            "status": "0",
            "type": "2",
            "value_type": "0",
            "trapper_hosts": "",
            "units": "",
            "interfaceid": "0",
            "port": "",
        }
    )

    zapi.triggerprototype.create(
        expression=trig_proto_expression,
        description=trig_proto_desc,
        url=trig_proto_url,
        manual_close=1,
        priority="0",
        comments=trig_proto_comment,
        status="0",
    )
    print('Created host "{}" (id: {})\n'.format(name, host_id))
    return host_id


def check_utils():
    print("Checking the connection to the zabbix-agent...")
    use_ip = True
    successful, out, cmd = check_zabbix_utils("agent", "127.0.0.1")
    if successful:
        print('Сompleted successfully. For connecting with zabbix-agent used address "127.0.0.1"\n')
    else:
        successful, out, cmd = check_zabbix_utils("agent", config.zbx_server_fqdn)
        if successful:
            use_ip = False
            print('For connecting with zabbix-agent used address "{}"\n'.format(config.zbx_server_fqdn))
        else:
            print(
                "Error: Can't execute remote command on zabbix-agent:\n"
                "Command: {}\n{}\nPlease fix this for continue!".format(cmd, out)
            )
            exit(1)

    print("Checking the connection to the zabbix-server via zabbix_sender...")
    successful, out, cmd = check_zabbix_utils("server", config.zbx_server_fqdn)
    if successful:
        print(
            'Сompleted successfully. '
            'For connecting with zabbix-server used address "{}"\n'.format(config.zbx_server_fqdn)
        )
    else:
        print(
            "Error: Can't send data with zabbix-sender:\n"
            "Command: {}\n{}\n\nPlease fix this for continue!".format(cmd, out)
        )
        exit(1)
    return int(use_ip)


def get_zabbix_obj(obj_type, filter_query, id_key, id_only=False):
    zbx_obj = getattr(zapi, obj_type).get(filter=filter_query, output=[id_key])
    if id_only:
        return zbx_obj[-1][id_key]
    return zbx_obj


def create_hosts():
    host_group_id = get_zabbix_obj('hostgroup', {"name": config.group_name}, 'groupid')
    if not host_group_id:
        print('Created host group "{}"\n'.format(config.group_name))
        host_group_id = zapi.hostgroup.create(name=config.group_name)['groupids'][0]
        sleep(5)    # wait until group created
    else:
        print('Host group "{}" already exists. Use this group\n'.format(config.group_name))
        host_group_id = host_group_id[0]["groupid"]

    if zbx_version < 5.4:
        expression = "{{{zabbix_host}:{zabbix_host}[{{{id}}}].last()}} > 0 and {{{score}}} >= {{$SCORE.MIN}}"
    else:
        expression = "last(/{zabbix_host}/{zabbix_host}[{{{id}}}]) > 0 and {{{score}}} >= {{$SCORE.MIN}}"

    create_zbx_host(
        host=config.hosts_host,
        name=config.hosts_name,
        group_id=host_group_id,
        app_name=config.application_name,
        lld_name="Hosts",
        lld_key="vulners.hosts_lld",
        item_proto_name="CVSS Score on {#H.HOST} [{#H.VNAME}]",
        item_proto_key="vulners.hosts[{#H.ID}]",
        trig_proto_expression=expression.format(
            zabbix_host=config.hosts_host, id="#H.ID", score="#H.SCORE"
        ),
        trig_proto_desc="Score {#H.SCORE}. Host = {#H.VNAME}",
        trig_proto_url="",
        trig_proto_comment="Cumulative fix:\r\n\r\n{#H.FIX}",
    )

    create_zbx_host(
        host=config.bulletins_host,
        name=config.bulletins_name,
        group_id=host_group_id,
        app_name=config.application_name,
        lld_name="Bulletins",
        lld_key="vulners.bulletins_lld",
        item_proto_name="[{#BULLETIN.SCORE}] [{#BULLETIN.ID}] - affected hosts",
        item_proto_key="vulners.bulletins[{#BULLETIN.ID}]",
        trig_proto_expression=expression.format(
            zabbix_host=config.bulletins_host, id="#BULLETIN.ID", score="#BULLETIN.SCORE",
        ),
        trig_proto_desc="Impact {#BULLETIN.IMPACT}. Score {#BULLETIN.SCORE}. Affected {ITEM.VALUE}. Bulletin = {#BULLETIN.ID}",
        trig_proto_url="https://vulners.com/info/{#BULLETIN.ID}",
        trig_proto_comment="Vulnerabilities are found on:\r\n\r\n{#BULLETIN.HOSTS}",
    )

    create_zbx_host(
        host=config.packages_host,
        name=config.packages_name,
        group_id=host_group_id,
        app_name=config.application_name,
        lld_name="Packages",
        lld_key="vulners.packages_lld",
        item_proto_name="[{#PKG.SCORE}] [{#PKG.ID}] - affected hosts",
        item_proto_key="vulners.packages[{#PKG.ID}]",
        trig_proto_expression=expression.format(
            zabbix_host=config.packages_host, id="#PKG.ID", score="#PKG.SCORE"
        ),
        trig_proto_desc="Impact {#PKG.IMPACT}. Score {#PKG.SCORE}. Affected {ITEM.VALUE}. Package = {#PKG.ID}",
        trig_proto_url="https://vulners.com/info/{#PKG.URL}",
        trig_proto_comment="Vulnerabilities are found on:\r\n\r\n{#PKG.HOSTS}\r\n----\r\n{#PKG.FIX}",
    )

    statistics_host_id = zapi.host.get(
        filter={"host": config.statistics_host, "name": config.statistics_name},
        output=["hostid"],
    )
    if statistics_host_id:
        statistics_host_id = statistics_host_id[0]["hostid"]
        bkp_h_stats = config.statistics_host + ".bkp-" + timestamp
        bkp_h_stats_vname = config.statistics_name + ".bkp-" + timestamp

        zapi.host.update(
            hostid=statistics_host_id,
            host=bkp_h_stats,
            name=bkp_h_stats_vname,
            status=1,
        )

        print(
            'Host "{}" (id: {}) was renamed to "{}" and deactivated'.format(
                config.statistics_name, statistics_host_id, bkp_h_stats_vname
            )
        )

    statistics_host_id = zapi.host.create(
        host=config.statistics_host,
        name=config.statistics_name,
        groups=[{"groupid": host_group_id}],
        macros=[
            {"macro": config.stats_macros_name, "value": config.stats_macros_value}
        ],
        interfaces=[
            {
                "type": 1,
                "main": 1,
                "useip": host_use_ip,
                "ip": "127.0.0.1",
                "dns": config.zbx_server_fqdn,
                "port": "10050",
            }
        ],
    )["hostids"][0]

    host_interface_id = zapi.hostinterface.get(
        hostids=statistics_host_id, output="interfaceid"
    )[0]["interfaceid"]

    zapi.item.create(
        name="Service item for running {$WORK_SCRIPT_CMD}",
        key_="system.run[{$WORK_SCRIPT_CMD},nowait]",
        hostid=statistics_host_id,
        type=0,
        value_type=3,
        interfaceid=host_interface_id,
        tags=[{"tag": "vulners", "value": config.application_name}],
        delay=delay_ztc,
    )

    zapi.item.create(
        *(
            {
                "name": "CVSS Score - %s" % name,
                "key_": "vulners.%s" % name.replace(" ", ""),
                "hostid": statistics_host_id,
                "type": "2",
                "value_type": "3",
                "trapper_hosts": "",
                "tags": [{"tag": "vulners", "value": config.application_name}],
            }
            for name in ("Total Hosts", "Maximum", "Average", "Minimum")
        )
    )

    median_item_id = zapi.item.create({
        "name": "CVSS Score - Median",
        "key_": "vulners.scoreMedian",
        "hostid": statistics_host_id,
        "type": "2",
        "value_type": "0",
        "trapper_hosts": "",
        "tags": [{"tag": "vulners", "value": config.application_name}],
    })["itemids"][0]

    hosts_cnt_score_item_ids = zapi.item.create(
        *(
            {
                "name": "CVSS Score - Hosts with a score ~ %s" % idx,
                "key_": "vulners.hostsCountScore%s" % idx,
                "hostid": statistics_host_id,
                "type": "2",
                "value_type": "3",
                "trapper_hosts": "",
                "tags": [{"tag": "vulners", "value": config.application_name}],
            }
            for idx in range(11)
        )
    )["itemids"]

    zapi.graph.create({
        "hostids": statistics_host_id,
        "name": MEDIAN_GRAPH_NAME,
        "width": "1000",
        "height": "300",
        "show_work_period": "0",
        "graphtype": "0",
        "show_legend": "0",
        "show_3d": "0",
        "gitems": [
            {"itemid": median_item_id, "color": "00AAAA", "drawtype": "5"}
        ],
    })

    gitems = []

    for idx, item_id in enumerate(hosts_cnt_score_item_ids):
        gitems.append({
            "itemid": item_id,
            "color": COLORS[idx],
            "drawtype": "5",
            "calc_fnc": "9",
        })

    zapi.graph.create({
        "hostids": statistics_host_id,
        "name": SCORE_GRAPH_NAME,
        "width": "1000",
        "height": "300",
        "show_work_period": "0",
        "graphtype": "2",
        "show_legend": "0",
        "show_3d": "1",
        "gitems": gitems,
    })

    print('Created host "{}"\n'.format(config.statistics_name))


def create_dashboard():
    host_id = get_zabbix_obj(
        'host', {'host': config.hosts_host, 'name': config.hosts_name}, 'hostid', True
    )
    bulletins_host_id = get_zabbix_obj(
        'host', {'host': config.bulletins_host, 'name': config.bulletins_name}, 'hostid', True
    )
    packages_host_id = get_zabbix_obj(
        'host', {'host': config.packages_host, 'name': config.packages_name}, 'hostid', True
    )
    median_graph_id = get_zabbix_obj('graph', {'name': MEDIAN_GRAPH_NAME}, 'graphid', True)
    score_graph_id = get_zabbix_obj('graph', {'name': SCORE_GRAPH_NAME}, 'graphid', True)

    widgets = [
        {
            "type": "problems",
            "name": config.bulletins_name,
            "x": "8",
            "y": "8",
            "width": "8",
            "height": "8",
            "fields": [
                {"type": "0", "name": "rf_rate", "value": "900"},
                {"type": "0", "name": "show", "value": "3"},
                {"type": "0", "name": "show_lines", "value": "100"},
                {"type": "0", "name": "sort_triggers", "value": "16"},
                {"type": "3", "name": "hostids", "value": bulletins_host_id},
            ],
        },
        {
            "type": "problems",
            "name": config.packages_name,
            "x": "8",
            "y": "0",
            "width": "8",
            "height": "8",
            "fields": [
                {"type": "0", "name": "rf_rate", "value": "600"},
                {"type": "0", "name": "show", "value": "3"},
                {"type": "0", "name": "show_lines", "value": "100"},
                {"type": "0", "name": "sort_triggers", "value": "16"},
                {"type": "3", "name": "hostids", "value": packages_host_id},
            ],
        },
        {
            "type": "problems",
            "name": config.hosts_name,
            "x": "0",
            "y": "8",
            "width": "8",
            "height": "8",
            "fields": [
                {"type": "0", "name": "rf_rate", "value": "600"},
                {"type": "0", "name": "show", "value": "3"},
                {"type": "0", "name": "show_lines", "value": "100"},
                {"type": "0", "name": "sort_triggers", "value": "16"},
                {"type": "3", "name": "hostids", "value": host_id},
            ],
        },
        {
            "type": "graph",
            "name": MEDIAN_GRAPH_NAME,
            "x": "0",
            "y": "4",
            "width": "8",
            "height": "4",
            "fields": [
                {"type": "0", "name": "rf_rate", "value": "600"},
                {"type": "0", "name": "show_legend", "value": "0"},
                {"type": "6", "name": "graphid", "value": median_graph_id},
            ],
        },
        {
            "type": "graph",
            "name": SCORE_GRAPH_NAME,
            "x": "0",
            "y": "0",
            "width": "8",
            "height": "4",
            "fields": [
                {"type": "0", "name": "rf_rate", "value": "600"},
                {"type": "0", "name": "show_legend", "value": "0"},
                {"type": "6", "name": "graphid", "value": score_graph_id},
            ],
        },
    ]

    dash_id = zapi.dashboard.get(
        filter={"name": config.dash_name}, output=["dashboardid"]
    )
    if dash_id:
        dash_id = dash_id[0]["dashboardid"]
        bkp_dash_name = config.dash_name + "_bkp_" + timestamp
        zapi.dashboard.update(dashboardid=dash_id, name=bkp_dash_name)
        print(
            "Dashboard {} (id: {}) was renamed to {}".format(
                config.dash_name, dash_id, bkp_dash_name
            )
        )

    dash_id = zapi.dashboard.create(
        name=config.dash_name,
        userGroups=[],
        users=[],
        private=0,
        **({"pages": [{"widgets": widgets}]} if zbx_version > 5.0 else {"widgets": widgets}),
    )
    dash_id = dash_id["dashboardids"][0]
    print(
        'Created dashboard "{dash_name}" (id: {dash_id})\n\n'
        'Script "{stats_macros_value}" will be run every day at {time}\n'
        'via the item "Service item..." on the host "{statistics_name}".\n\n'
        "Dashboard URL:\n{zbx_url}/zabbix.php?action=dashboard.view&dashboardid={dash_id}&fullscreen=1\n".format(
            dash_name=config.dash_name,
            dash_id=dash_id,
            stats_macros_value=config.stats_macros_value,
            time=ztc_start_time.strftime("%H:%M"),
            statistics_name=config.statistics_name,
            zbx_url=config.zbx_url,
        )
    )


def create_template():
    template_id = zapi.template.get(
        filter={"host": config.template_host, "name": config.template_name},
        output=["templateid"],
    )
    if template_id:
        template_id = template_id[0]["templateid"]
        bkp_template_host = config.template_host + ".bkp-" + timestamp
        bkp_template_name = config.template_name + ".bkp-" + timestamp
        zapi.template.update(
            templateid=template_id, host=bkp_template_host, name=bkp_template_name
        )
        print(
            'Template "{}" (id: {}) was renamed to "{}"'.format(
                config.template_name, template_id, bkp_template_name
            )
        )
    if zbx_version >= 6.2:
        template_group_id = zapi.templategroup.get(filter={"name": config.template_group_name}, output=["groupid"])
    else:
        template_group_id = zapi.hostgroup.get(filter={"name": config.template_group_name}, output=["groupid"])
    template_group_id = template_group_id[0]["groupid"]

    template_id = zapi.template.create(
        groups={"groupid": template_group_id},
        macros=[
            {
                "macro": config.template_macros_name,
                "value": config.template_macros_value,
            }
        ],
        host=config.template_host,
        name=config.template_name,
    )["templateids"][0]

    for name, arg, value_type in (('Name', 'os', 1), ('Version', 'version', 1), ('Packages', 'package', 4)):
        zapi.item.create(
            name="OS - " + name,
            key_="system.run[{$REPORT_SCRIPT_PATH} %s]" % arg,
            hostid=template_id,
            type=0,
            value_type=value_type,
            interfaceid="0",
            tags=[{"tag": "vulners", "value": config.template_application_name}],
            delay=delay_report,
        )

    print(
        'Created template "{}" (id: {})\n'.format(config.template_name, template_id)
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Creates objects in ZABBIX for  "ZTC ". Usage: ./prepare.py -uvtd'
    )

    parser.add_argument(
        "-u",
        "--utils",
        help="check zabbix-sender and zabbix-get settings",
        action="store_true",
    )

    parser.add_argument(
        "-v",
        "--vhosts",
        help="create the Virtual ZTC hosts in zabbix",
        action="store_true",
    )

    parser.add_argument(
        "-t",
        "--template",
        help="create the ZTC Template in zabbix",
        action="store_true",
    )

    parser.add_argument(
        "-d",
        "--dashboard",
        help="create the ZTC Dashboard in zabbix",
        action="store_true",
    )

    args = parser.parse_args()

    if not len(sys.argv) > 1:
        print(
            "\nYou do not specify the objects that you want to create.\n"
            "Show help: ./prepare.py -h\n"
            "Typical use: ./prepare.py -uvtd"
        )
        exit(0)

    zapi = ZabbixAPI(config.zbx_url, timeout=5)
    zapi.session.verify = config.zbx_verify_ssl
    zapi.login(config.zbx_user, config.zbx_pwd)
    zbx_version = zapi.api_version()

    print("Connected to Zabbix API v.{}\n".format(zapi.api_version()))

    zbx_version = float(".".join(zbx_version.split(".")[:2]))
    if zbx_version < min_zapi_version:
        print("Required Zabbix version {} or higher\nExit.".format(min_zapi_version))
        exit(0)

    host_use_ip = 1
    if args.utils:
        host_use_ip = check_utils()

    if args.vhosts:
        create_hosts()

    if args.template:
        create_template()

    if args.dashboard:
        create_dashboard()
