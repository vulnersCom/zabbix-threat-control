#!/usr/bin/env python3

from datetime import datetime
from pyzabbix import ZabbixAPI, ZabbixAPIException

from zbxvulners_settings import *


timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')


def z_host_create(zbx_host, zbx_vname, group_id, appl_name, lld_name, lld_key, item_proto_name, item_proto_key,
                  trig_proto_expr, trig_proto_descr, trig_proto_url, trig_proto_comm, ):
    try:
        host_id = zapi.host.get(filter={"host": zbx_host, "name": zbx_vname}, output=['hostid'])[0]['hostid']
        bkp_zbx_host = zbx_host + '.bkp-' + timestamp
        bkp_zbx_vname = zbx_vname + '.bkp-' + timestamp
        zapi.host.update(hostid=host_id, host=bkp_zbx_host, name=bkp_zbx_vname)
        print(f'Host "{zbx_vname}" (id: {host_id}) was renamed to "{bkp_zbx_vname}"')
    except Exception:
        host_id = None

    try:
        host_id = zapi.host.create(host=zbx_host, name=zbx_vname, groups=[{'groupid': group_id}],
                                   macros=[{'macro': '{$SCORE.MIN}', 'value': 8}],
                                   interfaces=[{"type": 1, "main": 1, "useip": 1, "ip": "127.0.0.1", "dns": "",
                                               "port": "10050"}])['hostids'][0]
        appl_id = zapi.application.create(name=appl_name, hostid=host_id)['applicationids'][0]
        lld_id = zapi.discoveryrule.create(type=2, hostid=host_id, name=lld_name, key_=lld_key, value_type='4',
                                           trapper_hosts='', units='', lifetime='0d')['itemids'][0]
        item_proto_id = zapi.itemprototype.create({'hostid': host_id, 'ruleid': lld_id,
                                                     'name': item_proto_name, 'key_': item_proto_key,
                                                     'delay': '0', 'status': '0', 'type': '2',
                                                     'value_type': '3', 'trapper_hosts': '', 'units': '',
                                                     'interfaceid': '0',
                                                     'port': ''})['itemids'][0]
        zapi.itemprototype.update(itemid=item_proto_id, applications=[appl_id])
        zapi.triggerprototype.create(hostid=host_id, ruleid=lld_id, expression=trig_proto_expr,
                                     description=trig_proto_descr, url=trig_proto_url,
                                     priority="0", comments=trig_proto_comm, status="0")
        print(f'Created host "{zbx_vname}" (id: {host_id})')
        return host_id
    except Exception as e:
        print(f'Can\'t create host {zbx_host}. Exception: {e}')
        exit(1)


try:
    zapi = ZabbixAPI(zbx_url, timeout=5)
    zapi.login(zbx_user, zbx_pass)
    print(f'Connected to Zabbix API v.{zapi.api_version()}')
except Exception as e:
    print(f'Error: {e}')
    exit(1)


# HOSTGROUP
try:
    group_id = zapi.hostgroup.get(filter={"name": group_name}, output=["groupid"])[0]['groupid']
    print(f'Host group "{group_name}" already exists (id: {group_id}).')
except IndexError:
    group_id = zapi.hostgroup.create(name=group_name)['groupids'][0]
    print(f'Created host group "{group_name}" (id: {group_id}).')
except Exception as e:
    print(f'Can\'t create host group "{group_name}". Exception: {e}')
    exit(1)


# TEMPLATE
try:
    tmpl_id = zapi.template.get(filter={"host": tmpl_host, "name": tmpl_name}, output=['templateid'])[0]['templateid']
    bkp_tmpl_host = tmpl_host + '.bkp-' + timestamp
    bkp_tmpl_name = tmpl_name + '.bkp-' + timestamp
    zapi.template.update(templateid=tmpl_id, host=bkp_tmpl_host, name=bkp_tmpl_name)
    print(f'Template "{tmpl_name}" (id: {tmpl_id}) was renamed to "{bkp_tmpl_name}"')
except Exception:
    tmpl_id = None

try:
    tmpl_id = zapi.template.create(groups={"groupid": 1},
                                   macros=[{'macro': tmpl_macros_name, 'value': tmpl_macros_value}],
                                   host=tmpl_host, name=tmpl_name)['templateids'][0]
    tmpl_app_id = zapi.application.create(name=tmpl_appl_name, hostid=tmpl_id)['applicationids'][0]

    zapi.item.create(name="OS - Name", key_="system.run[{$REPORT_SCRIPT_PATH} os]", hostid=tmpl_id, type=0,
                     value_type=4, interfaceid="0", applications=[tmpl_app_id], delay="0;wd1-7h6",
                     inventory_link=5)

    zapi.item.create(name="OS - Version", key_="system.run[{$REPORT_SCRIPT_PATH} version]", hostid=tmpl_id, type=0,
                     value_type=4, interfaceid="0", applications=[tmpl_app_id], delay="0;wd1-7h6",
                     inventory_link=6)

    zapi.item.create(name="OS - Packages", key_="system.run[{$REPORT_SCRIPT_PATH} package]", hostid=tmpl_id, type=0,
                     value_type=4, interfaceid="0", applications=[tmpl_app_id], delay="0;wd1-7h6",
                     inventory_link=17)

    print(f'Created template "{tmpl_name}" (id: {tmpl_id})')
except Exception as e:
    print(f'Can\'t create template "{tmpl_name}". Exception: {e}')
    exit(1)


# HOSTS
hosts_id = z_host_create(zbx_host=zbx_h_hosts,
                         zbx_vname=zbx_h_hosts_vname,
                         group_id=group_id,
                         appl_name=appl_name,
                         lld_name='Hosts',
                         lld_key='vulners.hosts_lld',
                         item_proto_name='CVSS Score on {#H.HOST} [{#H.VNAME}]',
                         item_proto_key='vulners.hosts[{#H.ID}]',
                         trig_proto_expr='{' + zbx_h_hosts + ':vulners.hosts[{#H.ID}].last()}>0 and {#H.SCORE}>={$SCORE.MIN}',
                         trig_proto_descr='Score {#H.SCORE}. Host = {#H.VNAME}',
                         trig_proto_url='',
                         trig_proto_comm='Cumulative fix:\r\n\r\n{#H.FIX}')


# BULLETINS
bulls_id = z_host_create(zbx_host=zbx_h_bulls,
                         zbx_vname=zbx_h_bulls_vname,
                         group_id=group_id,
                         appl_name=appl_name,
                         lld_name='Bulletins',
                         lld_key='vulners.bulletins_lld',
                         item_proto_name='[{#BULLETIN.SCORE}] [{#BULLETIN.ID}] - affected hosts',
                         item_proto_key='vulners.bulletin[{#BULLETIN.ID}]',
                         trig_proto_expr='{' + zbx_h_bulls + ':vulners.bulletin[{#BULLETIN.ID}].last()}>0 and {#BULLETIN.SCORE}>={$SCORE.MIN}',
                         # trig_proto_descr='Impact {#BULLETIN.IMPACT}. Score {#BULLETIN.SCORE}. Affected {ITEM.LASTVALUE}. Bulletin = {#BULLETIN.ID}',
                         trig_proto_descr='Impact {#BULLETIN.IMPACT}. Score {#BULLETIN.SCORE}. Affected {#BULLETIN.AFFECTED}. Bulletin = {#BULLETIN.ID}',
                         trig_proto_url='https://vulners.com/info/{#BULLETIN.ID}',
                         trig_proto_comm='Vulnerabilities are found on:\r\n\r\n{#BULLETIN.HOSTS}')


# PKGS
pkgs_id = z_host_create(zbx_host=zbx_h_pkgs,
                        zbx_vname=zbx_h_pkgs_vname,
                        group_id=group_id,
                        appl_name=appl_name,
                        lld_name='Packages',
                        lld_key='vulners.packages_lld',
                        item_proto_name='[{#PKG.SCORE}] [{#PKG.ID}] - affected hosts',
                        item_proto_key='vulners.pkg[{#PKG.ID}]',
                        trig_proto_expr='{' + zbx_h_pkgs + ':vulners.pkg[{#PKG.ID}].last()}>0 and {#PKG.SCORE}>={$SCORE.MIN}',
                        # trig_proto_descr='Impact {#PKG.IMPACT}. Score {#PKG.SCORE}. Affected {ITEM.LASTVALUE}. Package = {#PKG.ID}',
                        trig_proto_descr='Impact {#PKG.IMPACT}. Score {#PKG.SCORE}. Affected {#PKG.AFFECTED}. Package = {#PKG.ID}',
                        trig_proto_url='https://vulners.com/info/{#PKG.URL}',
                        trig_proto_comm='Vulnerabilities are found on:\r\n\r\n{#PKG.HOSTS}')


# STATISTIC
g1_name = 'CVSS Score - Median'
g2_name = 'CVSS Score on hosts'
colors = ['DD0000', 'EE0000', 'FF3333', 'EEEE00', 'FFFF66', '00EEEE', '00DDDD', '3333FF', '6666FF', '00DD00', '33FF33']

try:
    host_id = zapi.host.get(filter={"host": zbx_h_stats, "name": zbx_h_stats_vname}, output=['hostid'])[0]['hostid']
    bkp_h_stats = zbx_h_stats + '.bkp-' + timestamp
    bkp_h_stats_vname = zbx_h_stats_vname + '.bkp-' + timestamp
    zapi.host.update(hostid=host_id, host=bkp_h_stats, name=bkp_h_stats_vname)
    print(f'Host "{zbx_h_stats_vname}" (id: {host_id}) was renamed to "{bkp_h_stats_vname}"')
except Exception:
    host_id = None

try:
    host_id = zapi.host.create(host=zbx_h_stats, name=zbx_h_stats_vname, groups=[{'groupid': group_id}],
                               macros=[{'macro': stats_macros_name, 'value': stats_macros_value}],
                               interfaces=[{"type": 1, "main": 1, "useip": 0, "ip": "127.0.0.1", "dns": zbx_server, "port": "10050"}])['hostids'][0]

    appl_id = zapi.application.create(name=appl_name, hostid=host_id)['applicationids'][0]

    iface_id = zapi.hostinterface.get(hostids=host_id, output="interfaceid")[0]['interfaceid']

    zapi.item.create(name="Service item for running {$WORK_SCRIPT_CMD}", key_="system.run[{$WORK_SCRIPT_CMD},nowait]",
                     hostid=host_id, type=0, value_type=3, interfaceid=iface_id, applications=[appl_id], delay="0;wd1-7h7")

    zapi.item.create({'name': 'CVSS Score - Total hosts', 'key_': 'vulners.hostsCount', 'hostid': host_id,
                      'type': '2', 'value_type': '3', 'trapper_hosts': '', 'applications': [appl_id]},
                     {'name': 'CVSS Score - Maximum', 'key_': 'vulners.scoreMax', 'hostid': host_id,
                      'type': '2', 'value_type': '3', 'trapper_hosts': '', 'applications': [appl_id]},
                     {'name': 'CVSS Score - Average', 'key_': 'vulners.scoreMean', 'hostid': host_id,
                      'type': '2', 'value_type': '0', 'trapper_hosts': '', 'applications': [appl_id]},
                     {'name': 'CVSS Score - Minimum', 'key_': 'vulners.scoreMin', 'hostid': host_id,
                      'type': '2', 'value_type': '3', 'trapper_hosts': '', 'applications': [appl_id]})

    g1_itemid = zapi.item.create({'name': 'CVSS Score - Median', 'key_': 'vulners.scoreMedian', 'hostid': host_id,
                                  'type': '2', 'value_type': '0', 'trapper_hosts': '', 'applications': [appl_id]})['itemids'][0]

    g2_itemids = zapi.item.create(
        {'name': 'CVSS Score - Hosts with a score ~ 10', 'key_': 'vulners.hostsCountScore10', 'hostid': host_id,
         'type': '2', 'value_type': '3', 'trapper_hosts': '', 'applications': [appl_id]},
        {'name': 'CVSS Score - Hosts with a score ~ 9', 'key_': 'vulners.hostsCountScore9', 'hostid': host_id,
         'type': '2', 'value_type': '3', 'trapper_hosts': '', 'applications': [appl_id]},
        {'name': 'CVSS Score - Hosts with a score ~ 8', 'key_': 'vulners.hostsCountScore8', 'hostid': host_id,
         'type': '2', 'value_type': '3', 'trapper_hosts': '', 'applications': [appl_id]},
        {'name': 'CVSS Score - Hosts with a score ~ 7', 'key_': 'vulners.hostsCountScore7', 'hostid': host_id,
         'type': '2', 'value_type': '3', 'trapper_hosts': '', 'applications': [appl_id]},
        {'name': 'CVSS Score - Hosts with a score ~ 6', 'key_': 'vulners.hostsCountScore6', 'hostid': host_id,
         'type': '2', 'value_type': '3', 'trapper_hosts': '', 'applications': [appl_id]},
        {'name': 'CVSS Score - Hosts with a score ~ 5', 'key_': 'vulners.hostsCountScore5', 'hostid': host_id,
         'type': '2', 'value_type': '3', 'trapper_hosts': '', 'applications': [appl_id]},
        {'name': 'CVSS Score - Hosts with a score ~ 4', 'key_': 'vulners.hostsCountScore4', 'hostid': host_id,
         'type': '2', 'value_type': '3', 'trapper_hosts': '', 'applications': [appl_id]},
        {'name': 'CVSS Score - Hosts with a score ~ 3', 'key_': 'vulners.hostsCountScore3', 'hostid': host_id,
         'type': '2', 'value_type': '3', 'trapper_hosts': '', 'applications': [appl_id]},
        {'name': 'CVSS Score - Hosts with a score ~ 2', 'key_': 'vulners.hostsCountScore2', 'hostid': host_id,
         'type': '2', 'value_type': '3', 'trapper_hosts': '', 'applications': [appl_id]},
        {'name': 'CVSS Score - Hosts with a score ~ 1', 'key_': 'vulners.hostsCountScore1', 'hostid': host_id,
         'type': '2', 'value_type': '3', 'trapper_hosts': '', 'applications': [appl_id]},
        {'name': 'CVSS Score - Hosts with a score ~ 0', 'key_': 'vulners.hostsCountScore0', 'hostid': host_id,
         'type': '2', 'value_type': '3', 'trapper_hosts': '', 'applications': [appl_id]})['itemids']

    g1_id = zapi.graph.create({'hostids': host_id, 'name': g1_name, 'width': '1000', 'height': '300',
                               'show_work_period': '0', 'graphtype': '0', 'show_legend': '0', 'show_3d': '0',
                               'gitems': [{'itemid': g1_itemid, 'color': '00AAAA', 'drawtype': '5'}]})['graphids'][0]

    gitems = list()
    i = 0
    for id in g2_itemids:
        gitems.append({'itemid': id, 'color': colors[i], 'drawtype': '5'})
        i += 1

    g2_id = zapi.graph.create({'hostids': host_id, 'name': g2_name, 'width': '1000', 'height': '300',
                               'show_work_period': '0', 'graphtype': '1', 'show_legend': '1', 'show_3d': '0',
                               'gitems': gitems})['graphids'][0]

    print(f'Created host "{zbx_h_stats_vname}" (id: {host_id})')
except Exception as e:
    print(f'Can\'t create host "{zbx_h_stats_vname}". Exception: {e}')
    exit(1)


# DASHBOARD
widgets = [{'type': 'problems', 'name': zbx_h_bulls_vname, 'x': '5', 'y': '9', 'width': '7', 'height': '9',
            'fields': [{'type': '0', 'name': 'rf_rate', 'value': '600'}, {'type': '0', 'name': 'show', 'value': '3'},
                       {'type': '0', 'name': 'show_lines', 'value': '100'},
                       {'type': '0', 'name': 'sort_triggers', 'value': '16'},
                       {'type': '3', 'name': 'hostids', 'value': bulls_id}]},
           {'type': 'problems', 'name': zbx_h_pkgs_vname, 'x': '5', 'y': '0', 'width': '7', 'height': '9',
            'fields': [{'type': '0', 'name': 'rf_rate', 'value': '600'},
                       {'type': '0', 'name': 'show', 'value': '3'},
                       {'type': '0', 'name': 'show_lines', 'value': '100'},
                       {'type': '0', 'name': 'sort_triggers', 'value': '16'},
                       {'type': '3', 'name': 'hostids', 'value': pkgs_id}]},
           {'type': 'problems', 'name': zbx_h_hosts_vname, 'x': '0', 'y': '9', 'width': '5', 'height': '9',
            'fields': [{'type': '0', 'name': 'rf_rate', 'value': '600'},
                       {'type': '0', 'name': 'show', 'value': '3'},
                       {'type': '0', 'name': 'show_lines', 'value': '100'},
                       {'type': '0', 'name': 'sort_triggers', 'value': '16'},
                       {'type': '3', 'name': 'hostids', 'value': hosts_id}]},
           {'type': 'graph', 'name': g1_name, 'x': '0', 'y': '5', 'width': '5', 'height': '4',
            'fields': [{'type': '0', 'name': 'rf_rate', 'value': '600'},
                       {'type': '6', 'name': 'graphid', 'value': g1_id}]},
           {'type': 'graph', 'name': g2_name, 'x': '0', 'y': '0', 'width': '5', 'height': '5',
            'fields': [{'type': '0', 'name': 'rf_rate', 'value': '600'},
                       {'type': '6', 'name': 'graphid', 'value': g2_id}]}]

try:
    dash_id = zapi.dashboard.get(filter={"name": dash_name}, output=["dashboardid"])[0]['dashboardid']
    bkp_dash_name = dash_name + '_bkp_' + timestamp
    zapi.dashboard.update(dashboardid=dash_id, name=bkp_dash_name)
    print(f'Dashboard {dash_name} (id: {dash_id}) was renamed to {bkp_dash_name}')
except Exception:
    dash_id = None

try:
    dash_id = zapi.dashboard.create(name=dash_name, widgets=widgets, userGroups=[], users=[], private=0)
    dash_id = dash_id['dashboardids'][0]
    print(f'Created dashboard "{dash_name}" (id: {dash_id})')
    print(f'\nDashboard URL:\n{zbx_url}/zabbix.php?action=dashboard.view&dashboardid={dash_id}&fullscreen=1\n')
except Exception as e:
    print(f'Can\'t create dashboard "{dash_name}". Exception: {e}')
    exit(1)
