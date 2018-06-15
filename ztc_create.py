#!/usr/bin/env python3
"""
Zabbix vulnerability assessment plugin.

Script will create these objects in Zabbix using the API:
    - A template; through which data will be collected from the servers.
    - Zabbix hosts; for obtaining data on vulnerabilities.
    - Dashboard; for their display.
"""

from datetime import datetime
from random import randint

from pyzabbix import ZabbixAPI

import ztc_config as c


start_hour = randint(1, 24)
timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')


def z_host_create(zbx_host, zbx_vname, group_id, appl_name, lld_name, lld_key, item_proto_name, item_proto_key,
                  trig_proto_expr, trig_proto_descr, trig_proto_url, trig_proto_comm, ):
    try:
        host_id = zapi.host.get(filter={'host': zbx_host, 'name': zbx_vname}, output=['hostid'])[0]['hostid']
        bkp_zbx_host = zbx_host + '.bkp-' + timestamp
        bkp_zbx_vname = zbx_vname + '.bkp-' + timestamp
        zapi.host.update(hostid=host_id, host=bkp_zbx_host, name=bkp_zbx_vname)
        print('Host "{zbx_vname}" (id: {host_id}) was renamed to "{bkp_zbx_vname}"'
              .format(zbx_vname=zbx_vname, host_id=host_id, bkp_zbx_vname=bkp_zbx_vname))
    except Exception:
        host_id = None

    try:
        host_id = zapi.host.create(host=zbx_host, name=zbx_vname, groups=[{'groupid': group_id}],
                                   macros=[{'macro': '{$SCORE.MIN}', 'value': 8}],
                                   interfaces=[{'type': 1, 'main': 1, 'useip': 1, 'ip': '127.0.0.1', 'dns': '',
                                                'port': '10050'}])['hostids'][0]
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
                                     priority='0', comments=trig_proto_comm, status='0')
        print('Created host "{zbx_vname}" (id: {host_id})'.format(zbx_vname=zbx_vname, host_id=host_id))
        return host_id
    except Exception as e:
        print('Can\'t create host {zbx_host}. Exception: {e}'.format(zbx_host=zbx_host, e=e))
        exit(1)


try:
    zapi = ZabbixAPI(c.zbx_url, timeout=5)
    zapi.session.verify = c.zbx_verify_ssl_certs
    zapi.login(c.zbx_user, c.zbx_pass)
    zapi_ver = zapi.api_version()
    print('Connected to Zabbix API v.{zapi_ver}'.format(zapi_ver=zapi.api_version()))
except Exception as e:
    print('Error: {e}'.format(e=e))
    exit(1)


# HOSTGROUP
try:
    group_id = zapi.hostgroup.get(filter={'name': c.group_name}, output=['groupid'])[0]['groupid']
    print('Host group "{grp_name}" already exists (id: {group_id}).'.format(grp_name=c.group_name, group_id=group_id))
except IndexError:
    group_id = zapi.hostgroup.create(name=c.group_name)['groupids'][0]
    print('Created host group "{grp_name}" (id: {group_id}).'.format(grp_name=c.group_name, group_id=group_id))
except Exception as e:
    print('Can\'t create host group "{grp_name}". Exception: {e}'.format(grp_name=c.group_name, e=e))
    exit(1)


# TEMPLATE
try:
    tmpl_id = zapi.template.get(filter={'host': c.tmpl_host, 'name': c.tmpl_name},
                                output=['templateid'])[0]['templateid']
    bkp_tmpl_host = c.tmpl_host + '.bkp-' + timestamp
    bkp_tmpl_name = c.tmpl_name + '.bkp-' + timestamp
    zapi.template.update(templateid=tmpl_id, host=bkp_tmpl_host, name=bkp_tmpl_name)
    print('Template "{tmpl_name}" (id: {tmpl_id}) was renamed to "{bkp_tmpl_name}"'
          .format(tmpl_name=c.tmpl_name, tmpl_id=tmpl_id, bkp_tmpl_name=bkp_tmpl_name))
except Exception:
    tmpl_id = None

delay_report = '0;wd1-7h{start_hour}'.format(start_hour=start_hour)

try:
    tmpl_id = zapi.template.create(groups={'groupid': 1},
                                   macros=[{'macro': c.tmpl_macros_name, 'value': c.tmpl_macros_value}],
                                   host=c.tmpl_host, name=c.tmpl_name)['templateids'][0]
    tmpl_app_id = zapi.application.create(name=c.tmpl_appl_name, hostid=tmpl_id)['applicationids'][0]

    zapi.item.create(name='OS - Name', key_='system.run[{$REPORT_SCRIPT_PATH} os]', hostid=tmpl_id, type=0,
                     value_type=4, interfaceid='0', applications=[tmpl_app_id], delay=delay_report,
                     inventory_link=5)

    zapi.item.create(name='OS - Version', key_='system.run[{$REPORT_SCRIPT_PATH} version]', hostid=tmpl_id, type=0,
                     value_type=4, interfaceid='0', applications=[tmpl_app_id], delay=delay_report,
                     inventory_link=6)

    zapi.item.create(name='OS - Packages', key_='system.run[{$REPORT_SCRIPT_PATH} package]', hostid=tmpl_id, type=0,
                     value_type=4, interfaceid='0', applications=[tmpl_app_id], delay=delay_report,
                     inventory_link=17)

    print('Created template "{tmpl_name}" (id: {tmpl_id})'.format(tmpl_name=c.tmpl_name, tmpl_id=tmpl_id))
except Exception as e:
    print('Can\'t create template "{tmpl_name}". Exception: {e}'.format(tmpl_name=c.tmpl_name, e=e))
    exit(1)


# HOSTS
hosts_id = z_host_create(zbx_host=c.zbx_h_hosts,
                         zbx_vname=c.zbx_h_hosts_vname,
                         group_id=group_id,
                         appl_name=c.appl_name,
                         lld_name='Hosts',
                         lld_key='vulners.hosts_lld',
                         item_proto_name='CVSS Score on {#H.HOST} [{#H.VNAME}]',
                         item_proto_key='vulners.hosts[{#H.ID}]',
                         trig_proto_expr='{' + c.zbx_h_hosts + ':vulners.hosts[{#H.ID}].last()}>0 and {#H.SCORE}>={$SCORE.MIN}',
                         trig_proto_descr='Score {#H.SCORE}. Host = {#H.VNAME}',
                         trig_proto_url='',
                         trig_proto_comm='Cumulative fix:\r\n\r\n{#H.FIX}')


# BULLETINS
bulls_id = z_host_create(zbx_host=c.zbx_h_bulls,
                         zbx_vname=c.zbx_h_bulls_vname,
                         group_id=group_id,
                         appl_name=c.appl_name,
                         lld_name='Bulletins',
                         lld_key='vulners.bulletins_lld',
                         item_proto_name='[{#BULLETIN.SCORE}] [{#BULLETIN.ID}] - affected hosts',
                         item_proto_key='vulners.bulletin[{#BULLETIN.ID}]',
                         trig_proto_expr='{' + c.zbx_h_bulls + ':vulners.bulletin[{#BULLETIN.ID}].last()}>0 and {#BULLETIN.SCORE}>={$SCORE.MIN}',
                         trig_proto_descr='Impact {#BULLETIN.IMPACT}. Score {#BULLETIN.SCORE}. Affected {ITEM.LASTVALUE}. Bulletin = {#BULLETIN.ID}',
                         # trig_proto_descr='Impact {#BULLETIN.IMPACT}. Score {#BULLETIN.SCORE}. Affected {#BULLETIN.AFFECTED}. Bulletin = {#BULLETIN.ID}',
                         trig_proto_url='https://vulners.com/info/{#BULLETIN.ID}',
                         trig_proto_comm='Vulnerabilities are found on:\r\n\r\n{#BULLETIN.HOSTS}')


# PKGS
pkgs_id = z_host_create(zbx_host=c.zbx_h_pkgs,
                        zbx_vname=c.zbx_h_pkgs_vname,
                        group_id=group_id,
                        appl_name=c.appl_name,
                        lld_name='Packages',
                        lld_key='vulners.packages_lld',
                        item_proto_name='[{#PKG.SCORE}] [{#PKG.ID}] - affected hosts',
                        item_proto_key='vulners.pkg[{#PKG.ID}]',
                        trig_proto_expr='{' + c.zbx_h_pkgs + ':vulners.pkg[{#PKG.ID}].last()}>0 and {#PKG.SCORE}>={$SCORE.MIN}',
                        trig_proto_descr='Impact {#PKG.IMPACT}. Score {#PKG.SCORE}. Affected {ITEM.LASTVALUE}. Package = {#PKG.ID}',
                        # trig_proto_descr='Impact {#PKG.IMPACT}. Score {#PKG.SCORE}. Affected {#PKG.AFFECTED}. Package = {#PKG.ID}',
                        trig_proto_url='https://vulners.com/info/{#PKG.URL}',
                        trig_proto_comm='Vulnerabilities are found on:\r\n\r\n{#PKG.HOSTS}')


# STATISTIC
g1_name = 'CVSS Score - Median'
g2_name = 'CVSS Score on hosts'
colors = ['DD0000', 'EE0000', 'FF3333', 'EEEE00', 'FFFF66', '00EEEE', '00DDDD', '3333FF', '6666FF', '00DD00', '33FF33']

try:
    host_id = zapi.host.get(filter={'host': c.zbx_h_stats, 'name': c.zbx_h_stats_vname},
                            output=['hostid'])[0]['hostid']
    bkp_h_stats = c.zbx_h_stats + '.bkp-' + timestamp
    bkp_h_stats_vname = c.zbx_h_stats_vname + '.bkp-' + timestamp
    zapi.host.update(hostid=host_id, host=bkp_h_stats, name=bkp_h_stats_vname)
    print('Host "{zbx_h_stats_vname}" (id: {host_id}) was renamed to "{bkp_h_stats_vname}"'
          .format(zbx_h_stats_vname=c.zbx_h_stats_vname, host_id=host_id, bkp_h_stats_vname=bkp_h_stats_vname))
except Exception:
    host_id = None

delay_ztc = '0;wd1-7h{start_hour}m30'.format(start_hour=start_hour)
try:
    host_id = zapi.host.create(host=c.zbx_h_stats, name=c.zbx_h_stats_vname, groups=[{'groupid': group_id}],
                               macros=[{'macro': c.stats_macros_name, 'value': c.stats_macros_value}],
                               interfaces=[{'type': 1, 'main': 1, 'useip': 0, 'ip': '127.0.0.1', 'dns': c.zbx_server, 'port': '10050'}])['hostids'][0]

    appl_id = zapi.application.create(name=c.appl_name, hostid=host_id)['applicationids'][0]

    iface_id = zapi.hostinterface.get(hostids=host_id, output='interfaceid')[0]['interfaceid']

    zapi.item.create(name='Service item for running {$WORK_SCRIPT_CMD}', key_='system.run[{$WORK_SCRIPT_CMD},nowait]',
                     hostid=host_id, type=0, value_type=3, interfaceid=iface_id, applications=[appl_id],
                     delay=delay_ztc)

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
    for graph in g2_itemids:
        gitems.append({'itemid': graph, 'color': colors[i], 'drawtype': '5'})
        i += 1

    g2_id = zapi.graph.create({'hostids': host_id, 'name': g2_name, 'width': '1000', 'height': '300',
                               'show_work_period': '0', 'graphtype': '1', 'show_legend': '1', 'show_3d': '0',
                               'gitems': gitems})['graphids'][0]

    print('Created host "{zbx_h_stats_vname}" (id: {host_id})'
          .format(zbx_h_stats_vname=c.zbx_h_stats_vname, host_id=host_id))
except Exception as e:
    print('Can\'t create host "{zbx_h_stats_vname}". Exception: {e}'.format(zbx_h_stats_vname=c.zbx_h_stats_vname, e=e))
    exit(1)


# DASHBOARD
widgets = [{'type': 'problems', 'name': c.zbx_h_bulls_vname, 'x': '5', 'y': '9', 'width': '7', 'height': '9',
            'fields': [{'type': '0', 'name': 'rf_rate', 'value': '600'}, {'type': '0', 'name': 'show', 'value': '3'},
                       {'type': '0', 'name': 'show_lines', 'value': '100'},
                       {'type': '0', 'name': 'sort_triggers', 'value': '16'},
                       {'type': '3', 'name': 'hostids', 'value': bulls_id}]},
           {'type': 'problems', 'name': c.zbx_h_pkgs_vname, 'x': '5', 'y': '0', 'width': '7', 'height': '9',
            'fields': [{'type': '0', 'name': 'rf_rate', 'value': '600'},
                       {'type': '0', 'name': 'show', 'value': '3'},
                       {'type': '0', 'name': 'show_lines', 'value': '100'},
                       {'type': '0', 'name': 'sort_triggers', 'value': '16'},
                       {'type': '3', 'name': 'hostids', 'value': pkgs_id}]},
           {'type': 'problems', 'name': c.zbx_h_hosts_vname, 'x': '0', 'y': '9', 'width': '5', 'height': '9',
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
    dash_id = zapi.dashboard.get(filter={'name': c.dash_name}, output=['dashboardid'])[0]['dashboardid']
    bkp_dash_name = c.dash_name + '_bkp_' + timestamp
    zapi.dashboard.update(dashboardid=dash_id, name=bkp_dash_name)
    print('Dashboard {dash_name} (id: {dash_id}) was renamed to {bkp_dash_name}'
          .format(dash_name=c.dash_name, dash_id=dash_id, bkp_dash_name=bkp_dash_name))
except Exception:
    dash_id = None

try:
    dash_id = zapi.dashboard.create(name=c.dash_name, widgets=widgets, userGroups=[], users=[], private=0)
    dash_id = dash_id['dashboardids'][0]
    print('Created dashboard "{dash_name}" (id: {dash_id})\n\n'
          'Script "{stats_macros_value}" will be run every day at {start_hour}:30\n'
          'via the item "Service item..." on the host "{zbx_h_stats_vname}".\n\n'
          'Dashboard URL:\n{zbx_url}/zabbix.php?action=dashboard.view&dashboardid={dash_id}&fullscreen=1\n'
          .format(dash_name=c.dash_name, dash_id=dash_id, stats_macros_value=c.stats_macros_value,
                  start_hour=start_hour, zbx_h_stats_vname=c.zbx_h_stats_vname, zbx_url=c.zbx_url))
except Exception as e:
    print('Can\'t create dashboard "{dash_name}". Exception: {e}'.format(dash_name=c.dash_name, e=e))
    exit(1)
