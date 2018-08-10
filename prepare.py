#!/usr/bin/env python3

"""
Zabbix vulnerability assessment plugin.

Script will create these objects in Zabbix using the API:
    - A template; through which data will be collected from the servers.
    - Zabbix hosts; for obtaining data on vulnerabilities.
    - Dashboard; for their display.
    - Action; for run the command fixes the vulnerability.
"""

__author__ = 'samosvat'
__version__ = '1.3.3'


import sys
import argparse
import subprocess
from datetime import datetime, timedelta
from random import randint

from pyzabbix import ZabbixAPI

from readconfig import *


parser = argparse.ArgumentParser(description='Zabbix Threat Control - vulnerability assessment plugin')


parser.add_argument(
    '-u', '--utils',
    help='check zabbix-sender and zabbix-get settings',
    action='store_true')

parser.add_argument(
    '-v', '--vhosts',
    help='create the Virtual ZTC hosts in zabbix',
    action='store_true')

parser.add_argument(
    '-t', '--template',
    help='create the ZTC Template in zabbix',
    action='store_true')

parser.add_argument(
    '-d', '--dashboard',
    help='create the ZTC Dashboard in zabbix',
    action='store_true')

parser.add_argument(
    '-a', '--action',
    help='create the ZTC Action in zabbix',
    action='store_true')

args = parser.parse_args()


timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

host_start_time = datetime.now() + timedelta(minutes=randint(60, 1380))
ztc_start_time = (host_start_time + timedelta(minutes=10))
delay_report = host_start_time.strftime('0;wd1-7h%Hm%M')
delay_ztc = ztc_start_time.strftime('0;wd1-7h%Hm%M')

required_zapi_ver = 3.4


def check_zutils(check_type, host_conn):
    if check_type == 'agent':
        check_key = 'CheckRemoteCommand'
        cmd = '{z_get_bin} -s {host_conn} -k  system.run["echo {check_key}"]'.format(z_get_bin=z_get_bin, host_conn=host_conn, check_key=check_key)
    elif check_type == 'server':
        check_key = '"response":"success"'
        cmd = '{z_sender_bin} -z {host_conn} -p {port} -s zabbix_sender_ztc_test -k zabbix_sender_ztc_test -o 1 -vv'.format(z_sender_bin=z_sender_bin, host_conn=host_conn, port=zbx_server_port, check_key=check_key)
    else:
        return False, 1, 1

    proc = subprocess.Popen(cmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, shell=True)
    out = proc.communicate()[0].decode('utf8')
    exitcode = proc.poll()
    if out.find(check_key) != -1:
        return True, out, exitcode, cmd
    else:
        return False, out, exitcode, cmd


def z_host_create(zbx_host, zbx_vname, group_id, appl_name, lld_name, lld_key, item_proto_name, item_proto_key,
                  trig_proto_expr, trig_proto_descr, trig_proto_url, trig_proto_comm, ):
    try:
        host_id = zapi.host.get(filter={'host': zbx_host, 'name': zbx_vname}, output=['hostid'])[0]['hostid']
        bkp_zbx_host = zbx_host + '.bkp-' + timestamp
        bkp_zbx_vname = zbx_vname + '.bkp-' + timestamp
        zapi.host.update(hostid=host_id, host=bkp_zbx_host, name=bkp_zbx_vname, status=1)
        print('Host "{}" (id: {}) was renamed to "{}" and deactivated.'.format(zbx_vname, host_id, bkp_zbx_vname))
    except Exception:
        host_id = None

    try:
        host_id = zapi.host.create(host=zbx_host, name=zbx_vname, groups=[{'groupid': group_id}],
                                   macros=[{'macro': '{$SCORE.MIN}', 'value': min_cvss}],
                                   interfaces=[
                                       {'type': 1, 'main': 1, 'useip': host_use_ip, 'ip': '127.0.0.1',
                                        'dns': zbx_server_fqdn, 'port': '10050'}])['hostids'][0]
        appl_id = zapi.application.create(name=appl_name, hostid=host_id)['applicationids'][0]
        lld_id = zapi.discoveryrule.create(type=2, hostid=host_id, name=lld_name, key_=lld_key, value_type='4',
                                           trapper_hosts='', units='', lifetime='0')['itemids'][0]
        item_proto_id = zapi.itemprototype.create({'hostid': host_id, 'ruleid': lld_id,
                                                   'name': item_proto_name, 'key_': item_proto_key,
                                                   'delay': '0', 'status': '0', 'type': '2',
                                                   'value_type': '0', 'trapper_hosts': '', 'units': '',
                                                   'interfaceid': '0',
                                                   'port': ''})['itemids'][0]
        zapi.itemprototype.update(itemid=item_proto_id, applications=[appl_id])
        zapi.triggerprototype.create(hostid=host_id, ruleid=lld_id, expression=trig_proto_expr,
                                     description=trig_proto_descr, url=trig_proto_url, manual_close=1,
                                     priority='0', comments=trig_proto_comm, status='0')
        print('Created host "{}" (id: {})\n'.format(zbx_vname, host_id))
        return host_id
    except Exception as e:
        print('Can\'t create host {}. Exception: {}'.format(zbx_host, e))
        exit(1)

if not len(sys.argv) > 1:
    parser.print_help()
    exit(0)

try:
    zapi = ZabbixAPI(zbx_url, timeout=5)
    zapi.session.verify = zbx_verify_ssl
    zapi.login(zbx_user, zbx_pass)
    zapi_ver = zapi.api_version()
    print('Connected to Zabbix API v.{}\n'.format(zapi.api_version()))
    zapi_ver_float = float(zapi_ver.split('.')[0] + '.' + zapi_ver.split('.')[1])
    if zapi_ver_float < required_zapi_ver:
        print('Required Zabbix version {} or higher\nExit.'.format(required_zapi_ver))
        exit(0)
except Exception as e:
    print('Error: Can\'t connect to Zabbix API. Exception: {}'.format(e))
    exit(1)


host_use_ip = 1


# CHECK Z-UTILS
if args.utils:
    print('Checking the connection to the zabbix-agent...')

    za_out = check_zutils('agent', '127.0.0.1')
    if za_out[0] is True:
        print('Сompleted successfully. For connecting with zabbix-agent used address "127.0.0.1"\n')
    else:
        host_use_ip = 0
        za_out = check_zutils('agent', zbx_server_fqdn)
        if za_out[0] is True:
            print('For connecting with zabbix-agent used address "{}"\n'.format(zbx_server_fqdn))
        else:
            print('Error: Can\'t execute remote command on zabbix-agent:\n'
                  'Command: {}\n{}\nPlease fix this for continue!'.format(za_out[3], za_out[1]))
            exit(1)

    print('Checking the connection to the zabbix-server via zabbix_sender...')
    zs_out = check_zutils('server', zbx_server_fqdn)
    if zs_out[0] is True:
        print('Сompleted successfully. For connecting with zabbix-server used address "{}"\n'.format(zbx_server_fqdn))
    else:
        print('Error: Can\'t send data with zabbix-sender:\n'
              'Command: {}\n{}\n\nPlease fix this for continue!'.format(zs_out[3], zs_out[1]))
        exit(1)


# Z-HOSTS
if args.vhosts:
    # HOSTGROUP
    try:
        group_id = zapi.hostgroup.get(filter={'name': group_name}, output=['groupid'])[0]['groupid']
        print('Host group "{}" already exists (id: {}). Use this group.\n'.format(group_name, group_id))
    except IndexError:
        group_id = zapi.hostgroup.create(name=group_name)['groupids'][0]
        print('Created host group "{}" (id: {}).\n'.format(group_name, group_id))
    except Exception as e:
        print('Can\'t create host group "{}". Exception: {}'.format(group_name, e))
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
                             trig_proto_expr='{' + zbx_h_hosts + ':vulners.hosts[{#H.ID}].last()}>={$SCORE.MIN}',
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
                             trig_proto_expr='{' + zbx_h_bulls + ':vulners.bulletin[{#BULLETIN.ID}].last()}>={$SCORE.MIN}',
                             trig_proto_descr='Impact {#BULLETIN.IMPACT}. Score {#BULLETIN.SCORE}. Affected {ITEM.LASTVALUE}. Bulletin = {#BULLETIN.ID}',
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
                            trig_proto_expr='{' + zbx_h_pkgs + ':vulners.pkg[{#PKG.ID}].last()}>={$SCORE.MIN}',
                            trig_proto_descr='Impact {#PKG.IMPACT}. Score {#PKG.SCORE}. Affected {ITEM.LASTVALUE}. Package = {#PKG.ID}',
                            trig_proto_url='https://vulners.com/info/{#PKG.URL}',
                            trig_proto_comm='Vulnerabilities are found on:\r\n\r\n{#PKG.HOSTS}\r\n----\r\n{#PKG.FIX}')

    # STATISTIC
    g1_name = 'Median CVSS Score'
    g2_name = 'CVSS Score ratio by servers'
    colors = ['DD0000', 'EE0000', 'FF3333', 'EEEE00', 'FFFF66', '00EEEE', '00DDDD', '3333FF', '6666FF', '00DD00', '33FF33']

    try:
        host_id = zapi.host.get(filter={'host': zbx_h_stats, 'name': zbx_h_stats_vname},
                                output=['hostid'])[0]['hostid']
        bkp_h_stats = zbx_h_stats + '.bkp-' + timestamp
        bkp_h_stats_vname = zbx_h_stats_vname + '.bkp-' + timestamp
        zapi.host.update(hostid=host_id, host=bkp_h_stats, name=bkp_h_stats_vname, status=1)
        print('Host "{}" (id: {}) was renamed to "{}" and deactivated'.format(zbx_h_stats_vname, host_id,
                                                                              bkp_h_stats_vname))
    except Exception:
        host_id = None

    try:
        host_id = zapi.host.create(host=zbx_h_stats, name=zbx_h_stats_vname, groups=[{'groupid': group_id}],
                                   macros=[{'macro': stats_macros_name, 'value': stats_macros_value}],
                                   interfaces=[
                                       {'type': 1, 'main': 1, 'useip': host_use_ip, 'ip': '127.0.0.1',
                                        'dns': zbx_server_fqdn, 'port': '10050'}])['hostids'][0]

        appl_id = zapi.application.create(name=appl_name, hostid=host_id)['applicationids'][0]

        iface_id = zapi.hostinterface.get(hostids=host_id, output='interfaceid')[0]['interfaceid']

        zapi.item.create(name='Service item for running {$WORK_SCRIPT_CMD}', key_='system.run[{$WORK_SCRIPT_CMD},nowait]',
                         hostid=host_id, type=0, value_type=3, interfaceid=iface_id, applications=[appl_id],
                         delay=delay_ztc)

        zapi.item.create({'name': 'CVSS Score - Total hosts', 'key_': 'vulners.hostsCount', 'hostid': host_id,
                          'type': '2', 'value_type': '3', 'trapper_hosts': '', 'applications': [appl_id]},
                         {'name': 'CVSS Score - Maximum', 'key_': 'vulners.scoreMax', 'hostid': host_id,
                          'type': '2', 'value_type': '0', 'trapper_hosts': '', 'applications': [appl_id]},
                         {'name': 'CVSS Score - Average', 'key_': 'vulners.scoreMean', 'hostid': host_id,
                          'type': '2', 'value_type': '0', 'trapper_hosts': '', 'applications': [appl_id]},
                         {'name': 'CVSS Score - Minimum', 'key_': 'vulners.scoreMin', 'hostid': host_id,
                          'type': '2', 'value_type': '0', 'trapper_hosts': '', 'applications': [appl_id]})

        g1_itemid = zapi.item.create({'name': 'CVSS Score - Median', 'key_': 'vulners.scoreMedian', 'hostid': host_id,
                                      'type': '2', 'value_type': '0', 'trapper_hosts': '', 'applications': [appl_id]})[
            'itemids'][0]

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
            gitems.append({'itemid': graph, 'color': colors[i], 'drawtype': '5', 'calc_fnc': '9'})
            i += 1

        g2_id = zapi.graph.create({'hostids': host_id, 'name': g2_name, 'width': '1000', 'height': '300',
                                   'show_work_period': '0', 'graphtype': '2', 'show_legend': '0', 'show_3d': '1',
                                   'gitems': gitems})['graphids'][0]

        print('Created host "{}" (id: {})\n'.format(zbx_h_stats_vname, host_id))
    except Exception as e:
        print('Can\'t create host "{}". Exception: {}'.format(zbx_h_stats_vname, e))
        exit(1)


# TEMPLATE
if args.template:
    try:
        tmpl_id = zapi.template.get(filter={'host': tmpl_host, 'name': tmpl_name},
                                    output=['templateid'])[0]['templateid']
        bkp_tmpl_host = tmpl_host + '.bkp-' + timestamp
        bkp_tmpl_name = tmpl_name + '.bkp-' + timestamp
        zapi.template.update(templateid=tmpl_id, host=bkp_tmpl_host, name=bkp_tmpl_name)
        print('Template "{}" (id: {}) was renamed to "{}"'.format(tmpl_name, tmpl_id, bkp_tmpl_name))
    except Exception:
        tmpl_id = None

    try:
        tmpl_groupid = zapi.hostgroup.get(filter={'name': tmpl_group_name}, output=['groupid'])[0]['groupid']
        tmpl_id = zapi.template.create(groups={'groupid': tmpl_groupid},
                                       macros=[{'macro': tmpl_macros_name, 'value': tmpl_macros_value}],
                                       host=tmpl_host, name=tmpl_name)['templateids'][0]
        tmpl_app_id = zapi.application.create(name=tmpl_appl_name, hostid=tmpl_id)['applicationids'][0]

        zapi.item.create(name='OS - Name', key_='system.run[{$REPORT_SCRIPT_PATH} os]', hostid=tmpl_id, type=0,
                         value_type=1, interfaceid='0', applications=[tmpl_app_id], delay=delay_report)

        zapi.item.create(name='OS - Version', key_='system.run[{$REPORT_SCRIPT_PATH} version]', hostid=tmpl_id, type=0,
                         value_type=1, interfaceid='0', applications=[tmpl_app_id], delay=delay_report)

        zapi.item.create(name='OS - Packages', key_='system.run[{$REPORT_SCRIPT_PATH} package]', hostid=tmpl_id, type=0,
                         value_type=4, interfaceid='0', applications=[tmpl_app_id], delay=delay_report)

        print('Created template "{}" (id: {})\n'.format(tmpl_name, tmpl_id))
    except Exception as e:
        print('Can\'t create template "{}". Exception: {}'.format(tmpl_name, e))
        exit(1)


# ACTION
# todo проверка что созданы хосты (их id нужны для фильтра)
if args.action:
    try:
        action_id = zapi.action.get(filter={'name': action_name}, output=['actionid'])[0]['actionid']
        bkp_action_name = zbx_h_stats + '.bkp-' + timestamp
        zapi.action.update(actionid=action_id, name=bkp_action_name, status=1)
        print('Action "{}" (id: {}) was renamed to "{}" and deactivated.'.format(action_name, action_id, bkp_action_name))
    except Exception:
        action_id = None

    action_id = zapi.action.create(name=action_name, eventsource=0, status=0, esc_period=120,
                                   def_shortdata='{TRIGGER.NAME}: {TRIGGER.STATUS}',
                                   def_longdata='{TRIGGER.NAME}: {TRIGGER.STATUS}',
                                   filter={'evaltype': 0, 'formula': '', 'conditions': [
                                       {'conditiontype': 1, 'operator': 0, 'value': pkgs_id, 'value2': '',
                                        'formulaid': 'A'},
                                       {'conditiontype': 1, 'operator': 0, 'value': hosts_id, 'value2': '',
                                        'formulaid': 'B'}]},
                                   acknowledge_operations=[{'operationtype': 1, 'evaltype': 0,
                                                            'opcommand_hst': [{'hostid': '0'}], 'opcommand_grp': [],
                                                            'opcommand': {
                                                                'type': 0, 'scriptid': 0, 'execute_on': 0, 'port': '',
                                                                'authtype': 0,
                                                                'username': '', 'password': '', 'publickey': '',
                                                                'privatekey': '',
                                                                'command': '/opt/monitoring/zabbix-threat-control/fix.py {HOST.HOST} {TRIGGER.ID} {EVENT.ID}'}}])['actionids'][0]
    print('Created action "{}" (id: {})\n'.format(action_name, action_id))


# DASHBOARD
# todo проверка что созданы хосты (их id нужны для даша)
if args.dashboard:
    w = [{'type': 'problems', 'name': zbx_h_bulls_vname, 'x': '5', 'y': '7', 'width': '7', 'height': '8',
          'fields': [{'type': '0', 'name': 'rf_rate', 'value': '900'}, {'type': '0', 'name': 'show', 'value': '3'},
                     {'type': '0', 'name': 'show_lines', 'value': '100'},
                     {'type': '0', 'name': 'sort_triggers', 'value': '16'},
                     {'type': '3', 'name': 'hostids', 'value': bulls_id}]},
         {'type': 'problems', 'name': zbx_h_pkgs_vname, 'x': '5', 'y': '0', 'width': '7',
          'height': '7',
          'fields': [{'type': '0', 'name': 'rf_rate', 'value': '600'}, {'type': '0', 'name': 'show', 'value': '3'},
                     {'type': '0', 'name': 'show_lines', 'value': '100'},
                     {'type': '0', 'name': 'sort_triggers', 'value': '16'},
                     {'type': '3', 'name': 'hostids', 'value': pkgs_id}]},
         {'type': 'problems', 'name': zbx_h_hosts_vname, 'x': '0', 'y': '7', 'width': '5',
          'height': '8',
          'fields': [{'type': '0', 'name': 'rf_rate', 'value': '600'}, {'type': '0', 'name': 'show', 'value': '3'},
                     {'type': '0', 'name': 'show_lines', 'value': '100'},
                     {'type': '0', 'name': 'sort_triggers', 'value': '16'},
                     {'type': '3', 'name': 'hostids', 'value': hosts_id}]},
         {'type': 'graph', 'name': g1_name, 'x': '2', 'y': '0', 'width': '3', 'height': '7',
          'fields': [{'type': '0', 'name': 'rf_rate', 'value': '600'}, {'type': '0', 'name': 'show_legend', 'value': '0'},
                     {'type': '6', 'name': 'graphid', 'value': g1_id}]},
         {'type': 'graph', 'name': g2_name, 'x': '0', 'y': '0', 'width': '2', 'height': '7',
          'fields': [{'type': '0', 'name': 'rf_rate', 'value': '600'}, {'type': '0', 'name': 'show_legend', 'value': '0'},
                     {'type': '6', 'name': 'graphid', 'value': g2_id}]}]

    try:
        dash_id = zapi.dashboard.get(filter={'name': dash_name}, output=['dashboardid'])[0]['dashboardid']
        bkp_dash_name = dash_name + '_bkp_' + timestamp
        zapi.dashboard.update(dashboardid=dash_id, name=bkp_dash_name)
        print('Dashboard {} (id: {}) was renamed to {}'.format(dash_name, dash_id, bkp_dash_name))
    except Exception:
        dash_id = None

    try:
        dash_id = zapi.dashboard.create(name=dash_name, widgets=w, userGroups=[], users=[], private=0)
        dash_id = dash_id['dashboardids'][0]
        print('Created dashboard "{dash_name}" (id: {dash_id})\n\n'
              'Script "{stats_macros_value}" will be run every day at {time}\n'
              'via the item "Service item..." on the host "{zbx_h_stats_vname}".\n\n'
              'Dashboard URL:\n{zbx_url}/zabbix.php?action=dashboard.view&dashboardid={dash_id}&fullscreen=1\n'
              .format(dash_name=dash_name, dash_id=dash_id, stats_macros_value=stats_macros_value,
                      time=ztc_start_time.strftime('%H:%M'), zbx_h_stats_vname=zbx_h_stats_vname, zbx_url=zbx_url))
    except Exception as e:
        print('Can\'t create dashboard "{}". Exception: {}'.format(dash_name, e))
        exit(1)
