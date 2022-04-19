"""Config reader for ZTC"""

__version__ = '2.0'


import configparser

config = configparser.ConfigParser()
config.read('/opt/monitoring/zabbix-threat-control/ztc.conf')

vuln_api_key = config.get('MANDATORY', 'VulnersApiKey', fallback=None)

zbx_url = config.get('OPTIONAL', 'ZabbixFrontUrl', fallback='http://localhost')
zbx_user = config.get('MANDATORY', 'ZabbixApiUser', fallback=None)
zbx_pwd = config.get('MANDATORY', 'ZabbixApiPassword', fallback=None)
zbx_verify_ssl = config['OPTIONAL'].getboolean('VerifySSL', True)

zbx_server_fqdn = config.get('OPTIONAL', 'ZabbixServerFQDN', fallback='localhost')
zbx_server_port = config['OPTIONAL'].getint('ZabbixServerPort', 10051)

use_zbx_agent_to_fix = config['OPTIONAL'].getboolean('UseZabbixAgentToFix', True)
acknowledge_users = config.get('OPTIONAL', 'TrustedZabbixUsers', fallback='Admin').split(',')
ssh_user = config.get('OPTIONAL', 'SSHUser', fallback='root')

log_file = config.get('OPTIONAL', 'logfile', fallback='/var/log/zabbix-threat-control.log')
debug_level = config['OPTIONAL'].getint('DebugLevel', 1)
work_dir = config.get('OPTIONAL', 'WorkDir', fallback='/opt/monitoring/zabbix-threat-control').rstrip('/')

application_name = config.get('OPTIONAL', 'HostsApplicationName', fallback='Vulnerabilities')

dash_name = config.get('OPTIONAL', 'DashboardName', fallback='Vulners')
action_name = config.get('OPTIONAL', 'ActionName', fallback='Vulners')

hosts_host = config.get('OPTIONAL', 'HostsHost', fallback='vulners.hosts')
hosts_name = config.get('OPTIONAL', 'HostsVisibleName', fallback='Vulners - Hosts')

bulletins_host = config.get('OPTIONAL', 'BulletinsHost', fallback='vulners.bulletins')
bulletins_name = config.get('OPTIONAL', 'BulletinsVisibleName', fallback='Vulners - Bulletins')

packages_host = config.get('OPTIONAL', 'PackagesHost', fallback='vulners.packages')
packages_name = config.get('OPTIONAL', 'PackagesVisibleName', fallback='Vulners - Packages')

statistics_host = config.get('OPTIONAL', 'StatisticsHost', fallback='vulners.statistics')
statistics_name = config.get('OPTIONAL', 'StatisticsVisibleName', fallback='Vulners - Statistics')

stats_macros_name = config.get('OPTIONAL', 'StatisticsMacrosName', fallback='{$WORK_SCRIPT_CMD}')
stats_macros_value = config.get('OPTIONAL', 'StatisticsMacrosValue', fallback='/opt/monitoring/zabbix-threat-control/scan.py')

template_host = config.get('OPTIONAL', 'TemplateHost', fallback='tmpl.vulners.os-report')
template_name = config.get('OPTIONAL', 'TemplateVisibleName', fallback='Template Vulners OS-Report')

template_macros_name = config.get('OPTIONAL', 'TemplateMacrosName', fallback='{$REPORT_SCRIPT_PATH}')
template_macros_value = config.get('OPTIONAL', 'TemplateMacrosValue', fallback='/opt/monitoring/os-report/report.py')

template_application_name = config.get('OPTIONAL', 'TemplateApplicationName', fallback='Vulners OS Report')

group_name = config.get('OPTIONAL', 'HostGroupName', fallback='Vulners')
template_group_name = config.get('OPTIONAL', 'TemplateGroupName', fallback='Templates')

zabbix_sender_bin = config.get('OPTIONAL', 'ZabbixSender', fallback='zabbix_sender')
zabbix_get_bin = config.get('OPTIONAL', 'ZabbixGet', fallback='zabbix_get')

min_cvss = config['OPTIONAL'].getint('MinCVSS', 1)
