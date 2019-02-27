"""Config reader for ZTC"""

__author__ = 'samosvat'
__version__ = '1.3.4'


import configparser

config = configparser.ConfigParser()
config.read('/opt/monitoring/zabbix-threat-control/ztc.conf')

vuln_api_key = config.get('MANDATORY', 'VulnersApiKey', fallback=None)

zbx_user = config.get('MANDATORY', 'ZabbixApiUser', fallback=None)
zbx_pass = config.get('MANDATORY', 'ZabbixApiPassword', fallback=None)

zbx_url = config.get('OPTIONAL', 'ZabbixFrontUrl', fallback='http://localhost/zabbix')
zbx_verify_ssl = config['OPTIONAL'].getboolean('VerifySSL', True)

zbx_server_fqdn = config.get('OPTIONAL', 'ZabbixServerFQDN', fallback='localhost')
zbx_server_port = config['OPTIONAL'].getint('ZabbixServerPort', 10051)

use_zbx_agent_to_fix = config['OPTIONAL'].getboolean('UseZabbixAgentToFix', True)
acknowledge_users = config.get('OPTIONAL', 'TrustedZabbixUsers', fallback='Admin').split(',')
ssh_user = config.get('OPTIONAL', 'SSHUser', fallback='root')

log_file = config.get('OPTIONAL', 'logfile', fallback='/var/log/zabbix-threat-control.log')
debug_level = config['OPTIONAL'].getint('DebugLevel', 1)
work_dir = config.get('OPTIONAL', 'WorkDir', fallback='/opt/monitoring/zabbix-threat-control').rstrip('/')

appl_name = config.get('OPTIONAL', 'HostsApplicationName', fallback='Vulnerabilities')

dash_name = config.get('OPTIONAL', 'DashboardName', fallback='Vulners')
action_name = config.get('OPTIONAL', 'ActionName', fallback='Vulners')

zbx_h_hosts = config.get('OPTIONAL', 'HostsHost', fallback='vulners.hosts')
zbx_h_hosts_vname = config.get('OPTIONAL', 'HostsVisibleName', fallback='Vulners - Hosts')

zbx_h_bulls = config.get('OPTIONAL', 'BulletinsHost', fallback='vulners.bulletins')
zbx_h_bulls_vname = config.get('OPTIONAL', 'BulletinsVisibleName', fallback='Vulners - Bulletins')

zbx_h_pkgs = config.get('OPTIONAL', 'PackagesHost', fallback='vulners.packages')
zbx_h_pkgs_vname = config.get('OPTIONAL', 'PackagesVisibleName', fallback='Vulners - Packages')

zbx_h_stats = config.get('OPTIONAL', 'StatisticsHost', fallback='vulners.statistics')
zbx_h_stats_vname = config.get('OPTIONAL', 'StatisticsVisibleName', fallback='Vulners - Statistics')

stats_macros_name = config.get('OPTIONAL', 'StatisticsMacrosName', fallback='{$WORK_SCRIPT_CMD}')
stats_macros_value = config.get('OPTIONAL', 'StatisticsMacrosValue', fallback='/opt/monitoring/zabbix-threat-control/scan.py')

tmpl_host = config.get('OPTIONAL', 'TemplateHost', fallback='tmpl.vulners.os-report')
tmpl_name = config.get('OPTIONAL', 'TemplateVisibleName', fallback='Template Vulners OS-Report')

tmpl_macros_name = config.get('OPTIONAL', 'TemplateMacrosName', fallback='{$REPORT_SCRIPT_PATH}')
tmpl_macros_value = config.get('OPTIONAL', 'TemplateMacrosValue', fallback='/opt/monitoring/os-report/report.py')

tmpl_appl_name = config.get('OPTIONAL', 'TemplateApplicationName', fallback='Vulners OS Report')

group_name = config.get('OPTIONAL', 'HostGroupName', fallback='Vulners')
tmpl_group_name = config.get('OPTIONAL', 'TemplateGroupName', fallback='Templates')

z_sender_bin = config.get('OPTIONAL', 'ZabbixSender', fallback='zabbix_sender')
z_get_bin = config.get('OPTIONAL', 'ZabbixGet', fallback='zabbix_get')

min_cvss = config['OPTIONAL'].getint('MinCVSS', 1)

z_agent_conf = config.get('OPTIONAL', 'ZabbixAgentConf', fallback='/etc/zabbix/zabbix_agentd.conf')
with open(z_agent_conf, 'r') as f:
    config_string = '[zabbix_agent]\n'+f.read()
zabbix_agent_config = configparser.ConfigParser()
zabbix_agent_config.read_string(config_string)
tls_connect = zabbix_agent_config.get('zabbix_agent', 'TLSConnect', fallback='unencrypted')
if tls_connect == 'unencrypted':
    tls_options = ''
elif tls_connect == 'psk':
    tls_psk_identity = zabbix_agent_config.get('zabbix_agent', 'TLSPSKIdentity')
    tls_psk_file = zabbix_agent_config.get('zabbix_agent', 'TLSPSKFile')
    tls_options = '--tls-connect psk --tls-psk-identity ' + tls_psk_identity + ' --tls-psk-file ' + tls_psk_file
elif tls_connect == 'cert':
    tls_ca_file = zabbix_agent_config.get('zabbix_agent', 'TLSCAFile')
    tls_cert_file = zabbix_agent_config.get('zabbix_agent', 'TLSCertFile')
    tls_key_file = zabbix_agent_config.get('zabbix_agent', 'TLSKeyFile')
    tls_crl_file = zabbix_agent_config.get('zabbix_agent', 'TLSCRLFile', fallback='')
    tls_server_cert_issuer = zabbix_agent_config.get('zabbix_agent', 'TLSServerCertIssuer', fallback='')
    tls_server_cert_subject = zabbix_agent_config.get('zabbix_agent', 'TLSServerCertSubject', fallback='')
    tls_options = '--tls-connect cert --tls-ca-file ' + tls_ca_file + ' --tls-cert-file ' + tls_cert_file + ' --tls-key-file ' + tls_key_file
    if tls_crl_file != '':
        tls_options += ' --tls-crl-file ' + tls_crl_file
    if tls_server_cert_issuer != '':
        tls_options += ' --tls-server-cert-issuer ' + tls_server_cert_issuer
    if tls_server_cert_subject != '':
        tls_options += ' --tls-server-cert-subject ' + tls_server_cert_subject
    
