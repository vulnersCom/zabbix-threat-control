vuln_api_key = 'RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR'

zbx_user = 'yourlogin'
zbx_pass = 'yourpassword'
zbx_url = 'https://zabbixfront.yourdomain.com'
zbx_verify_ssl_certs = True

zbx_server_fqdn = 'zabbixserver.yourdomain.com'
zbx_server_port = '10051'

use_zbx_agent_to_fix = True
acknowledge_user = 'Admin'
ssh_user = 'root'

log_file = '/var/log/zabbix-threat-control.log'
zsender_lld_file = '/opt/monitoring/zabbix-threat-control/zbx_lld'
zsender_data_file = '/opt/monitoring/zabbix-threat-control/zbx_data'
h_matrix_dumpfile = '/opt/monitoring/zabbix-threat-control/h_matrix_dump'

group_name = 'Vulners'
appl_name = 'Vulnerabilities'

zbx_h_hosts = 'vulners.hosts'
zbx_h_hosts_vname = 'Vulners - Hosts'

zbx_h_bulls = 'vulners.bulletins'
zbx_h_bulls_vname = 'Vulners - Bulletins'

zbx_h_pkgs = 'vulners.packages'
zbx_h_pkgs_vname = 'Vulners - Packages'

zbx_h_stats = 'vulners.statistics'
zbx_h_stats_vname = 'Vulners - Statistics'

stats_macros_name = '{$WORK_SCRIPT_CMD}'
stats_macros_value = '/opt/monitoring/zabbix-threat-control/ztc.py'

dash_name = 'Vulners'
action_name = 'Vulners'

tmpl_host = 'tmpl.vulners.os-report'
tmpl_name = 'Template Vulners OS-Report'
tmpl_macros_name = '{$REPORT_SCRIPT_PATH}'
tmpl_macros_value = '/opt/monitoring/os-report/report.py'
tmpl_appl_name = 'Vulners OS Report'
