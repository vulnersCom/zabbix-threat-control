vuln_api_key = 'RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR'

zbx_pass = 'yourpassword'
zbx_user = 'yourlogin'
zbx_url = 'https://zabbixfront.yourdomain.com'

zbx_server = 'zabbixserver.yourdomain.com'
zbx_port = '10051'

log_file = '/var/log/zbxvulners.log'
zsender_data_file = '/tmp/zbxvulners_data'
zsender_lld_file = '/tmp/zbxvulners_lld'
h_matrix_dumpfile = '/opt/monitoring/zbx-vulners/h_matrix_dumpfile'


group_name = 'Vulners'
appl_name = 'Vulnerabilities'

zbx_h_hosts = 'vulners.hosts'
zbx_h_hosts_vname ='Vulners - Hosts'

zbx_h_bulls = 'vulners.bulletins'
zbx_h_bulls_vname ='Vulners - Bulletins'

zbx_h_pkgs = 'vulners.packages'
zbx_h_pkgs_vname ='Vulners - Packages'

zbx_h_stats = 'vulners.statistics'
zbx_h_stats_vname ='Vulners - Statistics'

stats_macros_name = '{$WORK_SCRIPT_CMD}'
stats_macros_value = '/opt/monitoring/zbx-vulners/zbxvulners.py'

dash_name = 'Vulners'

tmpl_host = 'tmpl.vulners'
tmpl_name = 'Template Vulners'
tmpl_macros_name = '{$REPORT_SCRIPT_PATH}'
tmpl_macros_value = '/opt/monitoring/os-report/report.py'
tmpl_appl_name = 'OS Report'


