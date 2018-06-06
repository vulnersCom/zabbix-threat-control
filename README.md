# Installation

**On zabbix-server host:**

- Move the ```zbx-vulners``` directory to /opt/monitoring/
- touch /var/log/zbxvulners.log
- chown -R zabbix:zabbix /opt/monitoring/zbx-vulners
- chown zabbix:zabbix /var/log/zbxvulners.log

**All servers that require a vulnerability scan:**

- Move the ```os-report``` directory to /opt/monitoring/
- chown -R zabbix:zabbix /opt/monitoring/os-report


# Сonfiguration

## Configuration file

Now you should get Vulners api-key. Log in to vulners.com, go to userinfo space https://vulners.com/userinfo. Then you should choose "apikey" section.
Choose "scan" in scope menu and click "Generate new key". You will get an api-key, which looks like this:
**RGB9YPJG7CFAXP35PMDVYFFJPGZ9ZIRO1VGO9K9269B0K86K6XQQQR32O6007NUK**

You'll need to write this key into configuration (parameter ```vuln_api_key```). Configuration is located in file  /opt/monitoring/zbx-vulners/zbxvulners_settings.py

Enter the data to connect to the Zabbix: 
-	URL, username and password for connection with API. The User should have rights to create groups, hosts and templates in Zabbix.
-	 Address and port of the Zabbix-server for pushing data using the zabbix-sender.

Here is example of config file:
```
vuln_api_key = 'RGB9YPJG7CFAXP35PMDVYFFJPGZ9ZIRO1VGO9K9269B0K86K6XQQQR32O6007NUK'

zbx_pass = 'yourpassword'
zbx_user = 'yourlogin'
zbx_url = 'https://zabbixfront.yourdomain.com'

zbx_server = 'zabbixserver.yourdomain.com'
zbx_port = '10051'
```

## Zabbix

You need to create objects in the Zabbix:
- template, through which data will be collected from the servers
- zabbix-hosts for obtaining data on vulnerabilities
- dashboard for their display

To do this, run the /opt/monitoring/zbx-vulners/create_zbxobj.py script.
Which will create all the necessary objects in Zabbix using the API.

Following this step, it is necessary to link (using zabbix web interface) the "Vulnerabilities" template to the hosts for which you want do vulnerabilities scan.
# Execution

Zabbix will automatically receive the name, version and installed packages of all hosts every day at 6 am.

Data processing is performed by script /opt/monitoring/zbx-vulners/zbxvulners.py.
This script is launched by the zabbix-agent every day at 7 am via the item "Service item" on the host "Vulnerabilities - Statistics".
