# Zabbix Threat Control

Оur plugin transforms your Zabbix monitoring system into vulnerability, risk and security managment system for your infrastructure.

  * [What the plugin does](#what-the-plugin-does)
  * [How the plugin works](#how-the-plugin-works)
  * [Requirements](#requirements)
  * [Installation](#installation)
  * [Сonfiguration](#configuration)
  * [Execution](#execution)
  * [Usage](#usage)
  
## What the plugin does

It provides Zabbix with information about vulnerabilities existing in your entire infrastructure and suggests easily applicable remediation plans.

Information is displayed in Zabbix in the following format:

- Maximum CVSS score for each server.
- Command for fixing all detected vulnerabilities for each server.
- List of security bulletins with descriptions for vulnerable packages valid for your infrastructure.
- List of all vulnerable packages in your infrastructure.


![](https://github.com/vulnersCom/zabbix-threat-control/blob/master/docs/hosts.gif)


Security bulletins and packages information includes:

- Impact index for the infrastructure.
- CVSS score of a package or a bulletin.
- Number of affected servers.
- A detailed list of affected hosts.
- Hyperlink to the description of a bulletin.

![](https://github.com/vulnersCom/zabbix-threat-control/blob/master/docs/pkgs.gif)

Sometimes it is impossible to update all packages on all servers to a version that fixes existing vulnerabilities. The proposed representation permits you to selectively update servers or packages.

This approach allows one to fix vulnerabilities using different strategies:

- all vulnerabilities on a specific server;
- a single vulnerability in the entire infrastructure.

This can be done directly from Zabbix (using its standard functionality) either on the administrator command or automatically.

## How the plugin works

- Using Zabbix API, the plugin receives lists of installed packages, names and versions of the OS from all the servers in the infrastructure (if the "Vulners OS-Report" template is linked with them).
- Transmits the data to Vulners
- Receives information on the vulnerabilities for each server.
- Processes the received information, aggregates it and sends it back to Zabbix via zabbix-sender.
- Finally the result is displayed in Zabbix.

## Requirements

- python 3 (only for ztc scripts)
- python modules: pyzabbix, jpath, requests
- zabbix version 3.4 is required to create a custom dashboard and a custom polling schedule.
- zabbix-agent for collect data and run scripts.
- zabbix-sender utility for sending data to zabbix-server.

## Installation

### RHEL, CentOS and other RPM-based

    rpm -Uhv https://repo.vulners.com/redhat/vulners-repo.rpm

**On zabbix-server host:**

    yum install zabbix-threat-control-main zabbix-threat-control-host

**On all the servers that require a vulnerability scan:**

    yum install zabbix-threat-control-host


### Debian and other debian-based

    wget https://repo.vulners.com/debian/vulners-repo.deb
    dpkg -i vulners-repo.deb

**On zabbix-server host:**

    apt-get update && apt-get install zabbix-threat-control-main zabbix-threat-control-host

**On all the servers that require a vulnerability scan:**

    apt-get update && apt-get install zabbix-threat-control-host

### From source

**On zabbix-server host:**

    git clone https://github.com/vulnersCom/zabbix-threat-control.git
    mkdir -p /opt/monitoring/zabbix-threat-control
    cp zabbix-threat-control/ztc* /opt/monitoring/zabbix-threat-control/
    chown -R zabbix:zabbix /opt/monitoring/zabbix-threat-control
    chmod 640 /opt/monitoring/zabbix-threat-control/ztc_config.py
    touch /var/log/zabbix-threat-control.log
    chown zabbix:zabbix /var/log/zabbix-threat-control.log
    chmod 664 /var/log/zabbix-threat-control.log

**On all the servers that require a vulnerability scan:**

    git clone https://github.com/vulnersCom/zabbix-threat-control.git
    mkdir -p /opt/monitoring/
    cp -R zabbix-threat-control/os-report /opt/monitoring/
    chown -R zabbix:zabbix /opt/monitoring/os-report

## Configuration

Configuration file is located here: `/opt/monitoring/zabbix-threat-control/ztc_config.py`

### Zabbix credentials

In order to connect to Zabbix you need to specify the following in the configuration file:
-	The URL, username and password. Note that the User should have rights to create groups, hosts and templates in Zabbix.
-	Domain name and port of the Zabbix-server for pushing data using the zabbix-sender.

Here is an example of a valid config file:

```
zbx_pass = 'yourpassword'
zbx_user = 'yourlogin'
zbx_url = 'https://zabbixfront.yourdomain.com'

zbx_server_fqdn = 'zabbixserver.yourdomain.com'
zbx_server_port = '10051'
```
### Vulners credentials

To use Vulners API you need an api-key. To get it follow the steps bellow:
- Log in to vulners.com.
- Navigate to userinfo space https://vulners.com/userinfo.
- Choose "API KEYS" section.
- Select "scan" in scope menu and click "Generate new key".
- You will get an api-key, which looks like this:
**RGB9YPJG7CFAXP35PMDVYFFJPGZ9ZIRO1VGO9K9269B0K86K6XQQQR32O6007NUK**

Now you need to add the Vulners api-key into your configuration file (parameter ```vuln_api_key```).

```
vuln_api_key = 'RGB9YPJG7CFAXP35PMDVYFFJPGZ9ZIRO1VGO9K9269B0K86K6XQQQR32O6007NUK'
```

### Zabbix entity

1. To create all the necessary objects in Zabbix, run the `/opt/monitoring/zabbix-threat-control/ztc_create.py` script. It will create the following objects using Zabbix API:
   * **A template** used to collect data from servers.
   * **Zabbix hosts** for obtaining data on vulnerabilities.
   * **A dashboard** for displaying results.
2. Using the Zabbix web interface, it is necessary to link the "Vulners OS-Report" template with the hosts that you are doing a vulnerabilities scan on.


## Execution

- `/opt/monitoring/os-report/report.py` transfers the name, version and installed packages of the operating system to Zabbix.<br />
  Runs with zabbix-agent on all hosts to which the template "Vulners OS-Report" is linked.

- `/opt/monitoring/zabbix-threat-control/ztc.py` processes raw data from zabbix and vulners and push them to the monitoring system using zabbix-sender.<br />
  Runs with zabbix-agent on the Zabbix server via the item "Service item" on the host "Vulners - Statistics".

To run these scripts, you should allow to execute the remote commands from the Zabbix server (`EnableRemoteCommands = 1` parameter in the zabbix-agent configuration file).<br />
Scripts are run once a day. The start-up time is selected randomly during the installation and does not change during operation.

## Usage
It will be ready soon...

