#!/usr/bin/env python3


"""
Zabbix vulnerability assessment plugin.

Script will fix vulnerabilities.
fix.py {HOST.HOST} {TRIGGER.ID} {EVENT.ID}
"""

__version__ = "2.0"


import sys
import logging
import subprocess
import config
from pyzabbix import ZabbixAPI


def shell(command):
    proc = subprocess.Popen(
        command, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, shell=True
    )
    out = proc.communicate()[0].decode("utf8")
    return out


def do_fix(visual_name, fix_cmd):
    hosts = zapi.host.get(filter={"name": visual_name}, output=["hostid"])
    if len(hosts) == 0:
        logging.warning(
            "Can't find host {} in Zabbix. Skip fixing vulnerabilities on this host".format(
                visual_name
            )
        )
        exit(1)

    host_id = hosts[0]["hostid"]
    host_interface = zapi.hostinterface.get(
        hostids=host_id,
        filter={"main": "1", "type": "1"},
        output=("dns", "ip", "useip", "port"),
    )

    if not host_interface:
        logging.error("Host interface for hostid {} not found".format(host_id))
        exit(1)

    cmd_params = {
        "zabbix_get_bin": config.zabbix_get_bin,
        "host_address": host_interface["ip" if int(host_interface["useip"]) else "dns"],
        "host_port": host_interface["port"],
        "fix_cmd": fix_cmd,
    }

    if config.use_zbx_agent_to_fix:
        cmd = '{zabbix_get_bin} -s {host_address} -p {host_port} -k "system.run[{fix_cmd},nowait]"'.format(
            **cmd_params
        )
    else:
        cmd = 'ssh {} -l {} "{}"'.format(cmd_params["host_address"], config.ssh_user, fix_cmd)

    logging.info(cmd)
    out = shell(cmd)
    logging.info(out)


def run():
    _, triggered_host, trigger_id, event_id, *__ = sys.argv

    logging.info(
        "Getting Started with the event: {}/tr_events.php?triggerid={}&eventid={}".format(
            config.zbx_url, trigger_id, event_id
        )
    )

    event = zapi.event.get(
        eventids=event_id,
        select_acknowledges=["username", "action"],
        output=["username", "action"],
    )

    if not event:
        logging.error("Event {} not found".format(event_id))
        exit(1)

    acknowledges = event[0]["acknowledges"][0]

    ack_alias = acknowledges["username"]
    ack_action = acknowledges["action"]

    if ack_alias not in config.acknowledge_users:
        logging.info(
            "Not trusted user in acknowledge: {}. Skipping this request to fix".format(
                ack_alias
            )
        )
        exit(0)

    trigger = zapi.trigger.get(triggerids=trigger_id, output="extend")[0]
    trigger_description = trigger["description"]
    trigger_comment = trigger["comments"]

    if ack_action == "1":
        logging.info(
            'The "{}" trigger was manually closed by the "{}" user. No further action required'.format(
                trigger_description, ack_alias
            )
        )
        exit(0)

    if triggered_host == config.hosts_host:
        hostname = trigger_description[trigger_description.rfind(" = ") + 3 :]
        fix = trigger_comment[trigger_comment.rfind("\r\n\r\n") + 4 :]
        do_fix(hostname, fix)
    elif triggered_host == config.packages_host:
        _, hosts, __, fix = filter(lambda x: x.strip(), trigger_comment.split('\r\n'))
        hosts = hosts.splitlines()
        hosts_cnt = len(hosts)
        for idx, hostname in enumerate(hosts, 1):
            logging.info(
                "[{idx} of {hosts_cnt}] {hostname}".format(
                    idx=idx, hosts_cnt=hosts_cnt, hostname=hostname
                )
            )
            do_fix(hostname, fix)
    else:
        logging.info(
            "Host {} that triggered the trigger does not match the required: {} or {}".format(
                triggered_host, config.packages_host, config.hosts_host
            )
        )


if __name__ == "__main__":

    logging.basicConfig(
        level=logging.INFO,
        filename=config.log_file,
        format="%(asctime)s  %(process)d  %(levelname)s  %(message)s  [%(filename)s:%(lineno)d]",
    )

    zapi = ZabbixAPI(config.zbx_url, timeout=10)
    zapi.session.verify = config.zbx_verify_ssl
    zapi.login(config.zbx_user, config.zbx_pwd)
    logging.info("Connected to Zabbix API v.{}".format(zapi.api_version()))
    run()
    logging.info("End")
