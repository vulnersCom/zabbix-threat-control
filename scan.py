#!/usr/bin/env python3

"""Zabbix vulnerability assessment plugin."""

__version__ = "2.0"

import os
import re
import argparse
import json
import logging
import pickle
import subprocess
import jpath
import vulners
import config
from time import sleep
from pyzabbix import ZabbixAPI
from statistics import mean, median


class Scan:
    lld_file_path = os.path.join(config.work_dir, "lld.zbx")
    data_file_path = os.path.join(config.work_dir, "data.zbx")
    hosts_dump_path = os.path.join(config.work_dir, "dump.bin")

    data_file = None
    lld_file = None

    hosts = None
    total_hosts_cnt = None

    def __init__(self):
        logger.info("Scan running")
        self.vapi = vulners.VulnersApi(api_key=config.vuln_api_key)
        self.zapi = ZabbixAPI(config.zbx_url, timeout=10)
        self.zapi.session.verify = config.zbx_verify_ssl
        self.zapi.login(config.zbx_user, config.zbx_pwd)

        logger.info("Connected to Zabbix API v.{}".format(self.zapi.api_version()))

        if self.total_hosts_cnt == 0:
            logger.info("There are no data in the host-matrix for further processing. Exit")
            exit()

    @staticmethod
    def shell(command):
        proc = subprocess.Popen(
            command, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, shell=True
        )
        out = proc.communicate()[0].decode("utf8")
        return out

    @staticmethod
    def uniq_list_of_dicts(list_):
        result = []
        for dict_ in list_:
            if dict_ not in result:
                result.append(dict_)
        return result

    @staticmethod
    def verify_os_data(os_name, os_version, os_packages, name, *args, **kwargs):
        try:
            if os_name and float(os_version) != 0. and len(os_packages) > 5:
                return True
        except Exception as e:
            logger.warning("Excluded {}. Exception: {}".format(name, e))
            return False
        logger.info(
            "Excluded {}. OS: {}, Version: {}, Packages: {}".format(
                name, os_name, os_version, len(os_packages)
            )
        )
        return False

    def create_hosts_dump(self):
        with open(self.hosts_dump_path, "wb") as file:
            pickle.dump(self.hosts, file)
        return True

    def read_hosts_dump(self):
        with open(self.hosts_dump_path, "rb") as file:
            obj = pickle.load(file)
        return obj

    def get_or_create_hosts_matrix(self):
        if os.path.exists(self.hosts_dump_path):
            logger.info("Found a dump of the h_matrix in {}. Loading".format(self.hosts_dump_path))
            self.hosts = self.read_hosts_dump()
        self.create_hosts_matrix()

    def update_with_zabbix_data(self):
        logger.info("Received from Zabbix {} hosts for processing".format(self.total_hosts_cnt))
        logger.info("Receiving extended data about hosts from Zabbix")

        for idx, host in enumerate(self.hosts, 1):
            items = self.zapi.item.get(
                hostids=host["hostid"],
                search={"key_": config.template_macros_name},
                output=["name", "lastvalue"],
            )
            for item in items:
                name = item["name"].replace('-', '_').replace(' ', '').lower()
                host.update({name: item["lastvalue"]})

            host.update({"os_name": re.sub("^ol$", "oraclelinux", host["os_name"])})

            logger.info(
                '[{} of {}] "{}". Successfully received extended data'.format(
                    idx, self.total_hosts_cnt, host["name"]
                )
            )

    def update_with_vulners_data(self):
        logger.info("Receiving the vulnerabilities from Vulners")
        for idx, host in enumerate(self.hosts, 1):
            vulnerabilities = self.vapi.os_audit(
                os=host["os_name"],
                version=host["os_version"],
                packages=host["os_packages"].splitlines(),
            )
            if vulnerabilities.get("errorCode", 0) == 0:
                host.update({"vulners_data": {"data": vulnerabilities, "success": True}})
                logger.info(
                    '[{} of {}] "{}". Successfully received data from Vulners'.format(
                        idx, self.total_hosts_cnt, host["name"]
                    )
                )
            else:
                host.update({"vulners_data": {"data": vulnerabilities, "success": False}})
                logger.info(
                    '[{} of {}] "{}". Can\'t receive data from Vulners. Error message: {}'.format(
                        idx,
                        self.total_hosts_cnt,
                        host["name"],
                        vulnerabilities.get("error", 0),
                    )
                )

    def create_hosts_matrix(self):
        template_id = self.zapi.template.get(filter={"host": config.template_host})[0]["templateid"]
        if args.limit:
            logger.info(
                '"limit" option is used. Fetching data from Zabbix is limited to {} hosts.'.format(
                    args.limit
                )
            )
        self.hosts = self.zapi.host.get(
            templated_hosts=False,
            templateids=template_id,
            monitored_hosts=True,
            output=["hostid", "host", "name"],
            limit=args.limit
        )

        self.total_hosts_cnt = len(self.hosts)

        self.update_with_zabbix_data()

        logger.info("Exclude invalid response data from Zabbix")
        self.hosts = list(filter(lambda host: self.verify_os_data(**host), self.hosts))
        filtered_hosts_cnt = len(self.hosts)
        removed_hosts_cnt = self.total_hosts_cnt - filtered_hosts_cnt
        logger.info(
            "There are {} entries left. Removed: {}".format(
                self.total_hosts_cnt, removed_hosts_cnt
            )
        )

        self.update_with_vulners_data()

        logger.info("Exclude invalid response data from Vulners")
        self.hosts = list(filter(lambda host: host["vulners_data"]["success"], self.hosts))

        removed_hosts_cnt = self.total_hosts_cnt - len(self.hosts)
        self.total_hosts_cnt = len(self.hosts)
        logger.info(
            "There are {} entries left. Removed: {}".format(self.total_hosts_cnt, removed_hosts_cnt)
        )

    def write_score_data(self):
        logger.info(
            "Creating an additional field in the host-matrix based on data from Vulners"
        )
        for idx, host in enumerate(self.hosts, 1):
            host_bulletins = []
            host_packages = {}
            vulners_data = host.pop("vulners_data", {})
            for row in jpath.get_all(jpath="data.packages.*.*.*", data=vulners_data):
                package_name = row["package"]
                bulletin_id = row["bulletinID"]
                score = float(row["cvss"]["score"])
                fix = row["fix"]

                host_bulletins.append({"name": bulletin_id, "score": score})

                package = host_packages.setdefault(package_name, {})
                if package.get('score') is None or package['score'] < score:
                    package.update({
                        "name": package_name,
                        "score": score,
                        "fix": fix,
                        "bulletin_id": bulletin_id
                    })

            host.update({
                "cumulative_fix": vulners_data["data"]["cumulativeFix"].replace(",", ""),
                "score": vulners_data["data"]["cvss"]["score"],
                "packages": list(host_packages.values()),
                "bulletins": self.uniq_list_of_dicts(host_bulletins),
            })

            logger.info(
                '[{} of {}] "{}". Successfully processed'.format(
                    idx, self.total_hosts_cnt, host["name"]
                )
            )

        logger.info("Creating an LLD-data: CVSS-Scores and Cumulative-Fix commands")
        discovery_hosts = []

        for idx, host in enumerate(self.hosts, 1):
            discovery_hosts.append({
                "{#H.VNAME}": host["name"],
                "{#H.HOST}": host["host"],
                "{#H.ID}": host["hostid"],
                "{#H.FIX}": host["cumulative_fix"],
                "{#H.SCORE}": host["score"],
            })

            self.data_file.write('"{}" vulners.hosts[{}] {}\n'.format(config.hosts_host, host["hostid"], host["score"]))

        discovery_hosts_json = json.dumps({"data": discovery_hosts}, separators=(',', ':'))

        self.lld_file.write(
            '"{}" vulners.hosts_lld {}\n'.format(config.hosts_host, discovery_hosts_json)
        )

    def write_packages_data(self):
        logger.info("Creating a matrix of vulnerable packages of all hosts")

        pkg_matrix = {}

        for idx, host in enumerate(self.hosts, 1):
            packages = host.pop("packages", [])
            for package in packages:
                pkg = pkg_matrix.setdefault(package['name'], {
                    "name": package["name"],
                    "score": package["score"],
                    "bulletin_id": package["bulletin_id"],
                    "fix": package["fix"],
                    "host_list": [],
                })
                if host['name'] not in pkg['host_list']:
                    pkg['host_list'].append(host['name'])
            logger.info(
                '[{} of {}] \"{}\". Successfully processed vulnerable packages: {}'.format(
                    idx, self.total_hosts_cnt, host['name'], len(packages))
            )
        pkg_matrix = list(pkg_matrix.values())

        logger.info("Unique vulnerable packages processed: {}".format(len(pkg_matrix)))
        logger.info("Creating an LLD-data for package monitoring")

        discovery_pkg = []

        for package in pkg_matrix:
            affected_hosts_cnt = len(package["host_list"])
            name = package["name"]
            bulletin_id = package["bulletin_id"]
            score = package["score"]
            fix = package["fix"]

            self.data_file.write(
                '"{}" "vulners.packages[{}]" {}\n'.format(
                    config.packages_host, name, affected_hosts_cnt
                )
            )

            discovery_pkg.append(
                {
                    "{#PKG.ID}": name,
                    "{#PKG.URL}": bulletin_id,
                    "{#PKG.SCORE}": score,
                    "{#PKG.FIX}": fix,
                    "{#PKG.AFFECTED}": affected_hosts_cnt,
                    "{#PKG.IMPACT}": int(affected_hosts_cnt * score),
                    "{#PKG.HOSTS}": "\n".join(package["host_list"]),
                }
            )

        discovery_pkg_json = json.dumps({"data": discovery_pkg}, separators=(',', ':'))

        self.lld_file.write('"{}" vulners.packages_lld {}\n'.format(config.packages_host, discovery_pkg_json))

    def write_bulletins_data(self):
        logger.info("Creating an bulletin-matrix")
        bulletin_matrix = {}
        for host in self.hosts:
            for bulletin in host["bulletins"]:
                bulletin_hosts = bulletin_matrix.setdefault(bulletin['name'], {
                    'bulletin': bulletin,
                    'host_list': []
                })
                if host['name'] not in bulletin_hosts['host_list']:
                    bulletin_hosts['host_list'].append(host['name'])
        bulletin_matrix = list(bulletin_matrix.values())

        logger.info("Unique security bulletins processed: {}".format(len(bulletin_matrix)))
        logger.info("Creating an LLD-data for bulletin monitoring")

        discovery_data = []

        for bulletin in bulletin_matrix:
            affected_hosts_cnt = len(bulletin["host_list"])
            bulletin_name = bulletin["bulletin"]["name"]
            bulletin_score = bulletin["bulletin"]["score"]
            bulletin_impact = int(affected_hosts_cnt * bulletin_score)

            self.data_file.write(
                '"{}" vulners.bulletins[{}] {}\n'.format(
                    config.bulletins_host, bulletin_name, affected_hosts_cnt
                )
            )

            discovery_data.append(
                {
                    "{#BULLETIN.ID}": bulletin_name,
                    "{#BULLETIN.SCORE}": bulletin_score,
                    "{#BULLETIN.AFFECTED}": affected_hosts_cnt,
                    "{#BULLETIN.IMPACT}": bulletin_impact,
                    "{#BULLETIN.HOSTS}": "\n".join(bulletin["host_list"]),
                }
            )

        discovery_json = json.dumps({"data": discovery_data}, separators=(',', ':'))
        self.lld_file.write(
            '"{}" vulners.bulletins_lld {}\n'.format(config.bulletins_host, discovery_json)
        )

    def write_cvss_and_aggregation_data(self):
        logger.info("Creating an CVSS Score-based host-lists")
        score_list = []

        host_count_table = dict((score_value, 0) for score_value in range(0, 11))
        for host in self.hosts:
            score_list.append(host["score"])
            host_count_table[int(host["score"])] += 1

        if not score_list:
            score_list = [0]

        logger.info("Creating an aggregated data")

        agg_score_median = median(score_list)
        agg_score_mean = mean(score_list)
        agg_score_max = max(score_list)
        agg_score_min = min(score_list)

        for intScore in host_count_table:
            self.data_file.write(
                '"{}" vulners.hostsCountScore{} {}\n'.format(
                    config.statistics_host, intScore, host_count_table.get(intScore)
                )
            )
        self.data_file.write('"{}" vulners.TotalHosts {}\n'.format(config.statistics_host, self.total_hosts_cnt))
        self.data_file.write('"{}" vulners.scoreMedian {}\n'.format(config.statistics_host, agg_score_median))
        self.data_file.write('"{}" vulners.scoreAverage {}\n'.format(config.statistics_host, agg_score_mean))
        self.data_file.write('"{}" vulners.scoreMaximum {}\n'.format(config.statistics_host, agg_score_max))
        self.data_file.write('"{}" vulners.scoreMinimum {}\n'.format(config.statistics_host, agg_score_min))

    def push_data(self):
        push_lld_cmd = "{} -z {} -p {} -i {}".format(
            config.zabbix_sender_bin,
            config.zbx_server_fqdn,
            config.zbx_server_port,
            self.lld_file_path,
        )
        push_cmd = "{} -z {} -p {} -i {}".format(
            config.zabbix_sender_bin,
            config.zbx_server_fqdn,
            config.zbx_server_port,
            self.data_file_path,
        )

        if args.nopush:
            logger.info(
                '"nopush" option is used. The transfer of data to zabbix is disabled, but can be performed by commands:'
            )
            logger.info("{}; sleep 300; {}".format(push_lld_cmd, push_cmd))
        else:
            logger.info("Pushing LLD-objects to Zabbix: {}".format(push_lld_cmd))
            logger.info(self.shell(push_lld_cmd))
            logger.info("Awaiting for 5 min")
            sleep(300)

            logger.info("Pushing data to Zabbix: {}".format(push_cmd))
            logger.info(self.shell(push_cmd))
        self.data_file.close()
        self.lld_file.close()
        logger.info("Work completed successfully")

    def open_files(self):
        self.data_file = open(self.data_file_path, 'w')
        self.lld_file = open(self.lld_file_path, 'w')

    def close_files(self):
        self.data_file.close()
        self.lld_file.close()

    def run(self):
        self.get_or_create_hosts_matrix()

        if args.dump:
            self.create_hosts_dump()
            logger.info("hosts-matrix saved to {}".format(self.hosts_dump_path))

        self.total_hosts_cnt = len(self.hosts)
        self.open_files()
        self.write_score_data()
        self.write_packages_data()
        self.write_bulletins_data()
        self.write_cvss_and_aggregation_data()
        self.close_files()
        self.push_data()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Vulners to zabbix integration tool")
    parser.add_argument(
        "-n",
        "--nopush",
        help="Bypass Zabbix-server. Don't push final dataset to Zabbix-server.",
        action="store_true",
    )

    parser.add_argument(
        "-d", "--dump", help="Dump zabbix and vulners data to disk", action="store_true"
    )

    parser.add_argument(
        "-l",
        "--limit",
        type=int,
        help="Host limit for processing. Only the specified number of hosts will be received from the Zabbix.",
    )

    args = parser.parse_args()

    logger = logging.getLogger("ZTC")
    if config.debug_level == 0:
        logger.setLevel(logging.ERROR)
    elif config.debug_level == 2:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    fh = logging.FileHandler(config.log_file)

    formatter = logging.Formatter(
        "%(asctime)s  %(name)s  %(levelname)s  %(message)s  [%(filename)s:%(lineno)d]"
    )
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    try:
        Scan().run()
    except Exception as e:
        logger.exception(e)
        raise
