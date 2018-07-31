#!/usr/bin/env python3

"""Zabbix vulnerability assessment plugin."""

__author__ = 'samosvat'
__version__ = '1.3.3'

import argparse
import json
import logging
import os
import pickle
import re
import subprocess
from statistics import mean, median
from time import sleep

import jpath

from pyzabbix import ZabbixAPI

import requests

from configreader import *


vulners_url = 'https://vulners.com/api/v3/audit/audit/'
jpath_mask = 'data.packages.*.*.*'

zsender_lld_file = work_dir + 'lld.zbx'
zsender_data_file = work_dir + 'data.zbx'
h_matrix_dumpfile = work_dir + 'dump.bin'

parser = argparse.ArgumentParser(description='Vulners to zabbix integration tool')


parser.add_argument(
    '--BypassZbxPush',
    help='Bypass Zabbix-server. Don\'t push final dataset to Zabbix-server.',
    action='store_true')


parser.add_argument(
    '--DumpHostMatrix',
    help='Dump zabbix and vulners data to disk',
    action='store_true')


args = parser.parse_args()


logging.basicConfig(
    # level=logging.DEBUG,
    level=logging.INFO,
    filename=log_file,
    format='%(asctime)s  %(process)d  %(levelname)s  %(message)s  [%(filename)s:%(lineno)d]')


# выполение комадн в шелле
def shell(command):
    proc = subprocess.Popen(command, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, shell=True)
    out = proc.communicate()[0].decode('utf8')
    return out


# аналог gnu-утилиты unic (оставляем только уникальные записи в списке)
def uniq_list(l):
    x = []
    for a in l:
        if a not in x:
            x.append(a)
    return x


# проверяем валидность информации об ОС
def os_data_valid(os, version, packages, host_name):
    try:
        if len(os) > 0 and float(version) != 0 and len(packages) > 5:
            return True
    except Exception as e:
        logging.warning('Excluded {}. Exception: {}'.format(host_name, e))
        return False
    logging.info('Excluded {}. ОS: {}, Version: {}, Packages: {}'.format(host_name, os, version, len(packages)))
    return False


def dump_create(filename, obj):
    with open(filename, 'wb') as file:
        pickle.dump(obj, file)
    return True


def dump_load(filename):
    with open(filename, 'rb') as file:
        obj = pickle.load(file)
    return obj


logging.info('Start.')
if len(vuln_api_key) != 64:
    logging.error('Error: not a valid Vulners API-key')
    exit(1)

# создаем сессию в заббикс
try:
    zapi = ZabbixAPI(zbx_url, timeout=10)
    zapi.session.verify = zbx_verify_ssl
    zapi.login(zbx_user, zbx_pass)
    logging.info('Connected to Zabbix API v.{}'.format(zapi.api_version()))
except Exception as e:
    logging.error('Error: Can\'t connect to Zabbix API. Exception: {}'.format(e))
    exit(1)

# Если матрица хостов есть - загружаем дамп с диска
if os.path.exists(h_matrix_dumpfile):
    logging.info('Found a dump of the h_matrix in {}. Loading'.format(h_matrix_dumpfile))
    h_matrix = dump_load(h_matrix_dumpfile)
    total_hosts = len(h_matrix)
else:
        # если дампа матрицы на диске нет - формируем (исходные данные из zabbix и затем обогащаем их через vulners)
    total_hosts = 0
    try:
        tmpl_id = zapi.template.get(filter={'host': tmpl_host})[0]['templateid']
        h_matrix = zapi.host.get(templated_hosts=False, templateids=tmpl_id, monitored_hosts=True, output=['hostid'])
        # h_matrix = zapi.host.get(templated_hosts=False, templateids=tmpl_id, limit=5, monitored_hosts=True, output=['hostid'])
        full_hosts = len(h_matrix)
        logging.info('Received from Zabbix {} hosts for processing'.format(full_hosts))
    except Exception as e:
        logging.error('Error: Can\'t get data from Zabbix. Exception: {}'.format(e))
        exit(1)

    logging.info('Receiving additional information for all hosts from Zabbix')
    current_host = 0
    logging.info('Processing hosts')
    for h in h_matrix:
        current_host += 1
        try:
            host = zapi.host.get(filter={'hostid': h['hostid']}, output=['host', 'name'])[0]
            # h.update({'host': host['host'], 'name': host['name']})
            h.update({'host_name': host['host'], 'v_name': host['name']})

            items = zapi.item.get(hostids=h['hostid'], search={'key_': tmpl_macros_name}, output=['name', 'lastvalue'])
            for i in items:
                h.update({i['name']: i['lastvalue']})

            # Костыль! Вулнерс почему то не умеет обрабатывать "ol"
            h.update({'OS - Name': re.sub('ol', 'oraclelinux', h['OS - Name'])})

        except Exception as e:
            logging.warning('[{} in {}] Skip, can\'t get additional data for hostid {}. Exception: {}'
                            .format(current_host, full_hosts, h['hostid'], e))
            h.update({'OS - Packages': '',
                      'OS - Name': '',
                      'OS - Version': '',
                      'v_name': '',
                      'host_name': ''})
            continue
    logging.info('Processed hosts: {}.'.format(current_host))

    logging.info('Checking data from Zabbix')
    # удаляем невалидные элементы данных из матрицы (там где триплет с хоста не подходящй)
    h_matrix[:] = [h for h in h_matrix if os_data_valid(h['OS - Name'], h['OS - Version'], h['OS - Packages'], h['v_name'])]
    total_hosts = len(h_matrix)
    removed_cnt = full_hosts - total_hosts
    logging.info('After checking data from Zabbix, there are {} entries left. Removed {}'.format(total_hosts, removed_cnt))

    # обогащаем матрицу данными от вулнерса
    logging.info('Receiving the vulnerabilities from Vulners')
    current_host = 0
    logging.info('Processing hosts')
    user_agent = 'vulners-ztc-{}'.format(__version__)
    for h in h_matrix:
        current_host += 1
        # todo: логирование обработки каждой стрки в матрице?
        try:
            os_data = '{"package":' + json.dumps(h['OS - Packages'].splitlines()) + ',"os":"' + h['OS - Name'] + \
                      '","version":"' + h['OS - Version'] + '","apiKey":"' + vuln_api_key + '"}'
            # идем в вулнерс и получем там уязвимости для списка пакетов и ОС
            vuln_response = requests.post(vulners_url, data=os_data, headers={'User-Agent': user_agent,
                                                                              'Content-Type': 'application/json', })
            h.update({'vuln_data': vuln_response.json()})
            # чтобы вулнерс не упал под нагрузкой, засыпаем на чуть-чуть (между запросами)
            ratelimit = int(vuln_response.headers.get('x-vulners-ratelimit-reqlimit'))
            sleep_timeout = 2 / ratelimit
            sleep(sleep_timeout)
        except Exception as e:
            sleep_timeout = 2
            h.update({'vuln_data': {'result': 'FAIL'}})
            logging.warning('[{} in {}] Skip {}], can\'t receive the vulnerabilities from Vulners. Exception: {}'
                            .format(current_host, total_hosts, h['v_name'], e))
            continue
    logging.info('Processed hosts: {}'.format(current_host))

    logging.info('Checking data from Vulners')
    # удаляем невалидные элементы данных из матрицы (там где ответ вулнерс не подходящй)
    h_matrix[:] = [h for h in h_matrix if h['vuln_data']['result'] == 'OK']
    total_hosts = len(h_matrix)
    logging.info('After checking data from Vulners there are {} entries left'.format(total_hosts))

    if args.DumpHostMatrix:
        try:
            # сохраняем дамп матрицы хостов на диск
            dump_create(h_matrix_dumpfile, h_matrix)
            logging.info('host-matrix saved to {}'.format(h_matrix_dumpfile))
        except Exception as e:
            logging.warning('Can\'t dump host-matrix to disk. Exception: {}'.format(e))

if len(h_matrix) == 0:
    logging.info('There are no data in the host-matrix for further processing. Exit')
    exit()

logging.info('Сreating an additional field in the host-matrix based on data from Vulners')
# формируем доп-поля в матрице на основе данных от вулнерса
current_host = 0
logging.info('Processing hosts')
for h in h_matrix:
    current_host += 1
    # todo: логирование обработки каждой стрки в матрице?
    try:
        # список словарей из bulletitID + SCORE, для этого хоста
        h_bulletins = list()
        # список словарей из PKG + его SCORE + его bulletitID, для этого хоста
        h_packages_tmp = list()

        # из форматированного через jpath-джейсона получаем пакет, его бюллетень и балл
        for row in jpath.get_all(jpath=jpath_mask, data=h['vuln_data']):
            pkg = row['package']
            bull = row['bulletinID']
            score = row['cvss']['score']
            fix = row['fix']
            # добавляем double-словарь (bull,score) во временный список (для будущего шаманства с бюллетенями)
            h_bulletins.append({'name': bull, 'score': score})
            # добавляем triple-словарь (pkg,score,bull) во второй временный список (для будущего шаманства с пакетами)
            h_packages_tmp.append({'name': pkg, 'score': score, 'fix': fix, 'bull': bull})

        # убираем дубли одинаковые пакеты, но разные баллы; оставляя только самый высокий бал
        h_packages = list()
        # для каждого пакета в списке "пакет-балл"
        for r in h_packages_tmp:
            pkg = r['name']
            # оставляем во временном списке словарей (куцом) только сторки с пакетами = пакету текущей строки
            h_pkg_tmp = [i for i in h_packages_tmp if i['name'] == pkg]
            h_score_tmp = [0]
            # выбираем все баллы из списка словарей
            for s in h_pkg_tmp:
                h_score_tmp.append(s['score'])
            # определяем самый высокий балл
            score_max = max(map(float, h_score_tmp))
            # оставляем в матрице только строки с самым высоким баллом
            h_pkg = [i for i in h_pkg_tmp if i['score'] == score_max]
            h_packages.append(h_pkg[0])

        # фиксируем в матрице только уникальные записи
        h.update({'h_fix': h['vuln_data']['data']['cumulativeFix'].replace(',', ''),
                  'h_score': h['vuln_data']['data']['cvss']['score'],
                  'h_packages': uniq_list(h_packages),
                  'h_bulletins': uniq_list(h_bulletins)})
    except Exception as e:
        logging.warning('[{} of {}] Skipping {}. Exception: {}'.format(current_host, total_hosts, h['v_name'], e))
        continue
logging.info('Processed hosts: {}'.format(current_host))

f = open(zsender_data_file, 'w')
f_lld = open(zsender_lld_file, 'w')

logging.info('Сreating an LLD-data: CVSS-Scores and Cumulative-Fix commands')
current_host = 0
discovery_hosts = list()
for h in h_matrix:
    current_host += 1
    # формируем LLD-JSON
    try:
        discovery_hosts.append({'{#H.VNAME}': h['v_name'],
                                '{#H.HOST}': h['host_name'],
                                '{#H.ID}': h['hostid'],
                                '{#H.FIX}': h['h_fix'],
                                '{#H.SCORE}': h['h_score']})

        f.write('\"{}\" vulners.hosts[{}] {}\n'.format(zbx_h_hosts, h['hostid'], h['h_score']))
    except Exception as e:
        logging.warning('[{} of {}] {}. Exception: {}'.format(current_host, total_hosts, h['v_name'], e))
        continue

# преобразовываем список в однострочный json без пробелов и пишем в файл
discovery_hosts_json = (json.dumps({'data': discovery_hosts})).replace(': ', ':').replace(', ', ',')

f_lld.write('\"{}\" vulners.hosts_lld {}\n'.format(zbx_h_hosts, discovery_hosts_json))

###########################
# ФОРМИРУЕМ МАТРИЦУ ПАКЕТОВ
###########################
logging.info('Creating an package-matrix')

# цель - найти все хосты, на которых зааффектило этот пакет, для этого
pkg_matrix_tmp = list()
# для каждой строки в матрице
row_iter = 0
p_row_iter = 0
h_row_iter = 0
pp_iter = 0
for row in h_matrix:
    row_iter += 1
    # todo: логирование обработки каждой стрки в матрице?
    try:
        # для каждого пакета в списке пакет-балл (из строки выше), делаем следующее
        for p_row in row['h_packages']:
            p_row_iter += 1
            # для каждой строки в матрице
            host_list = list()
            for h_row in h_matrix:
                h_row_iter += 1
                # для каждого пакета в списке пакет-бюллетени, из строки выше (по хостам)
                # проверяем что этот пакет, на этом хосте, соответсует тому, верхнеуровневому (уровень 2)
                for pp in h_row['h_packages']:
                    pp_iter += 1
                    if p_row['name'] == pp['name']:
                        # и если соответсвует - добавляем имя хоста к атрибутам пакета.
                        host_list.append(h_row['v_name'])
            pkg_matrix_tmp.append({'pkg': p_row['name'], 'score': p_row['score'], 'bull': p_row['bull'],
                                   'fix': p_row['fix'], 'host_list': host_list})
    except Exception as e:
        logging.warning('Skipping {}. Exception: {}'.format(row['v_name'], e))
        continue
logging.info('Processed hosts: {}'.format(row_iter))
pkg_matrix = uniq_list(pkg_matrix_tmp)


# формируем пакет LLD-данных
logging.info('Сreating an LLD-data for package monitoring')

discovery_pkg = list()
# для каждого бюллетеня (строки) в матрице бюллетеней строим LLD-json c кол-вом хостов, именем, баллами, влиянием
for p in pkg_matrix:
    affected_h_cnt = len(p['host_list'])
    pkg = p['pkg']
    bull = p['bull']
    pkg_score = p['score']
    fix = p['fix']

    # пишем данные касательно кол-ва хостов, затронутых этим пакетом
    f.write('\"{}\" \"vulners.pkg[{}]\" {}\n'.format(zbx_h_pkgs, pkg, affected_h_cnt))

    # формируем LLD-JSON
    discovery_pkg.append({'{#PKG.ID}': pkg,
                          '{#PKG.URL}': bull,
                          '{#PKG.SCORE}': pkg_score,
                          '{#PKG.FIX}': fix,
                          '{#PKG.AFFECTED}': affected_h_cnt,
                          '{#PKG.IMPACT}': int(affected_h_cnt * pkg_score),
                          '{#PKG.HOSTS}': '\n'.join(p['host_list'])})

# преобразовываем в однострочный json без пробелов и пишем в файл
discovery_pkg_json = (json.dumps({'data': discovery_pkg})).replace(': ', ':').replace(', ', ',')

f_lld.write('\"{}\" vulners.packages_lld {}\n'.format(zbx_h_pkgs, discovery_pkg_json))

##############################
# ФОРМИРУЕМ МАТРИЦУ БЮЛЛЕТЕНЕЙ
##############################
logging.info('Creating an bulletin-matrix')

bulletins_d = dict()
full_bulletins_lst = list()
d_iter = 0
bull_iter = 0
hh_iter = 0
# из каждой строки в матрице хостов "ХОСТ-[СПИСОК_БЮЛЛЕТЕНЕЙ]" (уровень 1)
for d in h_matrix:
    d_iter += 1
    # todo: логирование обработки каждой стрки в матрице?
    try:
        # обрабатыватываем поочередно каждый бюллетень из [СПИСОК_БЮЛЛЕТЕНЕЙ] (уровень 2)
        # todo: может быть стоит проверить что на хосте есть бюллетени, а не безусловно счтать что они есть?
        for bull in d['h_bulletins']:
            bull_iter += 1
            hh_list = list()
            # и теперь ищем этот бюллетень во всей _матрице_ хостов "ХОСТ-[СПИСОК_БЮЛЛЕТЕНЕЙ]" (уровень 3)
            for hh in h_matrix:
                hh_iter += 1
                # если встречается хоть раз - имя хоста, у которого бюллетень встречается, заносим во временный список
                cnt = hh['h_bulletins'].count(bull)
                if cnt > 0:
                    hh_list.append(hh['v_name'])

            # формируем словарь "БЮЛЛЕТЕНЬ-[СПИСОК_ХОСТОВ]" (обратный от уровня 1) и общий список
            bulletins_d = {'bull': bull, 'hosts': hh_list}
            # формируем список словарей (сырую матрицу) "БЮЛЛЕТЕНЬ-[СПИСОК_ХОСТОВ]" (обратную от host_matrix)
            full_bulletins_lst.append(bulletins_d)
    except Exception as e:
        logging.warning('Skipping entrie {}. Exception: {}'.format(bull_iter, e))
        continue
logging.info('Processed hosts: {}'.format(d_iter))


# оставляем только уникальные записи в списке (итоговая матрица)
b_matrix = uniq_list(full_bulletins_lst)

# формируем пакет LLD-данных
logging.info('Сreating an LLD-data for bulletin monitoring')

discovery_data = list()
# для каждого бюллетеня (строки) в матрице бюллетеней строим LLD-json c кол-вом хостов, именем, баллами, влиянием
for b in b_matrix:
    affected_h_cnt = len(b['hosts'])
    bullentin_name = b['bull']['name']
    bulletin_score = b['bull']['score']
    bulletin_impact = int(affected_h_cnt * bulletin_score)

    # пишем данные касательно кол-ва хостов, затронутых этим бюллетенем
    f.write('\"{}\" vulners.bulletin[{}] {}\n'.format(zbx_h_bulls, bullentin_name, affected_h_cnt))

    # формируем LLD-JSON
    discovery_data.append({'{#BULLETIN.ID}': bullentin_name,
                           '{#BULLETIN.SCORE}': bulletin_score,
                           '{#BULLETIN.AFFECTED}': affected_h_cnt,
                           '{#BULLETIN.IMPACT}': bulletin_impact,
                           '{#BULLETIN.HOSTS}': '\n'.join(b['hosts'])})

# преобразовываем в однострочный json без пробелов и пишем в файл
discovery_json = (json.dumps({'data': discovery_data})).replace(': ', ':').replace(', ', ',')

f_lld.write('\"{}\" vulners.bulletins_lld {}\n'.format(zbx_h_bulls, discovery_json))

logging.info('Сreating an CVSS Score-based host-lists')
score_list = list()

host_count_table = dict((score_value, 0) for score_value in range(0, 11))
for h in h_matrix:
    score_list.append(h['h_score'])
    score = float(h['h_score'])
    host_count_table[int(score)] += 1

# если вдруг список с баллами хостов пуст, пишем в него '0'
if len(score_list) == 0:
    score_list = [0]

logging.info('Сreating an aggregated data')
# считаем аггрегированыне метрики и пишем их в файл
agg_score_median = median(map(float, score_list))
agg_score_mean = mean(map(float, score_list))
agg_score_max = max(map(float, score_list))
agg_score_min = min(map(float, score_list))

for intScore in host_count_table:
    f.write('\"{}\" vulners.hostsCountScore{} {}\n'.format(zbx_h_stats, intScore, host_count_table.get(intScore)))
f.write('\"{}\" vulners.hostsCount {}\n'.format(zbx_h_stats, total_hosts))
f.write('\"{}\" vulners.scoreMedian {}\n'.format(zbx_h_stats, agg_score_median))
f.write('\"{}\" vulners.scoreMean {}\n'.format(zbx_h_stats, agg_score_mean))
f.write('\"{}\" vulners.scoreMax {}\n'.format(zbx_h_stats, agg_score_max))
f.write('\"{}\" vulners.scoreMin {}\n'.format(zbx_h_stats, agg_score_min))

f.close()
f_lld.close()

# пушим в заббикс полученные баллы и фиксы для всех хостов
push_lld_cmd = '{} -z {} -p {} -i {}'.format(z_sender_bin, zbx_server_fqdn, zbx_server_port, zsender_lld_file)
push_cmd = '{} -z {} -p {} -i {}'.format(z_sender_bin, zbx_server_fqdn, zbx_server_port, zsender_data_file)

if args.BypassZbxPush:
    logging.info('The transfer of data to zabbix is disabled, but can be performed by commands:')
    logging.info('{}; sleep 300; {}'.format(push_lld_cmd, push_cmd))
else:
    logging.info('Pushing LLD-objects to Zabbix: {}'.format(push_lld_cmd))
    logging.info(shell(push_lld_cmd))

    # чтобы LLD-метрики в Zabbix успели создаться нужен небольшой таймаут
    logging.info('sleep for 5 min')
    sleep(300)

    logging.info('Pushing data to Zabbix: {}'.format(push_cmd))
    logging.info(shell(push_cmd))

logging.info('Work completed successfully')
