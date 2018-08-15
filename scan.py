#!/usr/bin/env python3

"""Zabbix vulnerability assessment plugin."""

__author__ = 'samosvat'
__version__ = '1.3.4'

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

import vulners

from readconfig import *


vulners_url = 'https://vulners.com/api/v3/audit/audit/'
jpath_mask = 'data.packages.*.*.*'

zsender_lld_file = work_dir + '/lld.zbx'
zsender_data_file = work_dir + '/data.zbx'
h_matrix_dumpfile = work_dir + '/dump.bin'

parser = argparse.ArgumentParser(description='Vulners to zabbix integration tool')


parser.add_argument(
    '-n', '--nopush',
    help='Bypass Zabbix-server. Don\'t push final dataset to Zabbix-server.',
    action='store_true')


parser.add_argument(
    '-d', '--dump',
    help='Dump zabbix and vulners data to disk',
    action='store_true')

parser.add_argument(
    '-l', '--limit',
    type=int,
    help='Host limit for processing. Only the specified number of hosts will be received from the Zabbix.')


args = parser.parse_args()


logger = logging.getLogger("ZTC")
if debug_level == 0:
    logger.setLevel(logging.ERROR)
elif debug_level == 2:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)

fh = logging.FileHandler(log_file)

formatter = logging.Formatter('%(asctime)s  %(name)s  %(levelname)s  %(message)s  [%(filename)s:%(lineno)d]')
fh.setFormatter(formatter)

logger.addHandler(fh)


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
        logger.warning('Excluded {}. Exception: {}'.format(host_name, e))
        return False
    logger.info('Excluded {}. ОS: {}, Version: {}, Packages: {}'.format(host_name, os, version, len(packages)))
    return False


def dump_create(filename, obj):
    with open(filename, 'wb') as file:
        pickle.dump(obj, file)
    return True


def dump_load(filename):
    with open(filename, 'rb') as file:
        obj = pickle.load(file)
    return obj


# logger.info('Start.')
logger.info('Start.')
try:
    vapi = vulners.Vulners(api_key=vuln_api_key)
except Exception as e:
    logger.error('Error: Used API key: {}. {} '.format(vuln_api_key, e))
    exit(1)

# создаем сессию в заббикс
try:
    zapi = ZabbixAPI(zbx_url, timeout=10)
    zapi.session.verify = zbx_verify_ssl
    zapi.login(zbx_user, zbx_pass)
    logger.info('Connected to Zabbix API v.{}'.format(zapi.api_version()))
except Exception as e:
    logger.error('Error: Can\'t connect to Zabbix API. Exception: {}'.format(e))
    exit(1)

# Если матрица хостов есть - загружаем дамп с диска
if os.path.exists(h_matrix_dumpfile):
    logger.info('Found a dump of the h_matrix in {}. Loading'.format(h_matrix_dumpfile))
    h_matrix = dump_load(h_matrix_dumpfile)
    total_hosts = len(h_matrix)
else:
    # если дампа матрицы на диске нет - формируем (исходные данные из zabbix и затем обогащаем их через vulners)
    total_hosts = 0
    try:
        tmpl_id = zapi.template.get(filter={'host': tmpl_host})[0]['templateid']
        if args.limit is None:
            h_matrix = zapi.host.get(templated_hosts=False, templateids=tmpl_id, monitored_hosts=True, output=['hostid'])
        else:
            logger.info('\"limit\" option is used. Fetching data from Zabbix is limited to {} hosts.'.format(args.limit))
            h_matrix = zapi.host.get(templated_hosts=False, templateids=tmpl_id, limit=args.limit, monitored_hosts=True, output=['hostid'])
    except Exception as e:
        logger.error('Error: Can\'t get data from Zabbix. Exception: {}'.format(e))
        exit(1)

    full_hosts = len(h_matrix)
    logger.info('Received from Zabbix {} hosts for processing'.format(full_hosts))

    logger.info('Receiving extended data about hosts from Zabbix')
    current_host = 0
    for h in h_matrix:
        current_host += 1
        try:
            host = zapi.host.get(filter={'hostid': h['hostid']}, output=['host', 'name'])[0]
            h.update({'host_name': host['host'], 'v_name': host['name']})

            items = zapi.item.get(hostids=h['hostid'], search={'key_': tmpl_macros_name}, output=['name', 'lastvalue'])
            for i in items:
                h.update({i['name']: i['lastvalue']})

            # Костыль! Вулнерс почему то не умеет обрабатывать "ol"
            h.update({'OS - Name': re.sub('ol', 'oraclelinux', h['OS - Name'])})

            logger.info('[{} of {}] \"{}\". Successfully received extended data'
                         .format(current_host, full_hosts, h['v_name']))
        except Exception as e:
            h.update({'OS - Packages': '', 'OS - Name': '', 'OS - Version': '', 'v_name': '', 'host_name': ''})
            logger.warning('[{} in {}] Skip, can\'t get additional data about hostid {}. Exception: {}'
                            .format(current_host, full_hosts, h['hostid'], e))
            continue
    logger.info('Processed hosts: {}.'.format(current_host))

    logger.info('Checking data from Zabbix')
    # удаляем невалидные элементы данных из матрицы (там где триплет с хоста не подходящй)
    h_matrix[:] = [h for h in h_matrix if os_data_valid(h['OS - Name'], h['OS - Version'], h['OS - Packages'], h['v_name'])]
    total_hosts = len(h_matrix)
    removed_cnt = full_hosts - total_hosts
    logger.info('After checking data from Zabbix, there are {} entries left. Removed {}'.format(total_hosts, removed_cnt))

    # обогащаем матрицу данными от вулнерса
    logger.info('Receiving the vulnerabilities from Vulners')
    current_host = 0
    for h in h_matrix:
        current_host += 1
        try:
            # идем в вулнерс и получем там уязвимости для списка пакетов и ОС
            vulnerabilities = vapi.audit(os=h['OS - Name'], os_version=h['OS - Version'], package=h['OS - Packages'].splitlines())
            if vulnerabilities.get('errorCode', 0) == 0:
                h.update({'vuln_data': {'data': vulnerabilities, 'result': 'OK'}})
                logger.info('[{} of {}] \"{}\". Successfully received data from Vulners'
                             .format(current_host, total_hosts, h['v_name']))
            else:
                h.update({'vuln_data': {'data': vulnerabilities, 'result': 'FAIL'}})
                logger.info('[{} of {}] \"{}\". Can\'t receive data from Vulners. Error message: {}'
                             .format(current_host, total_hosts, h['v_name'], vulnerabilities.get('error', 0)))
        except Exception as e:
            h.update({'vuln_data': {'data': '', 'result': 'FAIL'}})
            logger.warning('[{} of {}] \"{}\". Error getting data from Vulners. Exception: {}'.format(current_host, total_hosts, h['v_name'], e))
            continue
    logger.info('Processed hosts: {}'.format(current_host))

    logger.info('Exclude invalid response data from Vulners')
    # удаляем невалидные элементы данных из матрицы (там где ответ вулнерс не подходящй)
    h_matrix[:] = [h for h in h_matrix if h['vuln_data']['result'] == 'OK']
    removed_cnt = total_hosts - len(h_matrix)
    total_hosts = len(h_matrix)
    logger.info('There are {} entries left. Removed: {}'.format(total_hosts, removed_cnt))


    if args.dump:
        try:
            # сохраняем дамп матрицы хостов на диск
            dump_create(h_matrix_dumpfile, h_matrix)
            logger.info('host-matrix saved to {}'.format(h_matrix_dumpfile))
        except Exception as e:
            logger.warning('Can\'t dump host-matrix to disk. Exception: {}'.format(e))

if len(h_matrix) == 0:
    logger.info('There are no data in the host-matrix for further processing. Exit')
    exit()

logger.info('Сreating an additional field in the host-matrix based on data from Vulners')
# формируем доп-поля в матрице на основе данных от вулнерса
current_host = 0
for h in h_matrix:
    current_host += 1
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

        logger.info('[{} of {}] \"{}\". Successfully processed'.format(current_host, total_hosts, h['v_name']))
    except Exception as e:
        logger.warning('[{} of {}] \"{}\". Skipping. Exception: {}'.format(current_host, total_hosts, h['v_name'], e))
        continue
logger.info('Processed hosts: {}'.format(current_host))

f = open(zsender_data_file, 'w')
f_lld = open(zsender_lld_file, 'w')

logger.info('Сreating an LLD-data: CVSS-Scores and Cumulative-Fix commands')
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
        logger.warning('[{} of {}] \"{}\". Skipping. Exception: {}'.format(current_host, total_hosts, h['v_name'], e))
        continue

# преобразовываем список в однострочный json без пробелов и пишем в файл
discovery_hosts_json = (json.dumps({'data': discovery_hosts})).replace(': ', ':').replace(', ', ',')

f_lld.write('\"{}\" vulners.hosts_lld {}\n'.format(zbx_h_hosts, discovery_hosts_json))

###########################
# ФОРМИРУЕМ МАТРИЦУ ПАКЕТОВ
###########################
logger.info('Creating a matrix of vulnerable packages of all hosts')

# цель - найти все хосты, на которых зааффектило этот пакет, для этого
pkg_matrix_tmp = list()
# для каждой строки в матрице
row_iter = 0
p_row_iter = 0
h_row_iter = 0
pp_iter = 0
for row in h_matrix:
    row_iter += 1
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
        if len(row['h_packages']) > 0:
            logger.info('[{} of {}] \"{}\". Successfully processed vulnerable packages: {}'.format(row_iter, total_hosts, row['v_name'], len(row['h_packages'])))
        else:
            logger.info('[{} of {}] \"{}\". No vulnerable packages found'.format(row_iter, total_hosts, row['v_name']))
    except Exception as e:
        logger.warning('[{} of {}] \"{}\". Skipping. Exception: {}'.format(row_iter, total_hosts, row['v_name'], e))
        continue
logger.info('Processed hosts: {}'.format(row_iter))
pkg_matrix = uniq_list(pkg_matrix_tmp)
logger.info('Unique vulnerable packages processed: {}'.format(len(pkg_matrix)))


# формируем пакет LLD-данных
logger.info('Сreating an LLD-data for package monitoring')

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
logger.info('Creating an bulletin-matrix')

bulletins_d = dict()
full_bulletins_lst = list()
d_iter = 0
bull_iter = 0
hh_iter = 0
# из каждой строки в матрице хостов "ХОСТ-[СПИСОК_БЮЛЛЕТЕНЕЙ]" (уровень 1)
for d in h_matrix:
    d_iter += 1
    try:
        # обрабатыватываем поочередно каждый бюллетень из [СПИСОК_БЮЛЛЕТЕНЕЙ] (уровень 2)
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

        if len(d['h_bulletins']) > 0:
            logger.info('[{} of {}] \"{}\". Successfully processed security bulletins: {}'.format(d_iter, total_hosts, d['v_name'], len(d['h_bulletins'])))
        else:
            logger.info('[{} of {}] \"{}\". No security bulletins found'.format(d_iter, total_hosts, d['v_name']))
    except Exception as e:
        logger.warning('[{} of {}] \"{}\". Skipping. Exception: {}'.format(d_iter, total_hosts, d['v_name'], e))
        continue
logger.info('Processed hosts: {}'.format(d_iter))

# оставляем только уникальные записи в списке (итоговая матрица)
b_matrix = uniq_list(full_bulletins_lst)
logger.info('Unique security bulletins processed: {}'.format(len(b_matrix)))

# формируем пакет LLD-данных
logger.info('Сreating an LLD-data for bulletin monitoring')

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

logger.info('Сreating an CVSS Score-based host-lists')
score_list = list()

host_count_table = dict((score_value, 0) for score_value in range(0, 11))
for h in h_matrix:
    score_list.append(h['h_score'])
    score = float(h['h_score'])
    host_count_table[int(score)] += 1

# если вдруг список с баллами хостов пуст, пишем в него '0'
if len(score_list) == 0:
    score_list = [0]

logger.info('Сreating an aggregated data')
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

if args.nopush:
    logger.info('\"nopush\" option is used. The transfer of data to zabbix is disabled, but can be performed by commands:')
    logger.info('{}; sleep 300; {}'.format(push_lld_cmd, push_cmd))
else:
    logger.info('Pushing LLD-objects to Zabbix: {}'.format(push_lld_cmd))
    logger.info(shell(push_lld_cmd))

    # чтобы LLD-метрики в Zabbix успели создаться нужен небольшой таймаут
    logger.info('sleep for 5 min')
    sleep(300)

    logger.info('Pushing data to Zabbix: {}'.format(push_cmd))
    logger.info(shell(push_cmd))

logger.info('Work completed successfully')
