#!/usr/bin/env python3
from re import compile, findall
from subprocess import PIPE, run
from time import sleep
from os import getenv

from prometheus_client import Gauge, start_http_server
from prometheus_client.core import REGISTRY, GaugeMetricFamily


addr = getenv('LISTEN_ADDRESS', 'localhost')
port = getenv('LISTEN_PORT', 9180)
path = getenv('EXEC_PATH', '/usr/bin/')
cmd = "{path}fail2ban-client status {service}"
comp = compile(r'\s([a-zA-Z\s]+):\t([a-zA-Z0-9-,\s]+)\n')


def extract_data(jail=""):
    r = run(cmd.format(path=path, service=jail),
            stdout=PIPE, check=True, shell=True)
    return findall(comp, ''.join(bytes(r.stdout).decode('utf-8')).lower())


def get_jails(jails):
    return str(jails[1][1]).split(",")


class GaugeCollector(object):
    def collect(self):
        for jail in get_jails(extract_data()):
            for label, value in extract_data(jail):
                yield GaugeMetricFamily("fail2ban_{}_{}".format(jail.strip(), label.replace(" ", "_")),
                                        "", float(value))


# Code execution starts from here
start_http_server(port, addr)
REGISTRY.register(GaugeCollector())
while True:
    sleep(10)
