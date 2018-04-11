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


class GaugeCollector(object):

    def collect(self):
        for jail in self.get_jails(self.extract_data()):
            g = GaugeMetricFamily("fail2ban_{}".format(
                self.snake_case(jail)), "", labels=['type'])
            for label, value in self.extract_data(jail):
                g.add_metric(
                    [self.snake_case(label)], float(value))
            yield g

    def get_jails(self, jails):
        return jails[1][1].split(",")

    def extract_data(self, jail=""):
        r = run(cmd.format(path=path, service=jail),
                stdout=PIPE, check=True, shell=True)
        return findall(comp, ''.join(bytes(r.stdout).decode('utf-8')).lower())

    def snake_case(self, string):
        return string.strip().replace("-", "_").replace(" ", "_")


# Code execution starts from here
start_http_server(port, addr)
REGISTRY.register(GaugeCollector())
while True:
    sleep(10)
