#!/usr/bin/env python3
import os

from re import compile, findall
from subprocess import PIPE, run
from time import sleep

from prometheus_client import Gauge, start_http_server
from prometheus_client.core import REGISTRY, GaugeMetricFamily


addr = os.getenv('LISTEN_ADDRESS', 'localhost')
port = int(os.getenv('LISTEN_PORT', 9180))
cmd =  os.path.join(os.getenv('EXEC_PATH', '/usr/bin/'), 'fail2ban-client')
comp = compile(r'\s([a-zA-Z\s]+):\t([a-zA-Z0-9-,\s]+)\n')


class GaugeCollector(object):

    def collect(self):
        for jail in self.get_jails(self.extract_data()):
            jail = jail.strip()
            g = GaugeMetricFamily("fail2ban_{}".format(
                self.snake_case(jail)), "", labels=['type'])
            for label, value in self.extract_data(jail):
                g.add_metric(
                    [self.snake_case(label)], float(value))
            yield g

    def get_jails(self, jails):
        return jails[1][1].split(",")

    def extract_data(self, jail=None):
        args = [cmd, "status"]
        if jail:
            args.append(jail)
        r = run(args, stdout=PIPE, check=True)
        return findall(comp, ''.join(bytes(r.stdout).decode('utf-8')).lower())

    def snake_case(self, string):
        return string.strip().replace("-", "_").replace(" ", "_")


# Code execution starts from here
start_http_server(port, addr)
REGISTRY.register(GaugeCollector())
while True:
    sleep(10)
