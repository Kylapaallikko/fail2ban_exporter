#!/bin/bash

cp fail2ban_exporter.py /usr/local/bin/fail2ban_exporter.py
cp fail2ban_exporter.service /etc/systemd/system/fail2ban_exporter.service

chmod +x /usr/local/bin/fail2ban_exporter.py

systemctl daemon-reload
systemctl enable fail2ban_exporter
systemctl start fail2ban_exporter
