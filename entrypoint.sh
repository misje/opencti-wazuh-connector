#!/bin/sh

cd /opt/opencti-connector-wazuh
# Attemp to load a config.yml file, but don't freak out if it doesn't exist:
python3 main.py --ignore --format yaml --config config.yml
