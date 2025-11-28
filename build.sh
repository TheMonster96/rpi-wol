#!/bin/bash

set -e 


sudo systemctl stop rpi-wol.service && make && sudo systemctl daemon-reload && sudo systemctl restart rpi-wol.service
