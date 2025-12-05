#!/bin/bash

set -e 

#make && chmod +x ./backend

 make && sudo systemctl daemon-reload && sudo systemctl restart rpi-wol.service
