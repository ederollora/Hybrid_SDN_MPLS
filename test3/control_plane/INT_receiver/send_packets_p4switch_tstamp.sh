#!/bin/bash
while true
do
    sudo python ~/revision/new_LDP_cp/send_p.py ens1f2 10.0.0.1 10.0.0.2 FEDCBA
    sudo python ~/revision/new_LDP_cp/send_p.py ens1f2 10.0.0.10 10.0.0.20 FEDCBA
    sleep 0.5
done
