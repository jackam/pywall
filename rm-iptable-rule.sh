#!/bin/bash

iptables -D OUTPUT -j NFQUEUE --queue-num 100
