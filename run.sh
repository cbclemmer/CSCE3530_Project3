#!/bin/bash

rm totally_not_my_privateKeys.db
rm aes_*

. ./export_key.sh
python main.py
