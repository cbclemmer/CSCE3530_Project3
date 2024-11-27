#!/bin/bash

. ./export_key.sh

python -m coverage run -m unittest unit_tests.py
python -m coverage report -m
