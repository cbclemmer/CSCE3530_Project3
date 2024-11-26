#!/bin/bash

python -m coverage run -m unittest unit_tests.py
python -m coverage report -m
