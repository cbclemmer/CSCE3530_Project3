#!/bin/bash

python generate_aes_key.py
export NOT_MY_KEY=$(cat aes_key.bin)