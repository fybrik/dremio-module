#
# Copyright 2020 IBM Corp.
# SPDX-License-Identifier: Apache-2.0
#
from timeit import repeat
#import pyarrow.flight as fl
import json
import threading

import csv
import urllib.request
import yaml
import requests



def main(config_path, data_set):
    r = requests.get('http://localhost:8000/' + data_set)
    print(r.text)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='arrow-flight-module sample')
    parser.add_argument(
        '-c', '--config', type=str, default='/etc/conf/conf.yaml', help='Path to config file')
    parser.add_argument(
        '--data', type=str, default='MedalsWinners', help='name of data set')
    args = parser.parse_args()

    main(args.config, args.data)
