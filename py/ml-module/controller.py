#!/usr/bin/env python3

import os
import sys
import logging
import argparse
import json
import random
import time
import pipeline
import yaml
from pathlib import Path
from pipeline import pkt_pipeline


if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description="Peregrine controller.")
    argparser.add_argument('-c', '--conf', type=str, help='Config path')
    args = argparser.parse_args()

    with open(args.conf, "r") as yaml_conf:
        conf = yaml.load(yaml_conf, Loader=yaml.FullLoader)

    start = time.time()

    # Packet processing pipeline.
    pipeline_out = pkt_pipeline(conf['iface'],
                                conf['fm_grace'],
                                conf['ad_grace'],
                                conf['max_ae'],
                                conf['fm_model'],
                                conf['el_model'],
                                conf['ol_model'],
                                conf['train_stats'],
                                conf['thres'],
                                conf['attack'])

    stop        = time.time()
    total_time  = stop - start

    print('Complete. Time elapsed: ', total_time)

    # flush stdout, stderr
    sys.stdout.flush()
    sys.stderr.flush()

    # exit (bug workaround)
    # os.kill(os.getpid(), signal.SIGTERM)
