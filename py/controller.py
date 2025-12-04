#!/usr/bin/env python3

import os
import sys
import logging
import argparse
import json
import random
import time
import pipeline
from pathlib import Path
from pipeline import pkt_pipeline


if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description="Peregrine controller.")
    argparser.add_argument('--cur_veth', type=str)
    argparser.add_argument('--max_ae', type=int, default=10, help='KitNET: m value')
    argparser.add_argument('--fm_model', type=str, default=None, help='Prev. trained FM model path')
    argparser.add_argument('--el_model', type=str, default=None, help='Prev. trained EL path')
    argparser.add_argument('--ol_model', type=str, default=None, help='Prev. trained OL path')
    argparser.add_argument('--train_stats', type=str, default=None, help='Trained stats struct path')
    argparser.add_argument('--thres', type=str, default=None, help='Threshold path')
    argparser.add_argument('--attack', type=str, help='Current trace attack name')
    args = argparser.parse_args()

    start = time.time()

    # Packet processing pipeline.
    pipeline_out = pkt_pipeline(args.cur_veth, args.max_ae, args.fm_model, args.el_model,
                                args.ol_model, args.train_stats, args.thres, args.attack)

    stop        = time.time()
    total_time  = stop - start

    print('Complete. Time elapsed: ', total_time)

    # exit (bug workaround)
    logger.info("Exiting!")

    # flush logs, stdout, stderr
    logging.shutdown()
    sys.stdout.flush()
    sys.stderr.flush()

    # exit (bug workaround)
    # os.kill(os.getpid(), signal.SIGTERM)
