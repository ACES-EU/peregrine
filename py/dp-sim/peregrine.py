#!/usr/bin/env python3

from pipeline_kitnet import PipelineKitNET
import argparse
import time
import yaml

if __name__ == "__main__":
    argparser = argparse.ArgumentParser(description="peregrine-py")
    argparser.add_argument('-c', '--conf', type=str, help='Config path')
    args = argparser.parse_args()

    with open(args.conf, "r") as yaml_conf:
        conf = yaml.load(yaml_conf, Loader=yaml.FullLoader)

    time_start = time.time()

    # Call function to run the packet processing pipeline.
    pipeline = PipelineKitNET(conf['iface'],
                              conf['trace'],
                              conf['sampl'],
                              conf['train_pkt_cnt'],
                              conf['train_stats'],
                              conf['dataset'],
                              conf['attack'])

    pipeline.process()

    time_stop   = time.time()
    total_time  = time_stop - time_start

    print('Complete. Time elapsed: ', total_time)
    print('Done.')
