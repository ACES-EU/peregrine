import os
import time
import pickle
import itertools
import numpy as np
import pandas as pd
from datetime import datetime
from pathlib import Path
from scapy.all import Ether, IP, UDP, TCP, ICMP, sendp, conf, Packet, IntField, LongField
from fc_kitnet import FCKitNET
from peregrine_header import PeregrineHdr

LAMBDAS = 4


class PipelineKitNET:
    def __init__(self, iface, trace, sampl, train_pkt_cnt, train_stats, dataset, attack):
        self.decay_to_pos = {
            0: 0, 1: 0, 2: 1, 3: 2, 4: 3,
            8192: 1, 16384: 2, 24576: 3}

        self.train_pkt_cnt  = train_pkt_cnt
        self.iface          = iface
        self.dataset        = dataset
        self.attack         = attack
        self.sampl          = sampl

        self.pkt_cnt_exec = self.train_pkt_cnt
        self.pkt_skip       = 0

        self.stats_mac_ip_src   = {}
        self.stats_ip_src       = {}
        self.stats_ip           = {}
        self.stats_five_t       = {}

        # Import the previously generated models.
        with open(train_stats, 'rb') as f_stats:
            stats                   = pickle.load(f_stats)
            self.stats_mac_ip_src   = stats[0]
            self.stats_ip_src       = stats[1]
            self.stats_ip           = stats[2]
            self.stats_five_t       = stats[3]

        # Initialize feature extraction/computation.
        self.fc = FCKitNET(trace, sampl, self.train_pkt_cnt, train_stats)

        self.trace_size = self.fc.trace_size()

    def process(self):
        time_old = time.time()
        time_new = time.time()

        print('--- DP Simulator: Inference phase ---')
        print('--- Processing...')

        # Process the trace, packet by packet.
        while True:
            cur_stats = 0

            time_new = time.time()
            if (self.pkt_cnt_exec + self.pkt_skip) % 10000 == 0:
                print(f'Processed pkts: {self.pkt_cnt_exec + self.pkt_skip}. '
                      f'Elapsed time: {time_new - time_old} ')
                time_old = time_new

            # ----------------------------------------
            # Execution phase
            # ----------------------------------------

            if self.pkt_cnt_exec + self.pkt_skip >= self.trace_size:
                break

            self.fc.feature_extract()

            cur_stats = self.fc.process()

            if (self.pkt_cnt_exec - self.train_pkt_cnt) % self.sampl != 0:
                self.pkt_cnt_exec += 1
                continue

            # If any statistics were obtained, send them to the ML pipeline.
            # Execution phase: only proceed according to the sampling rate.
            if cur_stats != 0:
                # If the packet is not IPv4.
                if cur_stats == -1:
                    self.pkt_skip += 1
                    continue

                self.pkt_cnt_exec += 1

                # Flatten the statistics' list of lists.
                cur_stats = list(itertools.chain(*cur_stats))

                self.send_peregrine_pkt(self.iface, cur_stats)

                # Break when we reach the end of the trace file.
                if self.pkt_cnt_exec + self.pkt_skip >= self.trace_size:
                    break
            else:
                print("Done.")
                break

    def send_peregrine_pkt(self, iface, cur_stats):
        conf.iface  = iface
        eth         = Ether(src=cur_stats[1])
        ip          = IP(src=cur_stats[2], dst=cur_stats[3])
        l4          = ""

        if cur_stats[4] == "17":
            l4 = UDP(sport=int(cur_stats[5]), dport=int(cur_stats[6]))
        elif cur_stats[4] == "6":
            l4 = TCP(sport=int(cur_stats[5]), dport=int(cur_stats[6]))
        elif cur_stats[4] == "1":
            l4 = ICMP(type=8, code=0)

        peregrine = PeregrineHdr(
            decay                   = cur_stats[7],
            mac_ip_src_pkt_cnt      = cur_stats[8],
            mac_ip_src_mean         = cur_stats[9],
            mac_ip_src_std_dev      = cur_stats[10],
            ip_src_pkt_cnt          = cur_stats[11],
            ip_src_mean             = cur_stats[12],
            ip_src_std_dev          = cur_stats[13],
            ip_pkt_cnt              = cur_stats[14],
            ip_mean_0               = cur_stats[15],
            ip_std_dev_0            = cur_stats[16],
            ip_magnitude            = cur_stats[17],
            ip_radius               = cur_stats[18],
            five_t_pkt_cnt          = cur_stats[19],
            five_t_mean_0           = cur_stats[20],
            five_t_std_dev_0        = cur_stats[21],
            five_t_magnitude        = cur_stats[22],
            five_t_radius           = cur_stats[23],
            ip_sum_res_prod_cov     = cur_stats[24],
            ip_pcc                  = cur_stats[25],
            five_t_sum_res_prod_cov = cur_stats[26],
            five_t_pcc              = cur_stats[27],
        )

        pkt = eth / ip / l4 / peregrine

        sendp(pkt, iface=iface, verbose=False)
