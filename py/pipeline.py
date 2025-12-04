import sys
import json
import itertools
import pandas as pd
from datetime import datetime
from scapy.all import sniff, bind_layers, TCP, UDP, ICMP, Ether, IP
from peregrine import Peregrine
from peregrine_header import PeregrineHdr

# KitNET parameters

learning_rate   = 0.1
hidden_ratio    = 0.75

# Peregrine parameters

lambdas     = 4     # Active decay values in the data plane.
cur_stats   = []    # Custom header stats from the last received packet.
pkt_header  = []    # Header fields from the last received packet.

# Data plane-based global packet counter.
# Needed to keep track of the total pkt num, as not all pkts are sent to the control plane.
pkt_cnt_global = 0

def pkt_callback(pkt):
    global cur_stats
    cur_stats = 0

    if PeregrineHdr in pkt:
        global pkt_header
        global pkt_cnt_global
        pkt_cnt_global += 1

        cur_stats = [[pkt[PeregrineHdr].decay,
                      pkt[PeregrineHdr].mac_ip_src_pkt_cnt,
                      pkt[PeregrineHdr].mac_ip_src_mean,
                      pkt[PeregrineHdr].mac_ip_src_std_dev,
                      pkt[PeregrineHdr].ip_src_pkt_cnt,
                      pkt[PeregrineHdr].ip_src_mean,
                      pkt[PeregrineHdr].ip_src_std_dev,
                      pkt[PeregrineHdr].ip_pkt_cnt,
                      pkt[PeregrineHdr].ip_mean_0,
                      pkt[PeregrineHdr].ip_std_dev_0,
                      pkt[PeregrineHdr].ip_magnitude,
                      pkt[PeregrineHdr].ip_radius,
                      pkt[PeregrineHdr].ip_sum_res_prod_cov,
                      pkt[PeregrineHdr].ip_pcc,
                      pkt[PeregrineHdr].five_t_pkt_cnt,
                      pkt[PeregrineHdr].five_t_mean_0,
                      pkt[PeregrineHdr].five_t_std_dev_0,
                      pkt[PeregrineHdr].five_t_magnitude,
                      pkt[PeregrineHdr].five_t_radius,
                      pkt[PeregrineHdr].five_t_sum_res_prod_cov,
                      pkt[PeregrineHdr].five_t_pcc]]

        pkt_header = [str(pkt[Ether].src),
                      str(pkt[IP].src),
                      str(pkt[IP].dst),
                      str(pkt[IP].proto)]

        if UDP in pkt:
            pkt_header.append(str(pkt[UDP].sport))
            pkt_header.append(str(pkt[UDP].dport))
        elif TCP in pkt:
            pkt_header.append(str(pkt[TCP].sport))
            pkt_header.append(str(pkt[TCP].dport))
        else:
            pkt_header.append('0')
            pkt_header.append('0')
        cur_stats.insert(0, pkt_header)

def pkt_pipeline(cur_eg_veth, max_ae, fm_model, el_model, ol_model,
                 train_stats, thres_path, attack):
    global cur_stats
    global pkt_header
    global pkt_cnt_global

    bind_layers(UDP, PeregrineHdr)
    bind_layers(TCP, PeregrineHdr)
    bind_layers(ICMP, PeregrineHdr)

    threshold = 0

    with open(thres_path, 'r') as f:
        threshold = f.readline()


    # Build Peregrine.
    peregrine = Peregrine(max_ae, learning_rate, hidden_ratio, lambdas,
                          fm_model, el_model, ol_model, train_stats, attack)

    # Process the trace, packet by packet.
    while True:
        cur_stats = -1

        if pkt_cnt_global % 1000 == 0:
            print('Processed packets: ', fm_grace + ad_grace + pkt_cnt_global)

        # Execution phase.
        else:
            # Execution: data plane
            # Callback function to retrieve the packet's custom header.
            sniff(iface=cur_eg_veth, count=1, prn=pkt_callback, timeout=60)

        # If any statistics were obtained, send them to the ML pipeline.
        if cur_stats != -1:
            if cur_stats == 0:
                continue

            # Flatten the statistics' list of lists.
            cur_stats = list(itertools.chain(*cur_stats))
            cur_stats_global.append(cur_stats)

            # Call function with the content of kitsune's main (before the eval/csv part).
            rmse = peregrine.proc_next_packet(cur_stats)

            # ---------- json ----------

            if rmse > threshold:
                output_json(cur_stats)

            # --------------------------

            rmse_list.append(rmse)

            peregrine_eval.append([cur_stats[0], cur_stats[1], cur_stats[2], cur_stats[3],
                                   cur_stats[4], cur_stats[5], rmse])
        else:
            print('TIMEOUT.')
            break

    return [rmse_list, cur_stats_global, peregrine_eval, threshold]

def output_json(cur_stats):
        ts_datetime = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]

        # Get current flow headers

        ip_src      = cur_stats[1]
        ip_dst      = cur_stats[2]
        ip_proto    = cur_stats[3]
        port_src    = cur_stats[4]
        port_dst    = cur_stats[5]

        # Generate json

        output_json = {
            "timestamp": ts_datetime,
            "data": {
                "ip_src": ip_src,
                "ip_dst": ip_dst,
                "ip_proto": ip_proto,
                "port_src": port_src,
                "port_dst": port_dst,
                "prediction": "MALICIOUS FLOW"
            },
            "model": "KitNET"
        }

        outdir = str(Path(__file__).parents[0]) + '/json'
        if not os.path.exists(str(Path(__file__).parents[0]) + '/json'):
            os.mkdir(outdir)

        with open(f'json/alert-{ts_datetime}.json', mode="w", encoding="utf-8") as wf:
            json.dump(output_json, wf)
