# Peregrine

Peregrine is an ML-based malicious traffic detector for Terabit networks that runs the detection process partially in the network data plane. Specifically, Peregrine offloads the detector’s ML feature computation to a commodity switch. The Peregrine switch processes a diversity of features per-packet, at Tbps line rates to feed the ML-based component in the control plane. While, in practice, current IDS systems sample raw traffic, in Peregrine sampling occurs after feature computation. This essential trait enables computing features over all traffic, significantly enhancing detection performance.

The calculated features are sent to the control plane following a per-epoch approach: at the end of each epoch (according to an operator-defined value), a features record is sent to the server with all computed features to trigger ML-based detection - the downsampling required to reconcile the traffic rates of the switch and the server.
The subsequent machine learning-based classification is then performed at the control plane level.

This repository contains data plane implementations for the Tofino Native Architecture: Tofino 1 (TNA) and Tofino 2 (T2NA), along with a control plane module that receives the data plane features and feeds them to a ML classification engine - KitNET. The control plane module receives as input a previously-trained model (e.g., from the Kitsune dataset's Mirai attack trace).

## Requirements

- Intel Tofino SDE

Tested Versions:

- TNA:  9.7.0
- T2NA: 9.12.0

## Compilation

### TNA

```
$SDE_INSTALL/bin/bf-p4c -g --verbose 2 -o $PEREGRINE_REPO_DIR/p4/tna/build $PEREGRINE_REPO_DIR/p4/tna/peregrine.p4
```

### T2NA

```
$SDE_INSTALL/bin/bf-p4c -g --verbose 2 -b tofino2 -o $PEREGRINE_REPO_DIR/p4/t2na/build $PEREGRINE_REPO_DIR/p4/t2na/peregrine.p4
```

## Execution

Both and TNA and T2NA implementation contains constant P4 match-action rules defined within the code, dispensing the need for an initial configuration through a controller.

An example execution for the TNA implementation using the SDE is as follows:

### Setup virtual interfaces.

```
$ $SDE/install/bin/veth_setup.sh
```

### Start the Tofino model.

```
$ ./run_tofino_model.sh --arch tofino -p ~/peregrine/p4/tna/peregrine.p4 -c ~/peregrine/p4/tna/build/peregrine.conf
```

### Start Switchd.

```
$ ./run_switchd.sh -p peregrine
```

### Start control plane module.

```
cd py/
$ python3 controller.py --cur_veth #INCOMING_PKT_VETH --max_ae $MAX_AE --fm_model $FM_PATH --el_model $EL_PATH --ol_model $OL_PATH --train_stats $TRAIN_STATS_PATH --thres $THRES_PATH --attack $CUR_ATTACK_NAME
```

