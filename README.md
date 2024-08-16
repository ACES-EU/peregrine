# Peregrine

Peregrine is a malicious traffic detector that leverages the programmable data plane to execute a subset of the overall intrusion detection pipeline, offloading feature computation to the switch-level.
Specifically, it performs packet header extraction and the calculation of network features, per-packet, for all packets, entirely on data plane switches.
The obtained statistics are sent to the control plane following a per-epoch approach: at the end of each epoch (according to an operator-defined value), a features record is sent to the server with all computed features to trigger ML-based detection - the downsampling required to reconcile the traffic rates of the switch and the server.
The subsequent machine learning-based classification is then performed at the control plane level.

This repository contains data plane implementations for the Tofino Native Architecture: Tofino 1 (TNA) and Tofino 2 (T2NA).

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

The T2NA implementation contains constant P4 match-action rules defined within the code, dispensing the need for an initial configuration through a controller.

An example execution for the T2NA implementation using the SDE is as follows:

### Setup virtual interfaces.

```
$ $SDE/install/bin/veth_setup.sh
```

### Start the Tofino model.

```
$ ./run_tofino_model.sh --arch tofino2 -p ~/peregrine/p4/t2na/peregrine.p4 -c ~/peregrine/p4/t2na/build/peregrine.conf
```

### Start Switchd.

```
$ ./run_switchd.sh -p peregrine
```

### Trace file replay (execution phase).

As a simple example, the following command uses `tcpreplay` to replay the a  file to `veth0`.

A constant table rule in line 104 of `t2na/peregrine.p4` (table `fwd`) defines the incoming port as 0 and the outgoing port as 4. These values can be modified as required.

```
$ tcpreplay -i veth0 $PCAP_FILE
```
