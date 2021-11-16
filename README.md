# DIKEUE

This is the public release of the code of our paper titled "Noncompliance as Deviant Behavior: An Automated Black-box Noncompliance Checker for 4G LTE Cellular Devices" (CCS'21).  

Please note that the concerned vendors are still in the process of patching the identified vulnerabilities. Upon request from the vendors, we are not releasing the modified cellular stack used in the FSM Inference module of our framework at this moment. We have, however, provided a sample adapter and a sample device code with the original statelearner to test the learner code and generate a finite state machine of the device. 
We will release the 4G LTE adapter once all the vendors confirm the completion of the responsible disclosure process. Apart from this, we are completely open-sourcing the equivalence checker with two FSMs extracted from two COTS devices (anonymized).

The paper: https://dl.acm.org/doi/10.1145/3460120.3485388

**Table of Contents**

- [Introduction](#introduction)
- [Requirements](#requirements)
- [DIKEUE Overview](#dikeue-overview)
- [FSM Inference Module](#fsm-inference-module)
  - [Learner](#learner)
  - [Adapter](#adapter)
  - [Device](#device)
- [FSM Equivalence Checker](#fsm-equivalence-checker)
- [License](#license)

# Introduction
DIKEUE is an automated black-box testing framework for 4G Long Term Evolution (LTE) control-plane protocol implementations in commercial-of-the-shelf (COTS) cellular devices (UEs). It adopts a property-agnostic differential testing approach to identify deviant behavior in UEs.  

# Requirements

- graphviz
- jdk 11
- maven
- python 2
- pydot

# DIKEUE Overview
DIKEUE has two primary components, namely, FSM inference module, and FSM equivalence checker. The FSM inference module requires blackbox access to UEs and uses active automata learning to extract the protocol state machine of UE implementations. On the other hand, the FSM equivalence checker tries to identify diverse set of deviant behavior by taking pairs of state machines generated by the prior component. Figure 1 shows the workflow of DIKEUE.

| ![overview](https://user-images.githubusercontent.com/22367466/141699623-68ce24b2-70e2-49e9-b9ae-069ced78430e.png) | 
|:--:| 
| *Figure 1: Workflow of DIKEUE* |


# FSM Inference Module
The FSM inference module contains a learner and an adapter which communicates with a UE with blackbox access. The learner generates abstract symbols which is converted to concrete packets by the adapter. Additionally, the adapter optimizes the number of over-the-air packets and resolves inconsistencies to reduce the time required for learning the finite state machine of the UE.

| ![flow drawio (1)](https://user-images.githubusercontent.com/44625877/141606854-fc371bdf-53ac-4f3b-bd62-24aceaa566f5.png) | 
|:--:| 
| *Figure 2: FSM Inference Module* |

## Learner
The learner uses active automata learning to learn the protocol state machine of the device under test. It generates many membership queries and equivalence queries to construct hypthesis models and to check for their validity. To run the learner, the following commands can be used: 

```bash
cd "FSM Learner Module/statelearner/"
mvn package shade:shade
java -jar target/stateLearner-0.0.1-SNAPSHOT.jar src/lteue.properties
```

## Adapter
The adapter optimizes the number of over-the-air queries and generates concrete packets.  Originally, it includes a modified cellular stack which can generate concrete packets according to the queries generated by the learner. However, as we are still in the process of responsible disclosure, we are not releasing the adapter codes due to security implications. Instead, we are giving a sample adapter and a sample device code to test the learner code and generate a finite state machine of the device. Figure 3 shows the modified adapter.

| ![flow drawio (3)](https://user-images.githubusercontent.com/44625877/141607348-b96a4167-8746-42cc-a268-35fe3aea4a4d.png) | 
|:--:| 
| *Figure 3: Modified FSM Inference Module* |

In this version, the cache resolver and inconsistency resolver is embedded to the learner module. The packet converter communicates with the sample UE through socket connection. To run the adapter, the following commands can be used: 
```bash
cd "FSM Learner Module/adapter/"
gcc -o adapter.out adapter.c
./adapter.out
```

## Device
To test the FSM inference module, we have included a sample device code. The adapter can communicate with it through socket connection. Upon receiving any messages, it replies with proper output and changes the internal states accordingly. 

To run the sample device code, the following commands can be used:
```bash
cd "FSM Learner Module/device/"
python2 device.py
```

To run the the FSM Learner Module, first you need to run the device, the adapter, followed by the learner. It takes the learner few hours to learn the underlying FSM of the device. All the FSMs will be stored in a folder `test_device` in the `FSM Learner Module/test_device` folder. All the queries will be saved in the `my_database.sqlite`. In the the learner is run again it will read queries from the database and in case the query is not found then communicate with the adapter. For running the learner from scratch the tables of the database will have to be deleted.


# FSM Equivalence Checker
The FSM equivalence checker takes two finite state machines in dot format as inputs and provides the deviating behavior inducing message sequences. We have included two sample FSMs for demonstrating the use of the component. It can be run with the following commands:
```bash
cd "FSM Equivalence Checker/"
python2 iterative-checker.py
```
Additional command line options can be viewed with: 

```bash
python2 iterative-checker.py --help
```
It takes the equivalence checker around 40-45 mins in our machine to check equivalence between the two FSMs. After the checking is done it will create two files: `FSM1_vs_FSM2_final` and `FSM1_vs_FSM2_time`. `FSM1_vs_FSM2_final` contains the deviating queries for the same input symbol. `FSM1_vs_FSM2_time` contains the timing for each round of model checking with nuXmv. The Folder already includes a nuXmv binary so installing nuXmv is not required.


# License
This work is licensed under Apache License 2.0. Please refer to the [license file](https://github.com/SyNSec-den/DIKEUE/blob/main/LICENSE) for details.
