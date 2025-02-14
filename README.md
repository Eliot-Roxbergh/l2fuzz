# L2Fuzz

A stateful fuzzer to detect vulnerabilities in Bluetooth BR/EDR Logical Link Control and Adaptation Protocol (L2CAP) layer.


## Prerequisites

L2Fuzz targets L2CAP on Bluetooth Classic. It uses any (the first?) Bluetooth dongle/device available to the system.

```bash
# Installation
sudo apt-get install bluetooth libbluetooth-dev python3-pip -y
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

L2Fuzz original repo used python3.6.9 and scapy 2.4.4 (if something breaks rollback to these versions?).

## Running the tests: command line
```
sudo su
source venv/bin/activate

# Interactive mode
python3 l2fuzz.py

# Target specific port
# arg 1: target mac
# arg 2: numeric index of profile starting at 0
python3 l2fuzz.py AA:BB:CC:DD:EE:FF 0

# Scan ONLY services
# arg 2: "scan-only"
python3 l2fuzz.py AA:BB:CC:DD:EE:FF scan-only

# Scan all services on ports that seem open
./fuzz_all_ports.sh AA:BB:CC:DD:EE:FF
```

## Running the tests: interactive mode

1. move to L2Fuzz folder.
2. run l2fuzz.py .
```
sudo su
source venv/bin/activate
python3 l2fuzz.py
```
3. Choose target device.
```
Reset Bluetooth...
Performing classic bluetooth inquiry scan...

	Target Bluetooth Device List
	[No.]	[BT address]		  [Device name]		[Device Class]	  	[OUI]
	00.	AA:BB:CC:DD:EE:FF	  DESKTOP       	Desktop   	      	Vendor A
	01.	11:22:33:44:55:66	  Smartphone    	Smartphone	      	Vendor B
	Found 2 devices

Choose Device : 0
```
4. Choose target service which is supported by L2CAP.

```
Start scanning services...

	List of profiles for the device
	00. [0x0000]: Service A
	01. [0x0001]: Service B
	02. [0x0002]: Service C
	03. [0x0003]: Service D
	04. [0x0004]: Service E
	05. [0x0005]: Service F

Select a profile to fuzz : 4
```
5. Fuzz testing start.

### End test

The test does not end by itself, interrupt to print logs and exit:

```
Ctrl + C
```

### Log file

The log file will only be generated after the fuzz testing is complete, stored in the L2Fuzz folder.

On a detected crash, further pings are sent, if and only if these also fail is the packet noted as a "crash" in the log.
Otherwise, the crash is not marked as such, likely since single failures could be due to interference or issues with the local adapter.

## Paper

L2Fuzz paper is published in Jun 27, 2022 through "The 52nd Annual IEEE/IFIP International Conference on Dependable Systems and Networks".

Title : L2Fuzz: Discovering Bluetooth L2CAP Vulnerabilities Using Stateful Fuzz Testing

Paper : https://arxiv.org/abs/2208.00110

Video : https://youtu.be/lrc-mJTw1yM

Authors : Haram Park (Korea University), Carlos Nkuba Kayembe (Korea University), Seunghoon Woo (Korea University), Heejo Lee (Korea University)

Contacts : freehr94@korea.ac.kr, https://ccs.korea.ac.kr/
