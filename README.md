# L2Fuzz

A stateful fuzzer to detect vulnerabilities in Bluetooth BR/EDR Logical Link Control and Adaptation Protocol (L2CAP) layer.

## Details

NOTE: there are many seemingly false positives with the tool and it may be misleading in that it thinks it communicates with a port/service that is in fact closed.
It is therefore strongly recommended to get access to system logs (an example is included with adb logcat).
Optionally, ensure traffic is sent as intended with Wireshark or, even better, with a method that can inspect the actual traffic sent over the air (e.g. Ubertooth).
To ensure issues are not with the local bluetooth adapter and that the target responds as intended.


The tool fuzzes several different Bluetooth states. For some states it uses the user supplied psm (port), for others
it uses a randomized psm (!), finally some states/requests may not use a psm at all.

Each request is saved to log in the working directory (only after the test completes), in a shared file for each run.
This is done once per run/target, either when the run is finished (e.g. after a certain number of requests) or upon CTRL+C by user.
When a random psm is used, the psm is printed in the package log. Otherwise, assume it is the psm given by user.

The fuzzer tries to identify a crash, depending on the host response or lack thereof.
Some transient errors, were certain connection types fails but the host is still up afterwards (ping test), are not marked as a crash in the log as they are likely false positives.
On the other hand, "hard crashes" can be found in logs by greping for crash\_info.

On each hard crash, the tool tries to run `sudo adb logcat -t <nr-of-entries-to-print>` to dump the last Android system logs to disk.
The filename includes current port (may be user-supplied, or random) and the timestamp [1] of packet.
To correlate packets in fuzzer logs with ADB logs, grep for this timestamp, as these are unique per packet.
Thereby, if you're able to confirm a system crash in a specific ADB logcat file, the offending packet can be found in the fuzzer logs, and possibly replayed (TODO: how?) or further investigated.

The script `fuzz_all_ports.sh` may be used to fuzz all detected ports on target.
It uses both SDP and manual scanning to identify all ports on target, and runs the fuzzer for each.
A separate log file is created for each port.
Note that, since many requests sent by the fuzzer do not utilize the user-supplied port (rather a random psm, or when applicable, none),
this is not an efficient way to fuzz only a specific port.
Regardless, this spent work still provides some value in that it keeps fuzzing random ports / other states, and besides,
it's fast; where it should be able to fuzz hundreds of millions of requests while you're away sleeping.


[1] - NOTE/TODO: the timestamp is set after the bluetooth connection fails, and not at time of sending the packet itself.
In other words, a system crash/issue - if present - must have happened before this time.


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

## Running the fuzzer
```
sudo su
source venv/bin/activate

# Interactive mode (to fuzz a specific port)
python3 l2fuzz.py

# Fuzz a specific port
# arg 1: target mac
# arg 2: target port
python3 l2fuzz.py AA:BB:CC:DD:EE:FF 0

# Scan ONLY for available services
# arg 1: target mac
# arg 2: "scan-only"
python3 l2fuzz.py AA:BB:CC:DD:EE:FF scan-only

# Scan and fuzz all ports that seem open
# arg 1: target mac
./fuzz_all_ports.sh AA:BB:CC:DD:EE:FF
```

## Running the fuzzer: interactive mode

1. Go to L2Fuzz folder.
2. Run l2fuzz.py:
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
5. [Fuzz testing started]

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

L2Fuzz paper was published in Jun 27, 2022 through "The 52nd Annual IEEE/IFIP International Conference on Dependable Systems and Networks".

Title : L2Fuzz: Discovering Bluetooth L2CAP Vulnerabilities Using Stateful Fuzz Testing

Paper : https://arxiv.org/abs/2208.00110

Video : https://youtu.be/lrc-mJTw1yM

Authors : Haram Park (Korea University), Carlos Nkuba Kayembe (Korea University), Seunghoon Woo (Korea University), Heejo Lee (Korea University)

Contacts : freehr94@korea.ac.kr, https://ccs.korea.ac.kr/
