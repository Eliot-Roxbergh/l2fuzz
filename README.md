# L2Fuzz

A stateful fuzzer to detect vulnerabilities in Bluetooth BR/EDR Logical Link Control and Adaptation Protocol (L2CAP) layer.

## Changelog as compared to original repo

### Merge pull requests
- Add proposed fixes <https://github.com/haramel/l2fuzz/pull/2>: "Don't show non-L2CAP profiles", add commandline mode, and minor fixes
- Add proposed fixes <https://github.com/haramel/l2fuzz/pull/6>: minor bug fix, add gitignore, add requirements.txt

### Build
- Remove .python-version to avoid forcing old Python
- Use latest dependencies in requirements.txt, and add related fixes to ensure it builds on Ubuntu 24.04.

### New features
- Use also manual connection scan (in addition to the SDP scan) when looking for services in commandline mode.
- Add function ensure_bluetooth_up that restarts bluetooth until an adapter is found, as reset_bluetooth may not always bring the adapter back up.
- Automatically run adb logcat on each hard crash, if possible, and save the last 5000 entries to .log file on disk. \
  This results in the original (.wrt) logfile per target port, as well as a new (.adb.log) file with the logcat dump for each hard crash. \
  To determine which run (.wrt file) resulted in a specific hard crash (.adb.log), grep for the timestamp in the filename to find the correspoding entry in the .wrt log for the run.
- Add command "scan-only" to only list all discovered services in commandline mode, without fuzzing.
- Add Bash script to automatically try to fuzz all ports that were discovered as open on target. \
  This was done in a Bash script to avoid using state from earlier fuzzing rounds as it otherwise would be run in the same single Python process.

### Exceptions and failure behavior
- Ignore several exceptions and try to continue anyway (add time.sleep, and restart bluetooth adapter or reset socket/state machine when necessary), to avoid fuzzing failing early. For some major unexpected exception the fuzzer will be retried up to five times (arbitrary number), until it gives up.
- Instead of defaulting to PSM/port 1 on connection error, continue using the requested port, to avoid confusion. Note that you may want to troubleshoot this error still and that l2fuzz is mainly intended to be used to ports that does not require pairing.

### Logging
- Instead of log truncation which deletes a lot of the logs, simple log everything but limit each run to 50 million packets (!) (as this limits the file to about 1-2GB).
- Clarify print outs and comments regarding which crashes are "soft" and can be ignored, or "hard" which are the ones written to log.
- Update log filename to contain the port that user requested (note: as normally, the program still scans other ports as well, which are still saved to this file, these packets are differentiated by the psm field that holds the port used for that specific packet)
- Save timestamp earlier after a crash to get slightly better precision.

### Other
- Update README to use venv, and add Details and Recommendations


## TODOs

- Why does every port tested return error "Device is not paired with host"? That is, even when the fuzzing seemingly works as intended! (see related comment in l2cap_fuzzer.py)
- Add other functionality to log or give up early if it's evident that a port is closed, i.e. each packet is rejected.
- Why do I get so many exceptions during testing, ignoring these and resetting the bluetooth state each time may mess up the fuzz test? Even if it looks OK.
- Add functionality to replay packets that resulted in potential crash.
- What's the support for scanning in paired mode? Does it provide any benefit: if we should regardless be able to fuzz the target's stack via SDP in unpaired mode?

## Recommendations

There are many seemingly false positives with the tool and it may be misleading in that it thinks it communicates with a port/service that is in fact closed.
It is therefore **strongly recommended to get access to system logs** (an example is included with adb logcat).
Optionally, **ensure traffic is sent as intended** with Wireshark (see section below) or with a method that can inspect the actual traffic sent over the air (this seemed difficult as Ubertooth failed to properly log all packets and show their contents - moreover, common SDR software for BladeRF seemed to have very poor support for Bluetooth Classic).
To ensure that (1) the port at all accepts (un)paired requests and doesn't indiscrimetly reject all - in which case try another port, or pair - and (2) that issues are not with the local bluetooth adapter and that the target responds as intended.


### Wireshark
Start Wireshark in the background while capturing, listen to interface bluetooth-monitor to avoid error when BT adapter is reset.
Afterwards, use filtering to ignore local packets to/from controller, with `bluetooth.addr == <TARGET_ADDR>` or for source only `bluetooth.src == <TARGET_ADDR>`.

One interesting thing to look for might be successful connections (to ports other than SDP 0x01, and when unpaired), to do this you may do the following. \
Look at Disconnection Requests to see which ports (PSMs) seemed to succeed: `bluetooth.src == <TARGET_ADDR> and btl2cap.cmd_code == 0x06`. \
Finally, if any ports succeeded in an unpaired state this could be of note, inspect the whole connection with a less restrictive filter (this ignores some error packets): `bluetooth.src == <TARGET_ADDR> and !(btl2cap.cmd_code == 0x07) and !(btl2cap.result == 0x0002) and !(_ws.col.info == "Rcvd Command Reject")`. \
Open ports could then be further targeted with some other tools, or further investigated (note: PSM is in hex format). \
In our example, we detected that some of the reported ports by SDP seemed to accept requests even when unpaired, ignoring SDP (0x01) itself, this was unexpected.


## Details

The tool fuzzes several different Bluetooth states in the L2CAP protocol. For some states it uses the user supplied psm (i.e. port), for others
it uses a randomized psm (!), finally some states/requests may not use a psm at all.

The l2fuzz is supposed to be used with a port that does not require pairing, as such SDP (0x01) is commonly used.
It targets the host's Bluetooth stack (i.e. software stack) with the lower-level L2CAP protocol.
Therefore, higher level services running on top of L2CAP are not tested, although I assume they can as a secondary effect be affected by certain random packets generated by l2fuzz.


Each request is saved to log in the working directory (_only after the test completes_), in a single file for each run.
This is done once per run/target, either when the run is finished (e.g. after a certain number of requests) or upon CTRL+C by user.
When a random psm is used, the psm is printed in the package log. Otherwise, assume it is the psm given by user.

The fuzzer tries to identify a crash, depending on the target's response or lack thereof.
Some transient errors, where certain connection types fails but the host is still up afterwards (ping test), are NOT marked as a crash in the log as they are likely false positives.
On the other hand, "hard crashes" can be found in logs by greping for crash\_info.

On each hard crash, the tool tries to run `sudo adb logcat -t <nr-of-entries-to-print>` to dump the last Android system logs to disk.
The filename includes current port (may be user-supplied, or random) and the timestamp [1] of packet.
To correlate packets in fuzzer logs with ADB logs, grep for this timestamp, as these are unique per packet.
Thereby, if you're able to confirm a system crash in a specific ADB logcat file, the offending packet can be found in the fuzzer logs, and possibly replayed (TODO: how?) or further investigated.

As l2fuzz targets the Bluetooth stack itself, I presume that it is generally superfluous to rerun it on several ports.
Regardless, I included `fuzz_all_ports.sh` [2] to do just this.
Although it's not the most effective method, by running the fuzzer against all ports, it will make it clear which ports allow or do not allow for unpaired connections and behavior when doing so.
Besides, fuzzing is fast and does not require user interaction (as long as nothing crashes, which would also be a good outcome).
Determining if a port is open with l2fuzz is complicated by the fact that l2fuzz itself does not disclose this, except for a single initial check.
Instead, monitor the testing with e.g. Wireshark to ascertain that not every packet fails with 'rejected'.
Finally, fuzzing against multiple ports (that does not require pairing) should not be duplicate work per se as packets are generated nondeterministically.


[1] - NOTE (TODO?): the timestamp is set after the bluetooth connection fails, and not at time of sending the packet itself. \
In other words, a system crash/issue - if present - must have happened before this time.

[2] - The script `fuzz_all_ports.sh` may be used to fuzz all detected ports on target. \
It uses both SDP and manual scanning to identify all ports on target, and runs the fuzzer for each.
Thereby, a separate log file is created for each port.
As there may be false positives even on closed ports (timeouts, issues with local BT adapter, and so on), it is recommended to also use e.g. Wireshark to ensure the ports actually give any response and do not reject every single packet.
Note that, since many requests sent by the fuzzer do not utilize the user-supplied port (rather a random psm, or when applicable, none),
this is not an efficient way to fuzz only a specific port, nor is this really the intention with l2fuzz as it targets the lower-level stack itself and not so much the application on that port.
Still, it may be used to gain some insight of how different target ports each react with unpaired connections/packets.
In my case, it discovered a port that was unexpectedly open for unpaired connections (although there are likely easy alternative ways to do this too).


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
python3 l2fuzz.py AA:BB:CC:DD:EE:FF 1

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
