import sys, os, re, time
import json

import bluetooth
from scapy.all import *
from ouilookup import OuiLookup
from collections import OrderedDict

from l2cap_fuzzer import *

from datetime import datetime

now = datetime.now()
nowTime = now.strftime("%H%M%S")
test_info = OrderedDict()
test_info["starting_time"] = str(now)
test_info["interface"] = "Bluetooth_L2CAP"
test_info["toolVer"] = "1.0.0"


def bluetooth_reset():
    """
    Reset linux bluetooth
    """
    print("[-] Resetting Bluetooth")
    os.system("sudo rfkill block bluetooth")  # Disable device
    os.system("sudo rm -r /var/lib/bluetooth/* 2> /dev/null")  # Clear addresses
    os.system("sudo rfkill unblock bluetooth")  # Enable device
    os.system("sudo systemctl restart bluetooth")  # Restart bluetooth service
    test_info["reset"] = "Y"
    time.sleep(3) # Arbitrary, can likely remove


def bluetooth_class_of_device(device_class):
    # https://github.com/mikeryan/btclassify.git

    class_string = device_class

    m = re.match("(0x)?([0-9A-Fa-f]{6})", class_string)
    if m is None:
        # print("Invalid class, skipping (%s)" % class_string)
        return {"major": "None", "minor": "None", "service": "None"}

    hex_string = m.group(2)

    # "class" is a reserved word in Python, so CoD is class
    CoD = int(hex_string, 16)

    # Major Device Classes
    classes = [
        "Miscellaneous",
        "Computer",
        "Phone",
        "LAN/Network Access Point",
        "Audio/Video",
        "Peripheral",
        "Imaging",
        "Wearable",
        "Toy",
        "Health",
    ]
    major_number = (CoD >> 8) & 0x1F
    if major_number < len(classes):
        major = classes[major_number]
    elif major_number == 31:
        major = "Uncategorized"
    else:
        major = "Reserved"

    # Minor - varies depending on major
    minor_number = (CoD >> 2) & 0x3F
    minor = None

    # computer
    if major_number == 1:
        classes = [
            "Uncategorized",
            "Desktop workstation",
            "Server-class computer",
            "Laptop",
            "Handheld PC/PDA (clamshell)",
            "Palm-size PC/PDA",
            "Wearable computer (watch size)",
            "Tablet",
        ]
        if minor_number < len(classes):
            minor = classes[minor_number]
        else:
            minor = "reserved"

    # phone
    elif major_number == 2:
        classes = [
            "Uncategorized",
            "Cellular",
            "Cordless",
            "Smartphone",
            "Wired modem or voice gateway",
            "Common ISDN access",
        ]
        if minor_number < len(classes):
            minor = classes[minor_number]
        else:
            minor = "reserved"

    # network access point
    elif major_number == 3:
        minor_number >> 3
        classes = [
            "Fully available",
            "1% to 17% Utilized",
            "17% to 33% Utilized",
            "33% to 50% Utilized",
            "50% to 67% Utilized",
            "67% to 83% Utilized",
            "83% to 99% Utilized",
            "No service available",
        ]
        if minor_number < len(classes):
            minor = classes[minor_number]
        else:
            minor = "reserved"

    # audio/video
    elif major_number == 4:
        classes = [
            "Uncategorized",
            "Wearable Headset Device",
            "Hands-free Device",
            "(Reserved)",
            "Microphone",
            "Loudspeaker",
            "Headphones",
            "Portable Audio",
            "Car audio",
            "Set-top box",
            "HiFi Audio Device",
            "VCR",
            "Video Camera",
            "Camcorder",
            "Video Monitor",
            "Video Display and Loudspeaker",
            "Video Conferencing",
            "(Reserved)",
            "Gaming/Toy",
        ]
        if minor_number < len(classes):
            minor = classes[minor_number]
        else:
            minor = "reserved"

    # peripheral, this one's gross
    elif major_number == 5:
        feel_number = minor_number >> 4
        classes = [
            "Not Keyboard / Not Pointing Device",
            "Keyboard",
            "Pointing device",
            "Combo keyboard/pointing device",
        ]
        feel = classes[feel_number]

        classes = [
            "Uncategorized",
            "Joystick",
            "Gamepad",
            "Remote control",
            "Sensing device",
            "Digitizer tablet",
            "Card Reader",
            "Digital Pen",
            "Handheld scanner for bar-codes, RFID, etc.",
            "Handheld gestural input device",
        ]
        if minor_number < len(classes):
            minor_low = classes[minor_number]
        else:
            minor_low = "reserved"

        minor = "%s, %s" % (feel, minor_low)

    # imaging
    elif major_number == 6:
        minors = []
        if minor_number & (1 << 2):
            minors.append("Display")
        if minor_number & (1 << 3):
            minors.append("Camera")
        if minor_number & (1 << 4):
            minors.append("Scanner")
        if minor_number & (1 << 5):
            minors.append("Printer")
        if len(minors > 0):
            minors = ", ".join(minors)

    # wearable
    elif major_number == 7:
        classes = ["Wristwatch", "Pager", "Jacket", "Helmet", "Glasses"]
        if minor_number < len(classes):
            minor = classes[minor_number]
        else:
            minor = "reserved"

    # toy
    elif major_number == 8:
        classes = ["Robot", "Vehicle", "Doll / Action figure", "Controller", "Game"]
        if minor_number < len(classes):
            minor = classes[minor_number]
        else:
            minor = "reserved"

    # health
    elif major_number == 9:
        classes = [
            "Undefined",
            "Blood Pressure Monitor",
            "Thermometer",
            "Weighing Scale",
            "Glucose Meter",
            "Pulse Oximeter",
            "Heart/Pulse Rate Monitor",
            "Health Data Display",
            "Step Counter",
            "Body Composition Analyzer",
            "Peak Flow Monitor",
            "Medication Monitor",
            "Knee Prosthesis",
            "Ankle Prosthesis",
            "Generic Health Manager",
            "Personal Mobility Device",
        ]
        if minor_number < len(classes):
            minor = classes[minor_number]
        else:
            minor = "reserved"

    # Major Service Class (can by multiple)
    services = []
    if CoD & (1 << 23):
        services.append("Information")
    if CoD & (1 << 22):
        services.append("Telephony")
    if CoD & (1 << 21):
        services.append("Audio")
    if CoD & (1 << 20):
        services.append("Object Transfer")
    if CoD & (1 << 19):
        services.append("Capturing")
    if CoD & (1 << 18):
        services.append("Rendering")
    if CoD & (1 << 17):
        services.append("Networking")
    if CoD & (1 << 16):
        services.append("Positioning")
    if CoD & (1 << 15):
        services.append("(reserved)")
    if CoD & (1 << 14):
        services.append("(reserved)")
    if CoD & (1 << 13):
        services.append("Limited Discoverable Mode")

    output = {"major": major, "minor": minor, "service": services}

    return output


def bluetooth_classic_scan():
    """
    This scan finds ONLY Bluetooth Classic (non-BLE) devices
    """
    print("Performing classic bluetooth inquiry scan...")

    while True:
        # Scan for nearby devices in regular bluetooth mode
        nearby_devices = bluetooth.discover_devices(
            duration=3, flush_cache=True, lookup_names=True, lookup_class=True
        )
        i = 0
        print("\n\tTarget Bluetooth Device List")
        print("\t[No.]\t[BT address]\t\t[Device name]\t\t[Device Class]\t\t[OUI]")
        for addr, name, device_class in nearby_devices:
            device_class = bluetooth_class_of_device(hex(device_class))
            oui = OuiLookup().query(addr)
            print(
                "\t%02d.\t%s\t%s\t\t%s(%s)\t%s"
                % (
                    i,
                    addr,
                    name,
                    device_class["major"],
                    device_class["minor"],
                    list(oui[0].values())[0],
                )
            )
            i += 1
        if len(nearby_devices) == 0:
            print("[-] No bluetooth device found. Did you connect an adapter?\n")
            sys.exit()
        elif len(nearby_devices) != 0:
            print("\tFound %d devices" % len(nearby_devices))
            break
        else:
            sys.exit()

    while True:
        user_input = int(input("\nChoose Device : "))
        if user_input < len(nearby_devices) and user_input > -1:
            idx = user_input
            break
        else:
            print("[-] Out of range.")

    addr_chosen = nearby_devices[idx][0]
    test_info["bdaddr"] = str(nearby_devices[idx][0])
    oui = OuiLookup().query(addr_chosen)
    test_info["OUI"] = list(oui[0].values())[0]
    test_info["name"] = str(nearby_devices[idx][1])
    test_info["Class of Device Value"] = str(nearby_devices[idx][2])
    test_info["Class of Device"] = bluetooth_class_of_device(
        hex(nearby_devices[idx][2])
    )

    return addr_chosen


# Manually try all possible CIDs, as SDP may not show all available services
def find_service(bt_addr):
    open_channels = []

    # Note that, as I remember, 0 is reserved and never work
    start_cid = 0
    end_cid = 65535 #max 65535

    # TODO: should we ignore even numbers if they are always supposedly invalid?

    print("\nTODO: I had issue that scanning took a long time, as each open port created a pairing prompt that needed to timeout or be closed manually. Why?\nIf so, you may want to limit searches, or disabled this feature.")

    print(f"Trying to connect to {bt_addr} on PSM ports {start_cid} to {end_cid}:\nWorking..")
    for port in range(start_cid, end_cid):
        sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)

        try:
            sock.connect((bt_addr, port))
            print(f"PSM {port:#x} ({port}) open")
            open_channels.append(port)
            sock.close()
        except bluetooth.btcommon.BluetoothError as e:
            pass
        except ValueError as e:
            # The PSM isn't valid for some reason
            pass
        except Exception as e:
            print(e)

    print("\nOpen L2CAP Channels:", open_channels)
    return open_channels


def find_all_services(bt_addr):

    # Manually try connect to each channel
    services_m = find_service(bt_addr)
    print("\n\n")

    # Services reported open by SDP
    services_s = []
    services_structs = bluetooth.find_service(address=bt_addr)
    i = 0
    print("SDP reports open:")
    for serv in services_structs:
        port=serv["port"]
        if serv["protocol"] != "L2CAP":
            del services_structs[i]
            continue
        if len(serv["profiles"]) == 0:
            print("\t%d. [None]: %s - Port %d open" % (i, serv["name"], port))
        else:
            print("\t%d. [0x%s]: %s - Port %d open" % (i, serv["profiles"][0][0], serv["name"], port))
        i += 1
        services_s.append(port)
    print("\n")

    # All ports with potential services: combine lists and remove duplicates
    all_services = list(set(services_m+services_s))
    print("All ports discovered open (L2CAP): ", all_services)
    return all_services

# TODO use find_all_services to also do the manual connection check.
#       This is currently done when calling the program in "command line mode",
#       but not for this - the "interactive mode"
def bluetooth_services_and_protocols_search(bt_addr):
    """
    Search the services and protocols of device
    """
    print("\nStart scanning services...")
    print("\n\tList of profiles for the device")

    #services = find_all_services(bt_addr)
    services = bluetooth.find_service(address=bt_addr)

    # print(services)
    if len(services) <= 0:
        print("\tNo services found!")
        #print("\t'protocol': 'None', 'name': 'None', 'port': 'None'")
        print("Giving up, no services found. Perhaps try again..")
        sys.exit(1)
    else:
        i = 0
        for serv in services:
            #print(f"{serv=}")
            if serv["protocol"] != "L2CAP":
                i += 1
                continue

            if len(serv["profiles"]) == 0:
                print("\t%02d. [None]: %s (port %d)" % (i, serv["name"], serv["port"]))
            else:
                print("\t%02d. [0x%s]: %s (port %d)" % (i, serv["profiles"][0][0], serv["name"], serv["port"]))
            i += 1

    while True:
        user_input = int(input("\nSelect a profile to fuzz : "))
        if user_input < len(services) and user_input > -1:
            idx = user_input
            serv_chosen = services[idx]
            break
        else:
            print("[-] Out of range.")

    print(
        "\n\tProtocol for the profile [%s] : %s\n"
        % (serv_chosen["name"], serv_chosen["protocol"])
    )

    test_info["service"] = serv_chosen["name"]
    test_info["protocol"] = serv_chosen["protocol"]
    test_info["port"] = serv_chosen["port"]

    return serv_chosen


def start_fuzzing(target_addr, target_protocol, target_profile, target_profile_port):

    # Protocol fuzzing
    if target_protocol == "L2CAP":
        l2cap_fuzzing(target_addr, target_profile, target_profile_port, test_info)
    else:
        print("Not Supported")


def is_bluetooth_up():
    try:
        bluetooth.discover_devices(duration=2)
    except OSError as e:
        print(f"[-] No Bluetooth adapter. Restarting Bluetooth..")
        return False
    except Exception as e:
        print(f"[-] Unexpected Bluetooth error, giving up!: {e}")
        sys.exit(1)
    return True

def ensure_bluetooth_up():
    while(not is_bluetooth_up()):
        bluetooth_reset()

if __name__ == "__main__":

    #print("\n===================Test Information===================")
    #print(json.dumps(test_info, ensure_ascii=False, indent="\t"))
    #print("======================================================\n")

    # optional: restart bluetooth chip and ensure it's up
    #bluetooth_reset()
    ensure_bluetooth_up()

    # Command line mode
    if len(sys.argv) > 2:
        target_protocol = "L2CAP"
        target_addr = sys.argv[1]
        target_profile = "none" # Doesn't matter - not used

        # Scan only (L2CAP services only)
        if sys.argv[2] == "scan-only":
            print("\n====================SCANNING START====================")
            # find all services on target
            print("Service scan for", target_addr)
            services = find_all_services(target_addr)
            file="l2fuzz_open_ports.tmp"
            with open(file, "w") as f:
                f.write(" ".join(map(str, services)))
            print("Open services saved to working dir:", file)
            sys.exit(0)

        # Fuzz given port
        else:
            print("\n====================TARGET START=====================")
            target_profile_port = int(sys.argv[2])
            print("Fuzzing target: ", target_addr, target_protocol, target_profile, target_profile_port)
            print("\n\n")

    # Iteractive mode
    else:
        #print("\n===================Test Information===================")
        #print(json.dumps(test_info, ensure_ascii=False, indent="\t"))
        #print("======================================================\n")
        print("\n====================TARGET START=====================")
        target_addr = bluetooth_classic_scan()
        target_service = bluetooth_services_and_protocols_search(target_addr)
        target_protocol = target_service["protocol"]
        target_profile = target_service["name"]
        target_profile_port = target_service["port"]
        print("Fuzzing target: ", target_addr, target_protocol, target_profile, target_profile_port)
        print("\n\n")

    # Start fuzzing (retry a few times on common errors)
    # TODO: note I'm not sure what effect running the fuzzer multiple times has, as it seems to preserve some kind of state (?)
    for i in range(0,5):
        try:
            start_fuzzing(target_addr, target_protocol, target_profile, target_profile_port)
            sys.exit(0) # success
        except PermissionError as e:
            print(f"[-] Unexpected exception {e}, usually due to local Bluetooth adapter.")
            print("[-] Restarting Bluetooth adapter and trying again...")
            bluetooth_reset()
            ensure_bluetooth_up()
        except OSError as e:
            print(f"[-] Unexpected {e}, ensure that host is up?")
            print("[-] Restarting Bluetooth adapter and trying again...")
            time.sleep(2)
            bluetooth_reset()
            ensure_bluetooth_up()
