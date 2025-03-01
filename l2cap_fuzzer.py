import subprocess
import json

import time, os

from datetime import datetime

from statemachine import StateMachine, State
from scapy.all import *
from scapy.packet import Packet
from random import *
from collections import OrderedDict


# Global
OUR_LOCAL_SCID = 0x40
pkt_cnt = 0
crash_cnt = 0
conn_rsp_flag = 0

# L2CAP Command Info
L2CAP_CmdDict = {
    0x01: "Reject",
    0x02: "Connection Request",
    0x03: "Connection Response",
    0x04: "Configuration Request",
    0x05: "Configuration Response",
    0x06: "Disconnection Request",
    0x07: "Disconnection Response",
    0x08: "Echo Request",
    0x09: "Echo Response",
    0x0A: "Information Request",
    0x0B: "Information Response",
    0x0C: "Create Channel Request",
    0x0D: "Create Channel Response",
    0x0E: "Move Channel Request",
    0x0F: "Move Channel Response",
    0x10: "Move Channel Confirmation Request",
    0x11: "Move Channel Confirmation Response",
    0x12: "Connection Parameter Update Request",
    0x13: "Connection Parameter Update Response",
    0x14: "LE Credit Based Connection Request",
    0x15: "LE Credit Based Connection Response",
    0x16: "Flow Control Credit Ind",
    0x17: "Credit Based Connection Request",
    0x18: "Credit Based Connection Response",
    0x19: "Credit Based Reconfigure Request",
    0x1A: "Credit Based Reconfigure Response",
}

L2CAP_Connect_Result = {
    0: "Connection successful",
    1: "Connection pending",
    2: "Connection refused - PSM not supported",
    3: "Connection refused - security block",
    4: "Connection refused - no resources available",
    6: "Connection refused - invalid Source CID",
    7: "Connection refused - Source CID already allocated",
}


class l2cap_state_machine(StateMachine):
    """
    L2CAP Protocol Fuzzing with 'Stateful Fuzzing Algorithm'

    A state machine is created for each new L2CAP_ConnectReq received.
    The state machine always starts in the CLOSED state

    *The state machine does not necessarily represent all possible scenarios.
    """

    #### States ####

    # Basic States
    closed_state = State("Closed State", initial=True)  # Start
    open_state = State("Open State")  # End
    wait_config_state = State("Wait Config State")
    wait_connect_state = State("Wait Connect State")
    wait_connect_rsp_state = State("Wait Connect Rsp State")
    wait_disconnect_state = State("Wait Disconnect State")

    # Optional States (Alternative MAC/PHY enabled operation)
    wait_create_state = State("Wait Create State")
    wait_create_rsp_state = State("Wait Create Rsp State")
    wait_move_confirm_state = State("Wait Move Confirm State")
    wait_move_state = State("Wait Move State")
    wait_move_rsp_state = State("Wait Move Rsp State")
    wait_confirm_rsp_state = State("Wait Confirm Rsp State")

    # Configurateion States
    wait_send_config_state = State("Wait Send Config State")
    wait_config_req_rsp_state = State("Wait Config Req Rsp State")
    wait_config_req_state = State("Wait Config Req State")
    wait_config_rsp_state = State("Wait Config Rsp State")
    wait_control_ind_state = State("Wait Control Ind State")
    wait_final_rsp_state = State("Wait Final Rsp State")
    wait_ind_final_rsp_state = State("Wait Ind Final Rsp State")

    #### Transitions ####

    # from open_state
    open_to_w_discon = open_state.to(wait_disconnect_state)
    open_to_closed = open_state.to(closed_state)
    open_to_w_conf = open_state.to(wait_config_state)
    open_to_w_move = open_state.to(wait_move_state)
    open_to_w_move_rsp = open_state.to(wait_move_rsp_state)
    open_to_w_move_confirm = open_state.to(wait_move_confirm_state)

    # from wait_config_state
    w_conf_to_closed = wait_config_state.to(closed_state)
    w_conf_to_w_discon = wait_config_state.to(wait_disconnect_state)
    w_conf_to_w_conf = wait_config_state.to.itself()
    w_conf_to_w_send_conf = wait_config_state.to(wait_send_config_state)
    w_conf_to_w_conf_req_rsp = wait_config_state.to(wait_config_req_rsp_state)

    # from closed_state
    closed_to_w_conn = closed_state.to(wait_connect_state)
    closed_to_w_conf = closed_state.to(wait_config_state)
    closed_to_w_conn_rsp = closed_state.to(wait_connect_rsp_state)
    closed_to_w_create = closed_state.to(wait_create_state)
    closed_to_w_create_rsp = closed_state.to(wait_create_rsp_state)

    # from wait_connect_state
    w_conn_to_closed = wait_connect_state.to(closed_state)
    w_conn_to_w_conf = wait_connect_state.to(wait_config_state)

    # from wait_connect_rsp_state
    w_conn_rsp_to_closed = wait_connect_rsp_state.to(closed_state)
    w_conn_rsp_to_w_conf = wait_connect_rsp_state.to(wait_config_state)

    # from wait_disconnect_state
    w_disconn_to_w_disconn = wait_disconnect_state.to.itself()
    w_disconn_to_closed = wait_disconnect_state.to(closed_state)

    # from wait_create_state
    w_create_to_closed = wait_create_state.to(closed_state)
    w_create_to_w_conf = wait_create_state.to(wait_config_state)

    # from wait_create_rsp_state
    w_create_rsp_to_closed = wait_create_rsp_state.to(closed_state)
    w_create_rsp_to_w_conf = wait_create_rsp_state.to(wait_config_state)

    # from wait_move_confirm_state
    w_move_confirm_to_open = wait_move_confirm_state.to(open_state)

    # from wait_move_state
    w_move_to_w_move_confirm = wait_move_state.to(wait_move_confirm_state)

    # from wait_move_rsp_state
    w_move_rsp_to_w_confirm_rsp = wait_move_rsp_state.to(wait_confirm_rsp_state)
    w_move_rsp_to_w_move = wait_move_rsp_state.to(wait_move_state)
    w_move_rsp_to_w_move_confirm = wait_move_rsp_state.to(wait_move_confirm_state)
    w_move_rsp_to_w_move_rsp = wait_move_rsp_state.to.itself()

    # from wait_confirm_rsp_state
    w_confirm_rsp_to_open = wait_confirm_rsp_state.to(open_state)

    # from wait_send_config_state
    w_send_conf_to_w_conf_rsp = wait_send_config_state.to(wait_config_rsp_state)

    # from wait_config_req_rsp_state
    w_conf_req_rsp_to_w_conf_req_rsp = wait_config_req_rsp_state.to.itself()
    w_conf_req_rsp_to_w_conf_req = wait_config_req_rsp_state.to(wait_config_req_state)
    w_conf_req_rsp_to_w_conf_rsp = wait_config_req_rsp_state.to(wait_config_rsp_state)

    # from wait_config_req_state
    w_conf_req_to_w_conf_req = wait_config_req_state.to.itself()
    w_conf_req_to_open = wait_config_req_state.to(open_state)
    w_conf_req_to_w_ind_final_rsp = wait_config_req_state.to(wait_ind_final_rsp_state)

    # from wait_final_rsp_state
    w_final_rsp_to_open = wait_final_rsp_state.to(open_state)
    w_final_rsp_to_w_conf = wait_final_rsp_state.to(wait_config_state)

    # from wait_control_ind_state
    w_control_ind_to_w_conf = wait_control_ind_state.to(wait_config_state)
    w_control_ind_to_open = wait_control_ind_state.to(open_state)

    # from wait_ind_final_rsp_state
    w_ind_final_rsp_to_w_final_rsp = wait_ind_final_rsp_state.to(wait_final_rsp_state)
    w_ind_final_rsp_to_w_control_ind = wait_ind_final_rsp_state.to(
        wait_control_ind_state
    )
    w_ind_final_rsp_to_w_conf = wait_ind_final_rsp_state.to(wait_config_state)

    # from wait_config_rsp_state
    w_conf_rsp_to_w_ind_final_rsp = wait_config_rsp_state.to(wait_ind_final_rsp_state)
    w_conf_rsp_to_w_conf_rsp = wait_config_rsp_state.to.itself()
    w_conf_rsp_to_open = wait_config_rsp_state.to(open_state)


class garbage_value(Packet):
    fields_desc = [LEShortField("garbage", 0)]


class new_L2CAP_ConnReq(Packet):
    name = "L2CAP Conn Req"
    fields_desc = [
        LEShortEnumField(
            "psm",
            0,
            {
                1: "SDP",
                3: "RFCOMM",
                5: "TCS-BIN",  # noqa
                7: "TCS-BIN-CORDLESS",
                15: "BNEP",
                17: "HID-Control",  # noqa
                19: "HID-Interrupt",
                21: "UPnP",
                23: "AVCTP-Control",  # noqa
                25: "AVDTP",
                27: "AVCTP-Browsing",
                29: "UDI_C-Plane",  # noqa
                31: "ATT",
                33: "3DSP",
                35: "IPSP",
                37: "OTS",
            },
        ),  # noqa
        LEShortField("scid", 0),
    ]


class new_L2CAP_ConnResp(Packet):
    name = "L2CAP Conn Resp"
    fields_desc = [
        LEShortField("dcid", 0),
        LEShortField("scid", 0),
        LEShortEnumField(
            "result",
            0,
            [
                "success",
                "pend",
                "cr_bad_psm",
                "cr_sec_block",
                "cr_no_mem",
                "reserved",
                "cr_inval_scid",
                "cr_scid_in_use",
            ],
        ),  # noqa: E501
        LEShortEnumField(
            "status", 0, ["no_info", "authen_pend", "author_pend", "reserved"]
        ),  # noqa: E501
    ]


class new_L2CAP_ConfReq(Packet):
    name = "L2CAP Conf Req"
    fields_desc = [
        LEShortField("dcid", 0),
        LEShortField("flags", 0),
        ByteField("type", 0),
        ByteField("length", 0),
        ByteField("identifier", 0),
        ByteField("servicetype", 0),
        LEShortField("sdusize", 0),
        LEIntField("sduarrtime", 0),
        LEIntField("accesslat", 0),
        LEIntField("flushtime", 0),
    ]


class new_L2CAP_ConfResp(Packet):
    name = "L2CAP Conf Resp"
    fields_desc = [
        LEShortField("scid", 0),
        LEShortField("flags", 0),
        LEShortField("result", 0),
        ByteField("type0", 0),
        ByteField("length0", 0),
        LEShortField("option0", 0),
        ByteField("type1", 0),
        ByteField("length1", 0),
    ]


class L2CAP_Create_Channel_Request(Packet):
    name = "L2CAP Create Channel Request"
    fields_desc = [
        LEShortEnumField(
            "psm",
            0,
            {
                1: "SDP",
                3: "RFCOMM",
                5: "TCS-BIN",  # noqa
                7: "TCS-BIN-CORDLESS",
                15: "BNEP",
                17: "HID-Control",  # noqa
                19: "HID-Interrupt",
                21: "UPnP",
                23: "AVCTP-Control",  # noqa
                25: "AVDTP",
                27: "AVCTP-Browsing",
                29: "UDI_C-Plane",  # noqa
                31: "ATT",
                33: "3DSP",
                35: "IPSP",
                37: "OTS",
            },
        ),  # noqa
        LEShortField("scid", 0),
        ByteField("controller_id", 0),
    ]


class L2CAP_Create_Channel_Response(Packet):
    name = "L2CAP Create Channel Response"
    fields_desc = [
        LEShortField("dcid", 0),
        LEShortField("scid", 0),
        LEShortEnumField(
            "result",
            0,
            {
                0: "Connection successful",
                1: "Connection pending",
                2: "Connection refused - PSM not supported",
                3: "Connection refused - security block",
                4: "Connection refused - no resources available",
                5: "Connection refused - Controller ID not supported",
                6: "Connection refused - Invalid Source CID",
                7: "Connection refused - Source CID already allocated",
            },
        ),
        LEShortEnumField(
            "status",
            0,
            {
                0: "No further information available",
                1: "Authentication pending",
                2: "Authorization pending",
            },
        ),
    ]


class L2CAP_Move_Channel_Request(Packet):
    name = "L2CAP Move Channel Request"
    fields_desc = [
        LEShortField("icid", 0),
        ByteField("dest_controller_id", 0),
    ]  # 0: move to Bluetooth BR/EDR, 1: move to wifi 802.11


class L2CAP_Move_Channel_Confirmation_Request(Packet):
    name = "L2CAP Move Channel Confirmation Request"
    fields_desc = [
        LEShortField("icid", 0),
        LEShortEnumField("result", 0, {0: "Move success", 1: "Move failure"}),
    ]


def log_pkt(pkt):
    """
    get default format of each packet and update the values
    """
    pkt_default = dict(pkt.default_fields, **pkt.payload.default_fields)
    pkt_default = dict(pkt_default, **pkt.payload.payload.default_fields)
    pkt_CmdHdr_updated = dict(pkt_default, **pkt.fields)
    pkt_payload_updated = dict(pkt_CmdHdr_updated, **pkt.payload.fields)
    pkt_garbage_updated = dict(pkt_payload_updated, **pkt.payload.payload.fields)

    return pkt_garbage_updated


def send_pkt(bt_addr, sock, pkt, cmd_code, state, port):
    """
    Errno
            ConnectionResetError: [Errno 104] Connection reset by peer
            ConnectionRefusedError: [Errno 111] Connection refused
            TimeoutError: [Errno 110] Connection timed out
            and so on ..
    """
    global pkt_cnt
    global crash_cnt
    pkt_cnt += 1
    pkt_info = ""
    port = str(port) #might not be necessary?

    try:
        sock.send(pkt)
        # print(pkt.summary)
        time_now = str(datetime.now())
        pkt_info = {}
        pkt_info["no"] = pkt_cnt
        pkt_info["protocol"] = "L2CAP"
        pkt_info["time"] = time_now
        pkt_info["payload"] = log_pkt(pkt)
        pkt_info["crash"] = "n"
        pkt_info["l2cap_state"] = state

    except ConnectionResetError:
        print("[-] Crash Found - ConnectionResetError detected")
        # Hard error: log for investigation!
        time_now = str(datetime.now())
        if l2ping(bt_addr) == False:
            print("Crash Packet :", pkt)
            crash_cnt += 1
            pkt_info = {}
            pkt_info["no"] = pkt_cnt
            pkt_info["protocol"] = "L2CAP"
            pkt_info["time"] = time_now
            pkt_info["cmd"] = L2CAP_CmdDict.get(cmd_code, "reserved for future use")
            pkt_info["payload"] = log_pkt(pkt)
            pkt_info["l2cap_state"] = state
            pkt_info["sended?"] = "n"
            pkt_info["crash"] = "y"
            pkt_info["crash_info"] = "ConnectionResetError"
            pkt_info["current_port"] = port
            dump_adb_logs(time_now, port)
        # Transient error: likely uninteresting, don't log
        else:
            print("[-] The connection failed but it went up quickly again, this was not a hard crash (will not be marked as 'crash' in log).")

    except ConnectionRefusedError:
        time_now = str(datetime.now())
        print("[-] Crash Found - ConnectionRefusedError detected")
        # Hard error: log for investigation!
        if l2ping(bt_addr) == False:
            print("Crash Packet :", pkt)
            crash_cnt += 1
            pkt_info = {}
            pkt_info["no"] = pkt_cnt
            pkt_info["protocol"] = "L2CAP"
            pkt_info["time"] = time_now
            pkt_info["cmd"] = L2CAP_CmdDict.get(cmd_code, "reserved for future use")
            pkt_info["payload"] = log_pkt(pkt)
            pkt_info["l2cap_state"] = state
            pkt_info["sended?"] = "n"
            pkt_info["crash"] = "y"
            pkt_info["crash_info"] = "ConnectionRefusedError"
            pkt_info["current_port"] = port
            dump_adb_logs(time_now, port)
        # Transient error: likely uninteresting, don't log
        else:
            print("[-] The connection failed but it went up quickly again, this was not a hard crash (will not be marked as 'crash' in log).")

    except ConnectionAbortedError:
        print("[-] Crash Found - ConnectionAbortedError detected")
        # Hard error: log for investigation!
        if l2ping(bt_addr) == False:
            time_now = str(datetime.now())
            print("Crash Packet :", pkt)
            crash_cnt += 1
            pkt_info = {}
            pkt_info["no"] = pkt_cnt
            pkt_info["protocol"] = "L2CAP"
            pkt_info["time"] = time_now
            pkt_info["cmd"] = L2CAP_CmdDict.get(cmd_code, "reserved for future use")
            pkt_info["payload"] = log_pkt(pkt)
            pkt_info["l2cap_state"] = state
            pkt_info["sended?"] = "n"
            pkt_info["crash"] = "y"
            pkt_info["crash_info"] = "ConnectionAbortedError"
            pkt_info["current_port"] = port
            dump_adb_logs(time_now, port)
        # Transient error: likely uninteresting, don't log
        else:
            print("[-] The connection failed but it went up quickly again, this was not a hard crash (will not be marked as 'crash' in log).")

    # Hard error: log for investigation!
    except TimeoutError:
        time_now = str(datetime.now())
        # State Timeout
        print("[-] Crash Found - TimeoutError detected")
        print("Crash Packet :", pkt)
        crash_cnt += 1
        pkt_info = {}
        pkt_info["no"] = pkt_cnt
        pkt_info["protocol"] = "L2CAP"
        pkt_info["time"] = time_now
        pkt_info["cmd"] = L2CAP_CmdDict.get(cmd_code, "reserved for future use")
        pkt_info["payload"] = log_pkt(pkt)
        pkt_info["l2cap_state"] = state
        pkt_info["sended?"] = "n"
        pkt_info["crash"] = "y"
        pkt_info["crash_info"] = "TimeoutError"
        pkt_info["current_port"] = port
        dump_adb_logs(time_now, port)

    except OSError as e:
        """
        OSError: [Errno 107] Transport endpoint is not connected
        OSError: [Errno 112] Host is down
        """
        # Hard error: log for investigation!
        time_now = str(datetime.now())
        if "Host is down" in e.__doc__:
            print("[-] Crash Found - Host is down")
            print("Crash Packet :", pkt)
            crash_cnt += 1
            pkt_info = {}
            pkt_info["no"] = pkt_cnt
            pkt_info["protocol"] = "L2CAP"
            pkt_info["time"] = time_now
            pkt_info["cmd"] = L2CAP_CmdDict.get(cmd_code, "reserved for future use")
            pkt_info["payload"] = log_pkt(pkt)
            pkt_info["l2cap_state"] = state
            pkt_info["sended?"] = "n"
            pkt_info["crash"] = "y"
            pkt_info["DoS"] = "y"
            pkt_info["crash_info"] = "OSError - Host is down"
            pkt_info["current_port"] = port
            print("[-] Crash packet causes HOST DOWN. Test finished.")
            dump_adb_logs(time_now, port)
            #TODO exit program (and save logs) here if host is in fact down ?
        # OS Error: likely a local issue. TODO could this be interesting? If so which other types of errors?
        else:
            print(f"[!] Unknown issue, got OS error when sending packet: {e}")
            time.sleep(3) # arbitrary sleep for good measure, can remove
            pass
    else:
        pass

    # Reset Socket
    sock = BluetoothL2CAPSocket(bt_addr)
    return sock, pkt_info


def l2ping(bt_addr):
    """
    <Crash finding example>
    1) Check the status of sockect in send() method
    2) If there is error in send(), Check l2ping
    3) if l2ping finds packet lost, it is crash!
    + You need to check the target device's condition. (Error pop-up or crash dump.)
    """
    l2pingRes = subprocess.run(
        ["l2ping", str(bt_addr), "-c", "3"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        failureRate = str(l2pingRes.stdout).split()[-2]
        failureRate = int(failureRate.split("%")[0])
    except ValueError:
        failureRate = 100
    if failureRate < 100:
        return True
    else:
        return False


def random_psm():
    """
    random psm for connection state fuzzing

    Since PSMs are odd and the least significant bit of the most significant byte is zero,
    the following ranges do not contain valid PSMs: 0x0100-0x01FF, 0x0300-0x03FF,
    0x0500-0x05FF, 0x0700-0x07FF, 0x0900-0x09FF, 0x0B00-0x0BFF, 0x0D00-
    0x0DFF. All even values are also not valid as PSMs.
    """
    # Get random invalid psm value
    psm4fuzz = 0
    opt = randint(0, 7)
    if opt == 0:
        psm4fuzz = randrange(0x0100, 0x01FF + 0x0001)
    elif opt == 1:
        psm4fuzz = randrange(0x0300, 0x03FF + 0x0001)
    elif opt == 2:
        psm4fuzz = randrange(0x0500, 0x05FF + 0x0001)
    elif opt == 3:
        psm4fuzz = randrange(0x0700, 0x07FF + 0x0001)
    elif opt == 4:
        psm4fuzz = randrange(0x0900, 0x09FF + 0x0001)
    elif opt == 5:
        psm4fuzz = randrange(0x0B00, 0x0BFF + 0x0001)
    elif opt == 6:
        psm4fuzz = randrange(0x0D00, 0x0DFF + 0x0001)
    elif opt == 7:
        psm4fuzz = randrange(0x0000, 0xFFFF + 0x0001, 2)
    return psm4fuzz


def connection_state_fuzzing(bt_addr, sock, state_machine, packet_info):
    iteration = 2500

    # 1) Target State : Wait Connect State
    for i in range(0, iteration):
        cmd_code = 0x02
        random_port = random_psm()
        pkt = (
            L2CAP_CmdHdr(code=cmd_code)
            / new_L2CAP_ConnReq(psm=random_port)
            / garbage_value(garbage=randrange(0x0000, 0x10000))
        )
        sock, pkt_info = send_pkt(
            bt_addr, sock, pkt, cmd_code, state_machine.current_state.name, random_port
        )
        if pkt_info == "":
            pass
        else:
            packet_info["packet"].append(pkt_info)

        state_machine.closed_to_w_conn()

        cmd_code = 0x03
        pkt = (
            L2CAP_CmdHdr(code=cmd_code)
            / new_L2CAP_ConnResp(
                dcid=randrange(0x0040, 0x10000), scid=randrange(0x0040, 0x10000)
            )
            / garbage_value(garbage=randrange(0x0000, 0x10000))
        )
        # Port is included for logging purposes only: I assume that the ConnResp uses same PSM (port) as used above in ConnReq?
        sock, pkt_info = send_pkt(
            bt_addr, sock, pkt, cmd_code, state_machine.current_state.name, random_port
        )
        if pkt_info == "":
            pass
        else:
            packet_info["packet"].append(pkt_info)

        state_machine.w_conn_to_closed()


def creation_state_fuzzing(bt_addr, sock, state_machine, packet_info):
    iteration = 2500

    # 2) Target State : Wait Create State
    for i in range(0, iteration):
        cmd_code = 0x0C
        random_port = random_psm()
        pkt = (
            L2CAP_CmdHdr(code=cmd_code)
            / L2CAP_Create_Channel_Request(psm=random_port)
            / garbage_value(garbage=randrange(0x0000, 0x10000))
        )

        sock, pkt_info = send_pkt(
            bt_addr, sock, pkt, cmd_code, state_machine.current_state.name, random_port
        )
        if pkt_info == "":
            pass
        else:
            packet_info["packet"].append(pkt_info)

        state_machine.closed_to_w_create()

        cmd_code = 0x0D
        pkt = (
            L2CAP_CmdHdr(code=cmd_code)
            / L2CAP_Create_Channel_Response(
                dcid=randrange(0x0040, 0x10000), scid=randrange(0x0040, 0x10000)
            )
            / garbage_value(garbage=randrange(0x0000, 0x10000))
        )

        # Port is included for logging purposes only: I assume that the ConnResp uses same PSM (port) as used above in ConnReq?
        sock, pkt_info = send_pkt(
            bt_addr, sock, pkt, cmd_code, state_machine.current_state.name, random_port
        )
        if pkt_info == "":
            pass
        else:
            packet_info["packet"].append(pkt_info)

        state_machine.w_create_to_closed()


def configuration_state_fuzzing(
    bt_addr, sock, state_machine, profile, port, packet_info
):
    iteration = 2500

    # From Connection State to Configure State (Closed State -> Wait Config State)
    while 1:
        cmd_code = 0x02
        pkt = L2CAP_CmdHdr(code=cmd_code) / new_L2CAP_ConnReq(psm=port, scid=OUR_LOCAL_SCID)
        sock, pkt_info = send_pkt(
            bt_addr, sock, pkt, cmd_code, state_machine.current_state.name, port
        )
        if pkt_info == "":
            pass
        else:
            packet_info["packet"].append(pkt_info)

        global conn_rsp_flag
        global dcid_value

        # Only run on first invokation of this function, i.e. only run once in total over lifetime of program
        if conn_rsp_flag == 0:
            conn_rsp = sock.recv()  # save pkt info for configuration request

            try:
                dcid_value = conn_rsp.dcid
                result_value = conn_rsp.result
            except:
                dcid_value = OUR_LOCAL_SCID
                result_value = 1

            conn_rsp_flag = 1
            # Can't connect to selected PSM.
            #
            # As l2fuzz is supposed to be used with an unpaired port,
            # TODO I get this error on any port, regardless if it requires pairing or not, or whether if I'm paired or not!
            #       It could be that SDP is not a connection oriented protocol and should fail this request? (in which case add logic for this)
            #        And furthermore that the other ports in my testing - even if they seem to work when fuzzing -
            #        does similarily fail?
            #       As indicated by the error message below, the recommended port to fuzz is SDP (port 1).
            #        If a port other than 1 is used, it is normal behavior that you need to pair in order to access and fuzz those ports.
            #
            # Reasoning for removal of port 1 fallback:
            #   As SDP should always work unpaired, the simplest solution is to fuzz this port only.
            #   However, it seemed confusing to the user that the program overrides their chosen port, so I removed the fallback to port 1,
            #     and instead continuing the test anyway.
            #   Note that it is likely that the fuzz test doesn't do much if the port requires pairing, in which case
            #     you should only see each packet being rejected. Still, the user may want to try this anyway to verify that's the case.
            #
            if result_value != 0:
                print(
                    "[!] Device is not paired with host('{}'). \n[!] l2fuzz may not be able to test the service port that you've selected. (try port 1 instead as SDP should not require pairing).".format(
                        L2CAP_Connect_Result.get(
                            result_value, "reserved for future use"
                        )
                    )
                )
                print(f"[!] Verify that {port=} does allow for unpaired connections, alternatively ensure that you are paired.")
                print("[!] Ignoring this error and trying again, beware.")
                #port = 1
                continue
        break

    state_machine.closed_to_w_conf()

    # 1) Target State : Wait Config State
    for i in range(0, iteration):
        # ConfigReq
        cmd_code = 0x04
        pkt4fuzz = (
            L2CAP_CmdHdr(code=cmd_code)
            / new_L2CAP_ConfReq(dcid=randrange(0x0040, 0x10000))
            / garbage_value(garbage=randrange(0x0000, 0x10000))
        )

        # logging, real sending(fuzzing in wait config state)
        sock, pkt_info = send_pkt(
            bt_addr, sock, pkt4fuzz, cmd_code, state_machine.current_state.name, port
        )
        if pkt_info == "":
            pass
        else:
            packet_info["packet"].append(pkt_info)

        # state transition
        state_machine.w_conf_to_w_conf()

    # From Wait Config State to Wait Send Config State
    cmd_code = 0x04
    pkt = L2CAP_CmdHdr(code=cmd_code) / L2CAP_ConfReq(dcid=dcid_value)
    sock, pkt_info = send_pkt(
        bt_addr, sock, pkt, cmd_code, state_machine.current_state.name, port
    )
    if pkt_info == "":
        pass
    else:
        packet_info["packet"].append(pkt_info)

    # state transition
    state_machine.w_conf_to_w_send_conf()

    # 2) Target State : Wait Send Config State
    for i in range(0, iteration):
        # ConfigReq
        cmd_code = 0x04
        pkt4fuzz = (
            L2CAP_CmdHdr(code=cmd_code)
            / new_L2CAP_ConfReq(dcid=randrange(0x0040, 0x10000))
            / garbage_value(garbage=randrange(0x0000, 0x10000))
        )

        # logging, real sending here (fuzzing in wait send config state)
        sock, pkt_info = send_pkt(
            bt_addr, sock, pkt4fuzz, cmd_code, state_machine.current_state.name, port
        )
        if pkt_info == "":
            pass
        else:
            packet_info["packet"].append(pkt_info)

    # state transition (L2CAP_ConfigReq will be sent from target device. From Wait Send Config State to Wait Config Rsp state)
    state_machine.w_send_conf_to_w_conf_rsp()

    # 3) Target State : Wait Config Rsp State
    for i in range(0, iteration):
        # ConfigResp(fail)
        cmd_code = 0x05
        pkt4fuzz = (
            L2CAP_CmdHdr(code=cmd_code)
            / new_L2CAP_ConfResp(scid=randrange(0x0040, 0x10000))
            / garbage_value(garbage=randrange(0x0000, 0x10000))
        )

        # logging, real sending here (fuzzing in wait send config state)
        sock, pkt_info = send_pkt(
            bt_addr, sock, pkt4fuzz, cmd_code, state_machine.current_state.name, port
        )
        if pkt_info == "":
            pass
        else:
            packet_info["packet"].append(pkt_info)

    # From Wait Config Rsp state to Wait Ind Final Rsp
    cmd_code = 0x05
    pkt = L2CAP_CmdHdr(code=cmd_code) / L2CAP_ConfResp(scid=dcid_value)
    sock, pkt_info = send_pkt(
        bt_addr, sock, pkt, cmd_code, state_machine.current_state.name, port
    )
    if pkt_info == "":
        pass
    else:
        packet_info["packet"].append(pkt_info)

    # state transition
    state_machine.w_conf_rsp_to_w_ind_final_rsp()

    # 4) Target State : Wait Ind Final Rsp State
    opt = randint(0, 1)
    if opt == 0:
        for i in range(0, iteration):
            random_port = random_psm()
            # ConnReq(fail)
            cmd_code = 0x02
            pkt = (
                L2CAP_CmdHdr(code=cmd_code)
                / new_L2CAP_ConnReq(psm=random_port)
                / garbage_value(garbage=randrange(0x0000, 0x10000))
            )

            # logging, real sending here
            sock, pkt_info = send_pkt(
                bt_addr, sock, pkt, cmd_code, state_machine.current_state.name, random_port
            )
            if pkt_info == "":
                pass
            else:
                packet_info["packet"].append(pkt_info)

        # From Wait Ind Final Rsp to Wait Final Rsp
        cmd_code = 0x02
        pkt = L2CAP_CmdHdr(code=cmd_code) / new_L2CAP_ConnReq(psm=port, scid=OUR_LOCAL_SCID)
        sock, pkt_info = send_pkt(
            bt_addr, sock, pkt, cmd_code, state_machine.current_state.name, port
        )
        if pkt_info == "":
            pass
        else:
            packet_info["packet"].append(pkt_info)

        # state transition
        state_machine.w_ind_final_rsp_to_w_final_rsp()

        # 4-1) Target State : Wait Final Rsp
        for i in range(0, iteration):
            # ConfigReq
            cmd_code = 0x04
            pkt4fuzz = (
                L2CAP_CmdHdr(code=cmd_code)
                / new_L2CAP_ConfReq(dcid=randrange(0x0040, 0x10000))
                / garbage_value(garbage=randrange(0x0000, 0x10000))
            )

            # logging, real sending here
            sock, pkt_info = send_pkt(
                bt_addr, sock, pkt4fuzz, cmd_code, state_machine.current_state.name, port
            )
            if pkt_info == "":
                pass
            else:
                packet_info["packet"].append(pkt_info)

        # From Wait Final Rsp to open
        cmd_code = 0x04
        pkt = L2CAP_CmdHdr(code=cmd_code) / L2CAP_ConfReq(dcid=dcid_value)
        sock, pkt_info = send_pkt(
            bt_addr, sock, pkt, cmd_code, state_machine.current_state.name, port
        )
        if pkt_info == "":
            pass
        else:
            packet_info["packet"].append(pkt_info)

        # state transition
        state_machine.w_final_rsp_to_open()

    elif opt == 1:
        for i in range(0, iteration):
            # ConfigReq
            cmd_code = 0x04
            pkt4fuzz = (
                L2CAP_CmdHdr(code=cmd_code)
                / new_L2CAP_ConfReq(dcid=randrange(0x0040, 0x10000))
                / garbage_value(garbage=randrange(0x0000, 0x10000))
            )

            # logging, real sending here
            sock, pkt_info = send_pkt(
                bt_addr, sock, pkt4fuzz, cmd_code, state_machine.current_state.name, port
            )
            if pkt_info == "":
                pass
            else:
                packet_info["packet"].append(pkt_info)

        # From Wait Ind Final Rsp to Wait Control Ind
        cmd_code = 0x04
        pkt = L2CAP_CmdHdr(code=cmd_code) / L2CAP_ConfReq(dcid=dcid_value)
        sock, pkt_info = send_pkt(
            bt_addr, sock, pkt, cmd_code, state_machine.current_state.name, port
        )
        if pkt_info == "":
            pass
        else:
            packet_info["packet"].append(pkt_info)

        # state transition
        state_machine.w_ind_final_rsp_to_w_control_ind()

        # 4-2) Target State : Wait Control Ind
        for i in range(0, iteration):
            random_port = random_psm()
            # ConnReq(fail)
            cmd_code = 0x02
            pkt = (
                L2CAP_CmdHdr(code=cmd_code)
                / new_L2CAP_ConnReq(psm=random_port)
                / garbage_value(garbage=randrange(0x0000, 0x10000))
            )
            # logging, real sending here
            sock, pkt_info = send_pkt(
                bt_addr, sock, pkt, cmd_code, state_machine.current_state.name, random_port
            )
            if pkt_info == "":
                pass
            else:
                packet_info["packet"].append(pkt_info)

        # From Wait Control Ind to open
        cmd_code = 0x02
        pkt = L2CAP_CmdHdr(code=cmd_code) / new_L2CAP_ConnReq(psm=port, scid=OUR_LOCAL_SCID)
        sock, pkt_info = send_pkt(
            bt_addr, sock, pkt, cmd_code, state_machine.current_state.name, port
        )
        if pkt_info == "":
            pass
        else:
            packet_info["packet"].append(pkt_info)

        # state transition
        state_machine.w_control_ind_to_open()


def shift_state_fuzzing(bt_addr, sock, state_machine, packet_info, port):
    """
    Connection Shift States : Wait Move, Wait Move Confirm, Wait Move Rsp, Wait Confirm Rsp

    >> From Configuration State to Connection Shift State
    Open State -> Wait Move
    [!] There is no real device which will be used for channel shift.

    >> Start state : Wait Move state

    >> Can Fuzzing : Wait Move, Wait Move Confirm
    1) Wait Move : Invalid Move req and invalid packets
    2) Wait Move Confirm : Invalid move chan confirm req and invalid packets

    >> Cannot Fuzzing : Wait Move Rsp, Wait Confirm Rsp
    1) Connection shift from Device to another device : Wait Move Rsp, Wait Confirm Rsp
    """
    iteration = 2500

    # 1) Target State : Wait Move State
    for i in range(0, iteration):
        # packet for moving from open state to wait move state with invalid movechanReq (with invalid dest_controller_id, 0x01(bt)-0x02(wifi) : valid id)
        cmd_code = 0x0E
        pkt = (
            L2CAP_CmdHdr(code=cmd_code)
            / L2CAP_Move_Channel_Request(dest_controller_id=randrange(0x02, 0x100))
            / garbage_value(garbage=randrange(0x0000, 0x10000))
        )

        # logging, real sending and state transition here
        sock, pkt_info = send_pkt(
            bt_addr, sock, pkt, cmd_code, state_machine.current_state.name, port
        )
        if pkt_info == "":
            pass
        else:
            packet_info["packet"].append(pkt_info)

        # state transition
        state_machine.open_to_w_move()

        # state transition
        state_machine.w_move_to_w_move_confirm()
        state_machine.w_move_confirm_to_open()

    # 2) Target State : Wait Move Confirm State
    for i in range(0, iteration):
        # packet for moving from open state to wait move confirm state with invalid move chan confirm req (with invalid icid)
        cmd_code = 0x0E
        pkt = (
            L2CAP_CmdHdr(code=cmd_code)
            / L2CAP_Move_Channel_Confirmation_Request(icid=randrange(0x00, 0x100))
            / garbage_value(garbage=randrange(0x0000, 0x10000))
        )

        # logging, real sending and state transition here
        sock, pkt_info = send_pkt(
            bt_addr, sock, pkt, cmd_code, state_machine.current_state.name, port
        )
        if pkt_info == "":
            pass
        else:
            packet_info["packet"].append(pkt_info)

        # state transition
        state_machine.open_to_w_move_confirm()

        # state transition
        state_machine.w_move_confirm_to_open()


def disconnection_state_fuzzing(bt_addr, sock, state_machine, port, packet_info):
    """
    Connection Shift States : Wait Disconnect

    >> From open to Disconnect
    Open State -> Wait disconnect

    >> Start state : Wait disconnect state

    >> Can Fuzzing : Wait Disconnect
    1) Wait Disconnect : Invalid disconn req with invalid psm and invalid packets
    """
    # print("\n\t[Disconnection State]")
    iteration = 2500

    # state transition
    state_machine.open_to_w_discon()

    # 1) Target State : Wait disconnect state
    for i in range(0, iteration):
        # packet for moving from open state to wait disconnect state
        cmd_code = 0x06
        pkt = (
            L2CAP_CmdHdr(code=cmd_code)
            / L2CAP_DisconnReq(
                scid=randrange(0x0040, 0x10000), dcid=randrange(0x0040, 0x10000)
            )
            / garbage_value(garbage=randrange(0x0000, 0x10000))
        )
        # logging, real sending and state transition here
        sock, pkt_info = send_pkt(
            bt_addr, sock, pkt, cmd_code, state_machine.current_state.name, port
        )
        if pkt_info == "":
            pass
        else:
            packet_info["packet"].append(pkt_info)

    # Valid Disconn Req
    cmd_code = 0x06
    pkt = L2CAP_CmdHdr(code=cmd_code) / L2CAP_DisconnReq(
        scid=OUR_LOCAL_SCID, dcid=dcid_value
    )

    # logging, real sending and state transition here
    sock, pkt_info = send_pkt(
        bt_addr, sock, pkt, cmd_code, state_machine.current_state.name, port
    )
    if pkt_info == "":
        pass
    else:
        packet_info["packet"].append(pkt_info)

    # state transition
    state_machine.w_disconn_to_closed()

def dump_adb_logs(time, port):
    # NOTE! Port is added to each failed request, however it may be misleading for certain request types
    #        that does not seem to be utilizing a port at all! In which case it includes user target port regardless.
    #        This can certainly be improved.
    filename=f"crash_port{port}_time{time}.adb.log".replace(" ","_")
    print("[-] Hard crash found, search for timestamp in logs to compare")
    print(f"[-] Time of crash {time}, port {port}")
    print(f"[-] Trying to save ADB logs to {filename}")

    ret = os.system(f"sudo adb logcat -t 5000 > '{filename}'")
    if ret != 0:
        print(f"ADB logcat may have failed, got exit code {exit_code}")
    return

def l2cap_fuzzing(bt_addr, profile, port, test_info):
    """
    Fuzzing in specific state = Sending packet from that state.
    """
    if profile == "None" or port == "None":
        print("Cannot Fuzzing")
        return

    with open(
        "log_port{}_{}.wfl".format(port, test_info["starting_time"][11:19].replace(":", "", 2)),
        "w",
        encoding="utf-8",
    ) as f:
        logger = OrderedDict()
        logger.update(test_info)
        logger["packet"] = []

        #print("Start Fuzzing... Please hit Ctrl + C to finish...")
        sock = BluetoothL2CAPSocket(bt_addr)
        state_machine = l2cap_state_machine()

        try:
            while True:
                try:
                    print("[+] Tested %d packets" % (pkt_cnt))

                    #Note! exit after many requests to avoid very big log files / out of memory, arbitrary limit
                    if len(logger["packet"]) > 5000000:
                        print("Success! 50m tries performed, saving to log..")
                        raise KeyboardInterrupt

                    # Connection State Fuzzing (1/2) + closed
                    connection_state_fuzzing(bt_addr, sock, state_machine, logger)

                    # Creation State fuzzing (1/2)
                    creation_state_fuzzing(bt_addr, sock, state_machine, logger)

                    # Configuration State Fuzzing (6/8)
                    configuration_state_fuzzing(
                        bt_addr, sock, state_machine, profile, port, logger
                    )

                    # Connection Shift State Fuzzing (2/4)
                    shift_state_fuzzing(bt_addr, sock, state_machine, logger, port)

                    # Disconnection State Fuzzing (1/1)
                    disconnection_state_fuzzing(bt_addr, sock, state_machine, port, logger)

                except KeyError as exception:
                    print(f"[!] Got exception KeyError: {exception}.")
                    print(f"[!] Catch programmer errors, this should never happen.")
                    exit(1)

                # In case an unexpected error, reset BT socket/state and continue testing (a bit ugly)
                # NOTE: you may want to log this? However seems like a lot of false positives
                except Exception as exception:
                    print(f"[!] Unexpected exception: {exception}. Reopening bluetooth socket and continuing...")
                    print(f"[!] Warning! This was not expected. Resetting socket/state machine may create issues (?).\n")

                    # arbitrary wait can remove
                    time.sleep(2)

                    # Reset Socket and State. TODO: what effect does this have on running test?
                    sock = BluetoothL2CAPSocket(bt_addr)
                    state_machine = l2cap_state_machine()

                    # arbitrary wait can remove
                    time.sleep(2)
                    #print(f"[!] restarted bluetooth socket")


        except KeyboardInterrupt as k:
            print("[!] Fuzzing Stopped :", k)
            print("[+] Save logfile")
            logger["end_time"] = str(datetime.now())
            logger["count"] = {
                "all": pkt_cnt,
                "crash": crash_cnt,
                "passed": pkt_cnt - crash_cnt,
            }
            json.dump(logger, f, indent="\t")

        # (This should not be possible any longer due to above except)
        except Exception as exception:
            print(f"[!] Error Message : {exception}")
            print("[+] Save logfile")
            logger["end_time"] = str(datetime.now())
            logger["count"] = {
                "all": pkt_cnt,
                "crash": crash_cnt,
                "passed": pkt_cnt - crash_cnt,
            }
            json.dump(logger, f, indent="\t")
