from scapy.contrib.coap import *
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.inet6 import *
import argparse
import json
import time
import subprocess
import os
from timeit import default_timer

well_known_core = '</.well-known/core>;ct=40,</actuators/leds>;title=\"LEDs: ?color='
timeout = 5


def test_well_known_core(dest_address):
    wkc_message = CoAP(
        ver=1L,
        type=0,
        code=1,
        token=RandBin(RandNum(0, 8)).__bytes__(),
        options=[(11L, '.well-known/core')]
    )
    wkc_req = IPv6(dst=dest_address)/UDP(sport=34552, dport=5683)/wkc_message
    full_response, empty = sr(wkc_req, iface="tun0", timeout=timeout, verbose=False)
    if len(full_response) == 0:
        return None
    return full_response[0][1].load == well_known_core


def cli_args():
    parser = argparse.ArgumentParser(description='CoAP Fuzzer for OpenMotes')
    parser.add_argument("--output", dest="output_file", type=str, required=True)
    parser.add_argument("--contiki", dest="contiki_path", type=str)
    parser.add_argument("--iface", dest="interface", type=str)
    parser.add_argument("--dest-address", dest="dest_address", type=str)
    parser.add_argument("--skip-setup", dest="skip_setup", action='store_true')
    parser.add_argument("--overwrite", dest="file_overwrite", action='store_true')
    parser.add_argument("--debug", dest="debug", action='store_true')
    parser.add_argument("--clean", dest="clean", action='store_true')
    parser.add_argument("--benchmark", dest="benchmark", type=int)
    return parser.parse_args()


def setup_devices(contiki_path, debug=False):
    devnull = open(os.devnull, 'wb')
    p = subprocess.Popen(["bash", "./border_router_setup.sh", contiki_path], stdout=subprocess.PIPE, stderr=devnull)
    # border_router_ip = None
    print("Starting border router...")
    for line in iter(p.stdout.readline, ""):
        if debug:
            # print(line)
            sys.stdout.write(line)
        if re.search(".*Tentative link-local IPv6 address.*", line, flags=0):
            border_router_ip_parts = line.split(" ")[-1].split(":")
            border_router_ip_parts[0] = "fd00"
            border_router_ip = ":".join(border_router_ip_parts).replace("\n","")
            print("border router started with ip %s ..." % border_router_ip)
            break

    q = subprocess.Popen(["bash", "./coap_server_setup.sh", contiki_path], stdout=subprocess.PIPE, stderr=devnull)
    time.sleep(1)
    # coap_server_ip = None
    print("Starting CoAP server...")
    for line in iter(q.stdout.readline, ""):
        if debug:
            # print(line)
            sys.stdout.write(line)
        if re.search(".*Tentative link-local IPv6 address.*", line, flags=0):
            coap_server_ip_parts = line.split(" ")[-1].split(":")
            coap_server_ip_parts[0] = "fd00"
            coap_server_ip = ":".join(coap_server_ip_parts).replace("\n","")
            print("CoAP server started with ip %s ..." % coap_server_ip)
            break
        elif re.search(".*Activating: sensors/max44009.*", line, flags=0):
            print("You might need to press reset on the CoAP server OpenMote...")

    return border_router_ip, coap_server_ip


def random_coap():
    token = RandBin(RandNum(0, 8)).__bytes__()
    token_len = RandNum(0, 8).__int__()  # len(token)
    return CoAP(
        ver=1L,
        type=RandNum(0, 1).__int__(),
        tkl=token_len,
        code=random_status_code(),
        msg_id=RandShort().__int__(),
        token=token,
        options=random_options(),
        paymark='\xff' + str((RandNum(0, 255).__int__())
    )


def random_options():
    """
    IF_MATCH = 1
    URI_HOST = 3
    ETAG = 4
    IF_NONE_MATCH = 5
    OBSERVE = 6  ### NON_RFC
    URI_PORT = 7
    LOCATION_PATH = 8
    URI_PATH = 11
    CONTENT_FORMAT = 12
    MAX_AGE = 14
    URI_QUERY = 15
    ACCEPT = 17
    LOCATION_QUERY = 20
    BLOCK2 = 23  ### NON_RFC
    BLOCK1 = 27  ### NON_RFC
    SIZE2 = 28  ### NON_RFC
    PROXY_URI = 35
    PROXY_SCHEME = 39
    SIZE1 = 60
    """
    option_ids = [1, 3, 4, 5, 6, 7, 8, 11, 12, 14, 15, 17, 20, 23, 27, 28, 35, 39, 60]
    num_options = RandNum(0, len(option_ids)).__int__()
    selected_options = random.sample(option_ids, num_options)
    return [(opt, RandString(RandNum(0, 12).__int__()).__str__()) for opt in selected_options]


def random_status_code():
    """
    ### REQUEST
    GET = 1
    POST = 2
    PUT = 3
    DELETE = 4

    ### RESPONSE
    CREATED_2_01 = 65
    DELETED_2_02 = 66
    VALID_2_03 = 67
    CHANGED_2_04 = 68
    CONTENT_2_05 = 69
    CONTINUE_2_31 = 95

    BAD_REQUEST_4_00 = 128
    UNAUTHORIZED_4_01 = 129
    BAD_OPTION_4_02 = 130
    FORBIDDEN_4_03 = 131
    NOT_FOUND_4_04 = 132
    METHOD_NOT_ALLOWED_4_05 = 133
    NOT_ACCEPTABLE_4_06 = 134
    PRECONDITION_FAILED_4_12 = 140
    REQUEST_ENTITY_TOO_LARGE_4_13 = 141
    UNSUPPORTED_MEDIA_TYPE_4_15 = 143

    INTERNAL_SERVER_ERROR_5_00 = 160
    NOT_IMPLEMENTED_5_01 = 161
    BAD_GATEWAY_5_02 = 162
    SERVICE_UNAVAILABLE_5_03 = 163
    GATEWAY_TIMEOUT_5_04 = 164
    PROXYING_NOT_SUPPORTED_5_05 = 165
    """
    status_codes = [1, 2, 3, 4, 65, 66, 67, 68, 69, 95, 128, 129, 130, 131, 132, 133, 134, 140, 141, 143, 160, 161, 162, 163, 164, 165]
    return status_codes[RandNum(0, len(status_codes) - 1).__int__()]


def main():
    args = cli_args()
    if args.skip_setup:
        print("Skipping OpenMote setup...")
        assert args.dest_address is not None, "Destination address must be provided if OpenMote setup is skipped."
        dest_address = args.dest_address
    
    else:
        assert args.contiki_path is not None, "Contiki path must be provided for OpenMote setup."
        border_router_ip, coap_server_ip = setup_devices(args.contiki_path, args.debug)
        assert border_router_ip is not None, "Border router setup failed."
        assert coap_server_ip is not None, "CoAP server setup failed."
        print("border-router: " + border_router_ip)
        print("coap-server: " + coap_server_ip)
        dest_address = coap_server_ip

    interface = args.interface or "tun0"
    file_mode = "w" if args.file_overwrite else "a"
    output_file = open(args.output_file, file_mode)
    output_file.write(json.dumps({
        "dest_address": dest_address,
        "interface": interface
    }) + "\n")
    log_output = {}
    start_time = default_timer()
    try:
        num_packets = 1
        print()
        while True:
            sys.stdout.write("\rSending packet %d..." % num_packets)
            sys.stdout.flush()
            # print("Sending packet %d..." % num_packets)
            fuzz_pattern = random_coap()
            # fuzz_pattern.show()
            # print(linehexdump(fuzz_pattern, dump=True, onlyhex=1))
            packet = IPv6(dst=dest_address) / UDP(sport=34552, dport=5683) / fuzz_pattern
            full_response, empty = sr(packet, iface=interface, timeout=timeout, verbose=False)
            num_responses = len(full_response)
            log_output["request"] = linehexdump(fuzz_pattern, dump=True, onlyhex=1)
            try:
                if num_responses == 0:  # timeout
                    pass
                elif num_responses == 1:
                    request, response = full_response[0]
                    log_output["response"] = linehexdump(response, dump=True, onlyhex=1)
                    # response.show()
                log_output["well-kown-core"] = test_well_known_core(dest_address)
            except AttributeError:
                log_output["response"] = None
            log_output["timestamp"] = int(time.time())
            output_file.write(json.dumps(log_output) + "\n")

            # TODO: make this work
            # if log_output["well-kown-core"] is None:
            #     print()
            #     print("OpenMote timed out. Waiting for it to respond again...")
            #     while True:
            #         res = sr1((IPv6(dst=dest_address) / ICMPv6EchoRequest()), iface=interface, timeout=timeout)
            #         if res:
            #             break
            #         time.sleep(1)
            #     print("OpenMote back up...")

            num_packets += 1
            if args.benchmark is not None and num_packets >= args.benchmark:
                print("\nFinished benchmark of %d packets..." % args.benchmark)
                print("Took %s seconds" % str(default_timer() - start_time))
                break
    except (KeyboardInterrupt, SystemExit):
        output_file.close()
        exit()


if __name__ == "__main__":
    main()
