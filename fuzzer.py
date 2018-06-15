from scapy.contrib.coap import *
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.inet6 import *
import argparse
import json
import time

def cli_args():
    parser = argparse.ArgumentParser(description='CoAP Fuzzer for OpenMotes')
    parser.add_argument("--dest", dest="dst_address", type=str, required=True)
    parser.add_argument("--iface", dest="interface", type=str)
    parser.add_argument("--output", dest="output_file", type=str, required=True)
    parser.add_argument("--overwrite-output", dest="file_overwrite", action='store_true')
    return parser.parse_args()


if __name__ == "__main__":
    args = cli_args()
    dst_address = args.dst_address
    interface = args.interface or "tun0"
    file_mode = "w" if args.file_overwrite else "a"
    output_file = open(args.output_file, file_mode)
    output_file.write(json.dumps({
        "dst_address": dst_address,
        "interface": interface
    }) + "\n")
    log_output = {}
    try:
        num_packets = 1
        print()
        while True:
            sys.stdout.write("\rSending packet %d..." % num_packets)
            sys.stdout.flush()
            fuzz_pattern = fuzz(CoAP(
                ver=1L,
                type=RandNum(0, 1).__int__(),
                code=RandNum(1, 4).__int__(),
                token=RandBin(RandNum(0, 8)).__bytes__(),
                options=[(11L, 'core')],
                paymark='\xff'+str(RandNum(0, 256).__int__())
            ))
            # fuzz_pattern.show2()
            packet = IPv6(dst=dst_address)/UDP(sport=34552, dport=5683)/fuzz_pattern
            full_response, empty = sr(packet, iface=interface, timeout=5, verbose=False)

            num_responses = len(full_response)
            log_output["request"] = linehexdump(fuzz_pattern, dump=True, onlyhex=1)
            if num_responses == 0:  # timeout
                pass
            elif num_responses == 1:
                request, response = full_response[0]
                log_output["response"] = linehexdump(response, dump=True, onlyhex=1)
                # response.show()

            log_output["timestamp"] = int(time.time())
            output_file.write(json.dumps(log_output) + "\n")

            num_packets += 1
    except (KeyboardInterrupt, SystemExit):
        output_file.close()
        exit()
