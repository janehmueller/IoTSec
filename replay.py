import argparse

from scapy.layers.inet6 import IPv6, UDP
from scapy.sendrecv import sr

from fuzzer import setup_devices


def cli_args():
    parser = argparse.ArgumentParser(description='Replay of CoAP Messages')
    parser.add_argument("--iface", dest="interface", type=str)
    parser.add_argument("--message", dest="message", type=str, required=True)
    parser.add_argument("--skip-setup", dest="skip_setup", action='store_true')
    parser.add_argument("--dest-address", dest="dest_address", type=str)
    return parser.parse_args()


def main():
    args = cli_args()

    if args.skip_setup:
        print("Skipping OpenMote setup...")
        assert args.dest_address is not None, "Destination address must be provided if OpenMote setup is skipped."
        dest_address = args.dest_address
    else:
        # Setup OpenMotes
        border_router_ip, coap_server_ip = setup_devices()
        assert border_router_ip is not None, "Border router setup failed."
        assert coap_server_ip is not None, "CoAP server setup failed."
        print("border-router: " + border_router_ip)
        print("coap-server: " + coap_server_ip)
        dest_address = coap_server_ip

    # Create packet from the CoAP hex string
    interface = args.interface or "tun0"
    coap = bytes(bytearray.fromhex(args.message))
    packet = IPv6(dst=dest_address) / UDP(sport=34552, dport=5683) / coap
    print("Sending following packet:")
    packet.show2()

    # Replay packet and show response
    full_response, empty = sr(packet, iface=interface, timeout=5, verbose=False)
    full_response.show()


if __name__ == "__main__":
    main()
