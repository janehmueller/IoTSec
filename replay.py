import argparse

from scapy.layers.inet6 import IPv6, UDP
from scapy.sendrecv import sr

from fuzzer import setup_devices


def cli_args():
    parser = argparse.ArgumentParser(description='Replay of CoAP Messages')
    parser.add_argument("--iface", dest="interface", type=str)
    parser.add_argument("--message", dest="message", type=str, required=True)
    return parser.parse_args()


def main():
    args = cli_args()

    # Setup OpenMotes
    border_router_ip, coap_server_ip = setup_devices()
    assert border_router_ip is not None, "Border router setup failed."
    assert coap_server_ip is not None, "CoAP server setup failed."
    print("border-router: " + border_router_ip)
    print("coap-server: " + coap_server_ip)
    dst_address = coap_server_ip

    # Create packet from the CoAP hex string
    interface = args.interface or "tun0"
    coap = bytes(bytearray.fromhex(args.message))
    packet = IPv6(dst=dst_address) / UDP(sport=34552, dport=5683) / coap
    print("Sending following packet:")
    packet.show2()

    # Replay packet and show response
    full_response, empty = sr(packet, iface=interface, timeout=5, verbose=False)
    full_response.show()


if __name__ == "__main__":
    main()
