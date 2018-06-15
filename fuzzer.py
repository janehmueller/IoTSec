from scapy.contrib.coap import *
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.inet6 import *

# conf.L3socket = L3RawSocket
# fuzz_pattern = fuzz(CoAP(
#     ver=1L,
#     type=RandNum(0, 1),
#     code=RandNum(0, 4),
#     token=RandBin(RandNum(0, 8)),
#     options=[(11L, 'core')],
#     paymark='\xff'+str(RandBin())
# ))
# print("show")
# fuzz_pattern.show()
# print("show2")
# fuzz_pattern.show2()

dst_address = "8.8.8.8"
dst_address = "ipv6.google.com"
# packet = IPv6(dst=dst_address)/UDP(sport=34552, dport=5683)/fuzz_pattern
packet = IPv6(dst=dst_address)/ICMPv6EchoRequest()
# packet = IP(dst=dst_address)/ICMP()
for answer in sr(packet):
    print("showing answer: %s" % answer)
    answer.show()
# srloop(packet, verbose=20, retry=-1, timeout=2)
