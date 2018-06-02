from scapy.contrib.coap import *
from scapy.all import *
from scapy.layers.inet6 import IPv6

random.seed("Let's fuzz CoAP!")
conf.L3socket = L3RawSocket
fuzz_pattern = fuzz(CoAP(
    ver=1L,
    type=RandNum(0, 1),
    code=RandNum(0, 4),
    token=RandBin(RandNum(0, 8)),
    options=[(11L, 'core')],
    paymark='\xff'+str(RandBin())
))

fuzz_pattern.show2()

dst_address = ""
packet = IPv6(dst=dst_address)/UDP(sport=34552, dport=5683)/fuzz_pattern
srloop(packet, verbose=20, retry=-1, timeout=2)
