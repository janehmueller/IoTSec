from scapy.contrib.coap import *
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.inet6 import *


fuzz_pattern = fuzz(CoAP(
    ver=1L,
    type=RandNum(0, 1),
    code=RandNum(0, 4),
    token=RandBin(RandNum(0, 8)),
    options=[(11L, 'core')],
    paymark='\xff'+str(RandNum(0, 256))
))
fuzz_pattern.show2()

dst_address = "fd00::ff:fe00:5403"
packet = IPv6(dst=dst_address)/UDP(sport=34552, dport=5683)/fuzz_pattern
full_response, empty = sr(packet, iface="tun0", timeout=5)
num_responses = len(full_response)
if num_responses == 0:  # NON
    pass
elif num_responses == 1:  # CON, RST
    request, response = full_response[0]
    response.show()
