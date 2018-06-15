from scapy.contrib.coap import *
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.inet6 import *

def test_well_known_core():
    wkc_message = CoAP(ver=1L, 
                       type=0, 
                       code=1, 
                       token=RandBin(RandNum(0,8)),
                       options=[(11L, '.well-known/core')])
    wkc_req = IPv6(dst=dst_address)/UDP(sport=34552, dport=5683)/wkc_message
    full_response, empty = sr(wkc_req, iface="tun0", timeout=5)
    if (full_response[0][1].load == '</.well-known/core>;ct=40,</actuators/leds>;title=\"LEDs: ?color='):
        return True
    return False
  
fuzz_pattern = fuzz(CoAP(
    ver=1L,
    type=RandNum(0, 1),
    code=RandNum(0, 4),
    token=RandBin(RandNum(0, 8)),
    options=[(11L, 'core')],
    paymark='\xff'+str(RandNum(0, 256))
))
fuzz_pattern.show2()

dst_address = "fd00::ff:fe00:53b8"
packet = IPv6(dst=dst_address)/UDP(sport=34552, dport=5683)/fuzz_pattern
full_response, empty = sr(packet, iface="tun0", timeout=5)
num_responses = len(full_response)
if num_responses == 0:  # NON
    pass
elif num_responses == 1:  # CON, RST
    request, response = full_response[0]
    response.show()

print("Mote is working: " + str(test_well_known_core()))
