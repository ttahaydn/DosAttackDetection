import xml.etree.ElementTree as ET
from scapy.all import sniff, TCP, IP
from datetime import datetime

tree = ET.parse("dfa.xml")
root = tree.getroot()

# Extract states
states = {state.attrib['name']: state.attrib.get('type', None) for state in root.find('states')}
start_state = next(state for state, type_ in states.items() if type_ == 'start')
accept_states = [state for state, type_ in states.items() if type_ == 'accept']

# Extract alphabet
alphabet = [symbol.text for symbol in root.find('alphabet')]

# Extract transitions
transitions = {}
for transition in root.find('transitions'):
    from_state = transition.find('from').text
    to_state = transition.find('to').text
    read_symbol = transition.find('read').text
    if from_state not in transitions:
        transitions[from_state] = {}
    transitions[from_state][read_symbol] = to_state

# Define DFA
class DFA:
    def __init__(self, start_state, accept_states, transitions):
        self.current_state = start_state
        self.accept_states = accept_states
        self.transitions = transitions

    def transition(self, symbol):
        if symbol in self.transitions[self.current_state]:
            self.current_state = self.transitions[self.current_state][symbol]

    def is_accepting(self):
        return self.current_state in self.accept_states

# Initialize DFA
dfa = DFA(start_state, accept_states, transitions)

# Packet processing function
syn_tokens = []
start_time = None

def process_packet(packet):
    global start_time
    if start_time is None:
        start_time = packet.time

    if packet.haslayer(TCP) and packet[TCP].flags == "S":
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        pck_flag = packet[TCP].flags
        timestamp = packet.time - start_time
        syn_token = {"src_ip": src_ip, "dst_ip": dst_ip, "timestamp": timestamp, "pck_flag": pck_flag}
        syn_tokens.append(syn_token)
        if len(syn_tokens) > 10:
            dfa.transition('a')
            if syn_tokens[-1]["timestamp"] - syn_tokens[-2]["timestamp"] < 0.1:
                dfa.transition('c')
                if dfa.is_accepting():
                    for i, token in enumerate(syn_tokens, 1):
                        print(f"{i}. {token}")
                    print("DDoS attack detected!!!")
                    exit(0)
            else:
                dfa.transition('b')
        else:
            dfa.transition('b')

input_interface = input("enter your interface name here: ")
sniff(iface=input_interface, prn=process_packet)