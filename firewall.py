import os
from netfilterqueue import NetfilterQueue
from scapy.all import *


def load_rules():
    allowed_incoming = {}
    blocked_outgoing = {}
    block_all_incoming = False


    with open('rules.txt', 'r') as f:
        for line in f:

            line = line.strip()
            if line.startswith('#') or not line:
                continue
            

            parts = line.split()


            if len(parts) == 4:
                action, direction, protocol, port = parts[0], parts[1], parts[2], int(parts[3])
                

                if direction == "IN":
                    if action == "ALLOW_IN":
                        allowed_incoming[(protocol, port)] = True
                    elif action == "BLOCK_IN":
                        allowed_incoming[(protocol, port)] = False

                elif direction == "OUT":
                    if action == "BLOCK_OUT":
                        blocked_outgoing[(protocol, port)] = True


            elif len(parts) == 1 and parts[0] == "BLOCK_ALL_INCOMING":
                block_all_incoming = True

    return allowed_incoming, blocked_outgoing, block_all_incoming


def packet_callback(packet, allowed_incoming, blocked_outgoing, block_all_incoming):
    scapy_packet = IP(packet.get_payload())  
    if scapy_packet.haslayer(IP):
        ip_layer = scapy_packet.getlayer(IP)


        if scapy_packet.haslayer(TCP):
            proto = 'TCP'
            tcp_udp_layer = scapy_packet.getlayer(TCP)
        elif scapy_packet.haslayer(UDP):
            proto = 'UDP'
            tcp_udp_layer = scapy_packet.getlayer(UDP)
        else:
            packet.accept()  # Accept non-TCP/UDP packets by default
            return

        port = tcp_udp_layer.dport if ip_layer.dst == get_if_addr(conf.iface) else tcp_udp_layer.sport
        direction = "Incoming" if ip_layer.dst == get_if_addr(conf.iface) else "Outgoing"

        # Handle incoming traffic
        if direction == "Incoming":
            if block_all_incoming and (proto, port) not in allowed_incoming:
                print(f"Blocking incoming {proto} packet on port {port}")
                packet.drop()  # Drop packet
                return
            elif allowed_incoming.get((proto, port), False):
                print(f"Allowing incoming {proto} packet on port {port}")
                packet.accept()  # Accept packet
                return

        # Handle outgoing traffic
        if direction == "Outgoing" and blocked_outgoing.get((proto, port), False):
            print(f"Blocking outgoing {proto} packet on port {port}")
            packet.drop()  # Drop packet
            return

        # Default: Block if no rule matches
        print(f"Blocking {proto} packet on port {port}")
        packet.drop()  # Drop packet
    else:
        packet.accept()  # Accept non-IP packets

# Main function to start the firewall
def start_firewall():
    allowed_incoming, blocked_outgoing, block_all_incoming = load_rules()

    print("Firewall started. Monitoring traffic...")

    # Set up NetfilterQueue
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, lambda p: packet_callback(p, allowed_incoming, blocked_outgoing, block_all_incoming))

    try:
        # Run the queue
        nfqueue.run()
    except KeyboardInterrupt:
        print("Stopping firewall")
    finally:
        nfqueue.unbind()

if __name__ == "__main__":
    # Set iptables rules to redirect traffic to NFQUEUE
    os.system("sudo iptables -I INPUT -j NFQUEUE --queue-num 1")
    os.system("sudo iptables -I OUTPUT -j NFQUEUE --queue-num 1")

    start_firewall()

    # Remove iptables rules when done
    os.system("sudo iptables -D INPUT -j NFQUEUE --queue-num 1")
    os.system("sudo iptables -D OUTPUT -j NFQUEUE --queue-num 1")





#sudo apt-get install libnetfilter-queue-dev

#pip3 install NetfilterQueue

#sudo apt-get install libnfnetlink-dev libnetfilter-queue-dev

#pip3 install NetfilterQueue

#pip3 install git+https://github.com/kti/python-netfilterqueue

#python3 -c "import netfilterqueue"

#sudo apt-get install python3-dev libnetfilter-queue-dev

#sudo apt-get install build-essential

#pip3 install git+https://github.com/kti/python-netfilterqueue.git

#python3 -c "import netfilterqueue"

#pip3 list | grep NetfilterQueue

#python3 -m pip install git+https://github.com/kti/python-netfilterqueue.git

#sudo pip3 install git+https://github.com/kti/python-netfilterqueue.git

#sudo chmod -R 755 $(python3 -m site --user-site)

#python3 -m venv firewall_env

#source firewall_env/bin/activate

#pip install git+https://github.com/kti/python-netfilterqueue.git

#sudo python3 firewall.py
