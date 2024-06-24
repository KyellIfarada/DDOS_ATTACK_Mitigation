from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.addresses import EthAddr, IPAddr
import time
import csv
import pox.lib.packet as pkt
from collections import defaultdict
import uuid
from pox.lib.util import dpidToStr

log = core.getLogger()
priority = 50000

# Constants
MAX_FLOWS = 5  # Maximum allowed flows per TIME_WINDOW
TIME_WINDOW = 60  # Time window in seconds
RATE_LIMIT_WINDOW = 10  # Rate limiting window in seconds
RATE_LIMIT = 2  # Maximum allowed flows per RATE_LIMIT_WINDOW

# Initialize tracking dictionaries and blacklist
mac_ip_map = defaultdict(set)  # Tracks IP addresses seen for each MAC address
ip_mac_map = {}  # Tracks MAC addresses seen for each IP address
blacklist = set()  # Set of blocked MAC addresses
flow_counters = defaultdict(list)  # Tracks timestamps of flows for each MAC address

def get_mac_address():
    mac = uuid.getnode()
    mac_address = ':'.join(("%012X" % mac)[i:i+2] for i in range(0, 12, 2))
    return mac_address

class Firewall(EventMixin):
    def __init__(self, l2config="l2firewall.config", fwconfig="l3firewall.config"):
        self.listenTo(core.openflow)
        self.disabled_MAC_pair = []  # Store a tuple of MAC pairs to be installed into the flow table of each switch.
        self.read_l2_rules(l2config)
        self.read_l3_rules(fwconfig)
        log.debug("Enabling Firewall Module")

    def read_l2_rules(self, l2config):
        with open(l2config, 'r') as rules:
            csvreader = csv.DictReader(rules)
            for line in csvreader:
                mac_0 = EthAddr(line['mac_0']) if line['mac_0'] != 'any' else None
                mac_1 = EthAddr(line['mac_1']) if line['mac_1'] != 'any' else None
                self.disabled_MAC_pair.append((mac_0, mac_1))

    def read_l3_rules(self, l3config):
        with open(l3config, 'r') as csvfile:
            log.debug("Reading firewall rules...")
            self.rules = csv.DictReader(csvfile)
            for row in self.rules:
                log.debug("Parsing firewall rule: %s", row)

    def replyToARP(self, packet, match, event):
        r = pkt.arp()
        r.opcode = pkt.arp.REPLY
        r.hwdst = match.dl_src
        r.protosrc = match.nw_dst
        r.protodst = match.nw_src
        r.hwsrc = match.dl_dst
        e = pkt.ethernet(type=packet.ARP_TYPE, src=r.hwsrc, dst=r.hwdst)
        e.set_payload(r)
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
        msg.in_port = event.port
        event.connection.send(msg)

    def allowOther(self, event, match):
        srcmac = str(match.dl_src)
        dstmac = str(match.dl_src)
        sport = int(match.tp_src)
        dport = int(match.tp_dst)
        nw_proto = str(match.nw_proto)
        nw_proto1 = pkt.ipv4.ICMP_PROTOCOL
        print "new proto: " + nw_proto
        if nw_proto == "tcp":
            nw_proto1 = pkt.ipv4.TCP_PROTOCOL
        elif nw_proto == "icmp":
            nw_proto1 = pkt.ipv4.ICMP_PROTOCOL
            s_port1 = None
            d_port1 = None
        elif nw_proto == "udp":
            nw_proto1 = pkt.ipv4.UDP_PROTOCOL
        else:
            print "PROTOCOL field is mandatory, Choose between ICMP, TCP, UDP"
        print "Allow other"
        print event

        packet = event.parsed
        srcIp = str(packet.payload.srcip)
        dstIp = str(packet.payload.dstip)
        print packet.payload

        print "srcMac: " + srcmac
        print "srcip: " + srcIp

        msg = of.ofp_flow_mod()
        match = of.ofp_match()
        action = of.ofp_action_output(port=of.OFPP_NORMAL)

        if srcIp != None:
            match.nw_src = IPAddr(srcIp)
        if dstIp != None:
            match.nw_dst = IPAddr(dstIp)
        match.nw_proto = int(nw_proto1)
        match.dl_src = EthAddr(srcmac)
        match.dl_dst = EthAddr(dstmac)
        match.tp_src = sport
        match.tp_dst = dport
        match.dl_type = pkt.ethernet.IP_TYPE
        msg.match = match
        msg.hard_timeout = 0
        msg.idle_timeout = 7200
        msg.priority = 5
        msg.actions.append(action)

        event.connection.send(msg)

    def installFlow(self, event, offset, srcmac, dstmac, srcip, dstip, sport, dport, nwproto):
        msg = of.ofp_flow_mod()
        match = of.ofp_match()
        if srcip is not None:
            match.nw_src = pkt.IPAddr(srcip)
        if dstip is not None:
            match.nw_dst = pkt.IPAddr(dstip)
        match.nw_proto = int(nwproto)
        match.dl_src = srcmac
        match.dl_dst = dstmac
        match.tp_src = sport
        match.tp_dst = dport
        match.dl_type = pkt.ethernet.IP_TYPE
        msg.match = match
        msg.hard_timeout = 0
        msg.idle_timeout = 200
        msg.priority = priority + offset
        event.connection.send(msg)

    def replyToIP(self, packet, match, event, fwconfig):
        srcmac = str(match.dl_src)
        dstmac = str(match.dl_src)
        sport = str(match.tp_src)
        dport = str(match.tp_dst)
        nwproto = str(match.nw_proto)

        with open(fwconfig) as csvfile:
            log.debug("Reading log file!")
            self.rules = csv.DictReader(csvfile)
            for row in self.rules:
                prio = row['priority']
                srcmac = row['src_mac']
                dstmac = row['dst_mac']
                s_ip = row['src_ip']
                d_ip = row['dst_ip']
                s_port = row['src_port']
                d_port = row['dst_port']
                nw_proto = row['nw_proto']

                log.debug("You are in original code block ...")
                srcmac1 = EthAddr(srcmac) if srcmac != 'any' else None
                dstmac1 = EthAddr(dstmac) if dstmac != 'any' else None
                s_ip1 = s_ip if s_ip != 'any' else None
                d_ip1 = d_ip if d_ip != 'any' else None
                s_port1 = int(s_port) if s_port != 'any' else None
                d_port1 = int(d_port) if d_port != 'any' else None
                prio1 = int(prio) if prio is not None else priority
                if nw_proto == "tcp":
                    nw_proto1 = pkt.ipv4.TCP_PROTOCOL
                elif nw_proto == "icmp":
                    nw_proto1 = pkt.ipv4.ICMP_PROTOCOL
                    s_port1 = None
                    d_port1 = None
                elif nw_proto == "udp":
                    nw_proto1 = pkt.ipv4.UDP_PROTOCOL
                else:
                    log.debug("PROTOCOL field is mandatory, Choose between ICMP, TCP, UDP")
                print prio1, s_ip1, d_ip1, s_port1, d_port1, nw_proto1
                self.installFlow(event, prio1, srcmac1, dstmac1, s_ip1, d_ip1, s_port1, d_port1, nw_proto1)
        self.allowOther(event, match)

    def _handle_ConnectionUp(self, event):
        self.connection = event.connection
        for (source, destination) in self.disabled_MAC_pair:
            message = of.ofp_flow_mod()
            match = of.ofp_match(dl_src=source, dl_dst=destination)
            message.priority = 65535
            message.match = match
            event.connection.send(message)
        log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))

    def _handle_PacketIn(self, event):
        packet = event.parsed
        match = of.ofp_match.from_packet(packet)
        self.read_l3_rules("l3firewall.config")

        src_mac = str(match.dl_src)
        dst_mac = str(match.dl_dst)
        src_ip = str(match.nw_src)
        dst_ip = str(match.nw_dst)

        log.debug("Packet in %s %s %s %s %s", src_mac, dst_mac, src_ip, dst_ip, match)

        current_time = time.time()
        flow_counters[src_mac] = [ts for ts in flow_counters[src_mac] if current_time - ts < TIME_WINDOW]

        if len(flow_counters[src_mac]) >= MAX_FLOWS:
            if src_mac not in blacklist:
                blacklist.add(src_mac)
                log.info("MAC address %s added to blacklist due to flow limit", src_mac)

        flow_counters[src_mac].append(current_time)

        if src_mac in blacklist:
            log.info("Blocking packet from blacklisted MAC address %s", src_mac)
            return

        ip_mac_map[src_ip] = src_mac

        if src_mac in mac_ip_map and src_ip not in mac_ip_map[src_mac]:
            log.warning("Possible MAC spoofing detected: %s is claiming to be %s", src_mac, src_ip)
            return

        mac_ip_map[src_mac].add(src_ip)

        if len(mac_ip_map[src_mac]) > 1:
            log.warning("Multiple IP addresses detected for MAC address %s: %s", src_mac, mac_ip_map[src_mac])
            return

def launch():
    core.registerNew(Firewall)
