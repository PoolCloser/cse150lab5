from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

LAPTOP1 = '10.1.2.2'
LAPTOP2 = '10.1.2.156'
DOORBELL = '10.1.6.15'
HEATER = '10.1.6.5'

LAPTOPS = {LAPTOP1, LAPTOP2}
IOT_DEVICES = {DOORBELL, HEATER}


class Firewall(object):
    """One firewall handler is created for each connected switch."""

    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

    def do_firewall(self, packet, packet_in):
        def install_rule(allow):
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match.from_packet(packet, packet_in.in_port)
            msg.idle_timeout = 60
            msg.hard_timeout = 180
            if allow:
                msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
                msg.data = packet_in
            self.connection.send(msg)

        def accept():
            install_rule(True)
            log.info('Packet Accepted - Flow Table Installed on Switch')

        def drop():
            install_rule(False)
            log.info('Packet Dropped - Flow Table Installed on Switch')

        # Rule 1: Allow ARP everywhere.
        if packet.find('arp') is not None:
            accept()
            return

        ip_header = packet.find('ipv4')
        if ip_header is None:
            drop()
            return

        src = str(ip_header.srcip)
        dst = str(ip_header.dstip)

        # Rule 1: Allow ICMP everywhere.
        if ip_header.protocol == 1:
            accept()
            return

        # Rule 2: Allow TCP between the laptops (both directions).
        # Rule 3: Allow TCP between laptop2 and each IoT device (both directions).
        if ip_header.protocol == 6:
            if (src in LAPTOPS and dst in LAPTOPS and src != dst):
                accept()
                return
            if ((src == LAPTOP2 and dst in IOT_DEVICES) or
                    (dst == LAPTOP2 and src in IOT_DEVICES)):
                accept()
                return

        # Rule 3: Allow UDP between the IoT devices (both directions).
        # Rule 4: Allow UDP between the laptops (both directions).
        if ip_header.protocol == 17:
            if src in IOT_DEVICES and dst in IOT_DEVICES and src != dst:
                accept()
                return
            if src in LAPTOPS and dst in LAPTOPS and src != dst:
                accept()
                return

        # Rule 5: Deny everything not explicitly allowed above.
        drop()

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning('Ignoring incomplete packet')
            return
        self.do_firewall(packet, event.ofp)


def launch():
    def start_switch(event):
        log.debug('Controlling %s', event.connection)
        Firewall(event.connection)

    core.openflow.addListenerByName('ConnectionUp', start_switch)
