\ Simulation test in VXF environment to check an example of
\ 1. ARP frame handling
\ 2. UDP datagram creation 
\ 3. ARP cache operation
\ 4. IP forwarding

decimal
10 11 12 13 14 15 setMAC
192 168 1 99 setIP			\ 0xC0A80163
255 255 255 0 setSubnet
192 168 1 1 setRouter		\ 0xC0A80101

hex
arp.initcache 10 ms			\ need to allow ms counter to update - include with VFX forth is too fast!
inframe parseframe ffffffffffff6cf049eef42a080600010800060400016cf049eef42aC0A80101000000000000C0A80163
arp.updatecache 10 ms
inframe parseframe ffffffffffff7df049eef43b080600010800060400017df049eef43bC0A8010a000000000000C0A80163
arp.updatecache .arpcache 10 ms

c0 a8 01 0a setUDPdestIP
07 UDPdestPort w!
05 UDPsrcPort w!
s" my text" udp.send
udpframe .udpfields
