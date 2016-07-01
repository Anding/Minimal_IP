\ Hardware testing on N.I.G.E
\ 1. incoming ARP frame handling
\ 2. UDP datagram receipt

hex
00 08 dc 1d bb bb setMAC
decimal
255 255 255 0 setSubnet
192 168 1 102 setIP			\ 0xC0A80163
192 168 1 1 setRouter		\ 0xC0A8010
192 168 1 18 setUDPdestIP
5000 UDPdestPort w!
5000 UDPsrcPort w!
arp.initcache

: debugEthernet
	>remote
	EthernetReceiveTask
;

0 ' debugEthernet RUN
drop drop


