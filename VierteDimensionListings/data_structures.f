decimal

create inFrame 1518 allot					\ An incoming Ethernet frame.  14 + 1500 + 4 bytes maximum
create UDPframe 1518 allot					\ An outgoing UDP frame
create ARPframe 1518 allot					\ An outgoing ARP frame

create hostMAC 6 allot						\ Host MAC address
create hostIP 4 allot						\ Host IP address
create subnet 4 allot						\ Host's local network subnet mask
create router 4 allot						\ Host's local network router IP

create MACbroadcast 255 c, 255 c, 255 c, 255 c, 255 c, 255 c,
create MACempty 00 c, 00 c, 00 c, 00 c, 00 c, 00 c,

\ ARP chache is a simple array with space for 8 entries for
\ IP address (4 bytes), MAC address (6 bytes), timestamp (4 bytes)
create ARPcache 112 allot					\ 112 = 14 * 8