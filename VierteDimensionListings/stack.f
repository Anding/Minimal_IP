: UDP.check ( -- destPort)
\ Check an UDP frame. If the checksum is invalid, return 0
\ otherwise return the destination port
	inframe 
	dup UDP.checksum 0= IF
		36 + w@n
	ELSE drop 0 THEN
;

: UDP.in ( --)
\ Receive a UDP frame from the IP layer
	UDP.check	( -- destport | 0)		\ validate checksum
\ further code here to handle the datagram
;

: IP.check ( -- protocol)
\ Check an IP frame.  If the datagram does not meet assumptions return 0.  
\ If the datagram is good, return the protocol
	inFrame 
	dup 14 + 20 checksum 0= IF				\ confirm checksum = 0
		dup 14 + c@ 69 = IF						\ confirm version = IPv4 and no optional headers		
			dup 20 + w@n 8191 and 0= IF				\ confirm this is not a fragment				 	
				dup 30 + hostIP IP= IF					\ confirm destination IP = host IP									
					23 + c@	EXIT							\ retreive IP protocol			
				THEN
			THEN
		THEN
	THEN
	drop 0
;

: IP.in  ( --)
\ Receive an IP frame from the Ethernet layer
\ Check the frame and pass it up the protocol stack
	IP.check	
	CASE
		17 OF UDP.in ENDOF					\ 0x11 is a UDP datagram
		\ expand to handle other protocols
	ENDCASE
	\ all other datagrams silently dropped
;

: Ethernet.check ( -- EthernetType)
\ Check an Ethernet frame. If the destination does not match the 
\ host MAC / broadcast, return 0. Otherwise return the EthernetType
	inframe
	dup hostMAC MAC= 							\ destination MAC = host MAC
	over MACbroadcast MAC=  or IF				\ destination MAC = broadcast
		12 + w@n								\ read Ethernet type
	ELSE drop 0	THEN
;

: Ethernet.in ( --)
\ Receive an IP frame form the MAC controller and pass it up the protocol stack
	Ethernet.check ( -- EthernetType)
	CASE
		2054 OF				\ 0x0806 is an ARP frame
			ARPsemaphore ACQUIRE
				ARP.in			( --)
			ARPsemaphore RELEASE
		ENDOF
		2048 OF				\ 0x0800 is an IP frame
			IP.in			( -- protocol type)
		ENDOF
	ENDCASE					\ all other frames / datagrams are silently discarded
;

