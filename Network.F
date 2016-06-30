\ Mimimal UDP/IP stack 
\ Andrew Read June 2016

\ ..............................................................................................................
\ Implementation overview ......................................................................................
\ This implementation does not queue frame.  We reserve space for a single incoming
\ frame and a single frame for each top level protocol. Each must be completely
\ processed before the next is created.  The in and out FIFO buffers provide a 
\ buffer of one frame between the harware MAC controller and this software

\ MAC and IP addresses are stored as a sequence of bytes in network (big) endian
\ format for easy copy/comparison with the respective fields in Ethernet/IP frames
\ MAC and IP addresses are always referenced by pointer, never held on the stack

\ The internet checksum routine assumes a cell size of not less that 32 bits

\ ..............................................................................................................
\ Host data ....................................................................................................
create inFrame 1518 allot					\ An incoming Ethernet frame.  14 + 1500 + 4 bytes maximum
create UDPframe 1518 allot					\ An outgoing UDP frame
create ARPframe 1518 allot					\ An outgoing ARP frame

create hostMAC 6 allot						\ Host MAC address
create hostIP 4 allot						\ Host IP address
create subnet 4 allot						\ Host's local network subnet mask
create router 4 allot						\ Host's local network router IP

\ ARP chache is a simple array with space for 8 entries for
\ IP address (4 bytes), MAC address (6 bytes), timestamp (4 bytes)
create ARPcache 112 allot					\ 112 = 14 * 8

\ ..............................................................................................................
\ Hardware specific (N.I.G.E. Machine)..........................................................................
hex
03f860 constant MACreadyRX
03f864 constant MACdataRX
03f868 constant MACchecksum_err
03f86c constant MACreadyTX
03f870 constant MACdataTX
03f874 constant MACtransmit_req
decimal

: getFrame ( -- ) 
\ wait for an incoming Ethernet frame and place it into inFrame
	BEGIN
		\ wait for an incoming frame
		BEGIN								
			MACreadyRX @
			pause
		UNTIL		
		\ copy the incoming frame from the FIFO buffer to local storage				
		inFrame dup 1518 + swap DO						\ maximum 1518 bytes of data may be copied
			MACdataRX @ i c!
			MACreadyRX @ 0= IF LEAVE THEN				\ ... but exit as soon as the FIFO is empty
		LOOP
		MACchecksum_err @ not							\ confirm checksum validity
	UNTIL
;

: putFrame ( frame len --)
\ wait until MAC controller is free and then send the Ethernet frame of length len
\ the Ethernet CRC checksum will be computed in hardware by the MAC controller 
	
	\ wait for any existing transmission to complete
	BEGIN
		MACreadyTX @
		pause
	UNTIL
	\ transfer the frame to the FIFO buffer
	over + swap DO
		i C@ MACdataTX C!
	LOOP
	\ signal the MAC controller to transmit
	0 MACtransmit_req !
;	

\ ..............................................................................................................
\ Host configuration  ..........................................................................................

: setMAC ( x0 x1 x2 x3 x4 x5 --)
\ set the host MAC address
	hostMAC dup 5 + DO i c! -1 +LOOP
;

: setIP ( x0 x1 x2 x3 --)
\ set the host IP address
	hostIP dup 3 + DO i c! -1 +LOOP
;

: setSubnet ( x0 x1 x2 x3 --)
\ set the host's local network subnet mask
	subnet dup 3 + DO i c! -1 +LOOP
;

: setRouter ( x0 x1 x2 x3 --)
\ set the host's local network default router
	router dup 3 + DO i c! -1 +LOOP
;	

\ ..............................................................................................................
\ Helper words .................................................................................................

create MACbroadcast 255 c, 255 c, 255 c, 255 c, 255 c, 255 c,
create MACempty 00 c, 00 c, 00 c, 00 c, 00 c, 00 c,
create ARPheader 00 c, 01 c, 08 c, 00 c, 06 c, 04 c, 

: w@n ( addr -- x)
\ read a 16 bit word in network endian format

\ this word can be used on both big and little endian machines.  It deals with
\ (1) byte reversal for little endian machines and (2) misaligned access
\ N.I.G.E. is a big endian machine that supports misaligned access in SRAM
\ Simply use w@ on the N.I.G.E.

	0 swap				( 0 addr)			
	dup 2 + swap DO		
		256 * i c@ or
	LOOP
;

: w!n ( x addr --)
\ write a 16 bit word in network endian format

\ this word can be used on both big and little endian machines.  It deals with
\ (1) byte reversal for little endian machines and (2) misaligned access
\ N.I.G.E. is a big endian machine that supports misaligned access in SRAM
\ Simply use w! on the N.I.G.E.

	dup 1 + DO
		dup 255 and i c!
		8 rshift
	-1 +LOOP
	drop
;

: @n ( addr -- x)
\ read a 32 bit longword in network endian format
	0 swap				( 0 addr)			
	dup 4 + swap DO		
		256 * i c@ or
	LOOP
;

: !n ( addr x --)
\ write a 32 bit longword in network endian format
	dup 3 + DO
		dup 255 and i c!
	-1 +LOOP
	drop
;	

: mem= ( addr1 addr2 n -- flag)
\ compare n bytes of data at two memory locations
	over + swap DO
		dup c@ i c@ = not IF drop unloop 0 exit THEN
		1+
	LOOP
	drop -1
;

: MAC= ( MAC1 MAC2 -- flag)
\ compare two MAC addresses referenced by pointers
	6 mem=
;

: IP=  ( IP1 IP2 -- flag)
\ compare two IP addresses referenced by pointers
	4 mem=
;

: checksum ( addr n -- x)
\ return the internet checksum for n bytes starting at addr
\ routine adapted from https://tools.ietf.org/html/rfc1071
	>R 0 swap			( 0 addr R:n)
	
	\ sum over 16 bit words in a 32 bit cell
	BEGIN
		R@ 1 >
	WHILE
		dup w@ 			( sum addr u)
		rot + swap		( sum' addr)
		2 +				( sum' addr')
		R> 2 - >R		\ decrement n
	REPEAT
	
	\ deal with any left over byte
	R> IF C@ + ELSE drop THEN
	
	\ fold 32-bit sum into 16 bits
	BEGIN				( sum)
		dup 
		16 Rshift dup	( sum sum>>16 sum>>16)
	WHILE
		swap 65535 and	( sum>>16 sumAND0xffff)
		+
	REPEAT
		drop			( sum)
	
	\ invert 16 bit checksum
	NOT 65535 and
;

\ ..............................................................................................................
\ ARP protocol  ................................................................................................

: Ethernet.dispatchARP ( MAC --)
\ Dispatch the ARP protocol frame to Ethernet address MAC
	ARPframe
	dup -rot 6 move								\ copy in the Ethernet destination MAC address	
	hostMAC over 6 + 6 move						\ copy in the Ethernet source MAC address
	dup 12 + 2054 swap !n						\ set EthernetType = 0x0806
	42											\ APR length of 28 plus 14 for Ethernet
	( frame len) \ putframe
;

: ARP.initCache ( --)
\ initialize the ARP cache
	ARPcache 112 blank				\ zero the cache memory
	timer							( timestamp)	
	ARPcache dup 112 + swap DO		\ timestamp all cache slots with the current time
		dup i 10 + !
	14 +LOOP drop
;

: ARP.lookupIP ( IP -- addr flags) 
\ lookup IP in cache.  Returns flags and addr as follows
\  0  : IP not found. Address addr can be used to hold this IP entry
\  1  : partial IP (no MAC) entry available at address addr
\ -1  : complete IP/MAC entry available at address addr

	\ search the ARPchache for this IP address
	0
	ARPcache dup 112 + swap DO
		dup i IP=
		IF drop i LEAVE THEN		\ IP address found, replace 0 with the pointer to the entry
	14 +LOOP
	
	( 0 | addr) dup IF				\ if IP was found, now check the MAC field		
		dup 4 + MACempty MAC= IF			
			1 exit					\ MAC address is zero - this is a partial entry		
		ELSE
			\ check the timestamp
			-1 exit					\ MAC address is not zero - this is a complete entry
		THEN
	ELSE							\ if IP not found, find the Least Recently Used (LRU) cache entry
		ARPcache swap 				\ for now, just return the first slot	
	THEN
;	

: ARP.updateCache ( --)
\ Updates the ARP cache by reference to an ARP reply or request received from the network
\ assumes that inFrame is the incoming ARP frame
	inFrame 22 + ARP.lookupIP  					( addr flags)  \ lookup sender's IP
	0= IF inFrame 22 + over 4 move THEN			\ copy sender's IP address if this is a new entry
	inFrame 28 + over 4 + 6 move				\ copy sender's MAC address
	10 + timer swap !							\ timestamp the chache entry
;

: ARP.request ( IP --)
\ create and send an ARP request WhoIs? IP
	ARPframe
	ARPheader over 14 + 6 move					\ copy in the ARP header
	dup 20 + 1 swap w!n							\ opcode 1 is an ARP request
	hostMAC over 22 + 6 move					\ copy in sender's (i.e. host) MAC
	hostIP over 28 + 4 move						\ copy in sender's IP
	dup 32 + 6 blank							\ zeros for target MAC
	38 + 4 move									\ copy in target IP
	MACbroadcast								\ destination MAC will be broadcast
	( broadcastMAC) Ethernet.dispatchARP
;

: ARP.gratuitous
\ make a gratuitous ARP request for the host's own IP
	hostIP ARP.request
;

: ARP.reply ( --)
\ create an ARP reply in reponse to a ARP request and dispatch via the Ethernet layer
	ARPframe
	ARPheader over 14 + 6 move					\ copy in the ARP header
	dup 20 + 2 swap w!n							\ opcode 2 is an ARP reply
	hostMAC over 22 + 6 move					\ copy in sender's (i.e. host) MAC
	hostIP over 28 + 4 move						\ copy in sender's IP
	InFrame 22 + over 32 + 10 move				\ copy the sender fields from the ARP request 
												\ 	to the target fields of the ARP reply
	32 + 										\ destination MAC will be the target MAC
	( targetMAC) Ethernet.dispatchARP
;

: ARP.getMAC ( IP -- MAC true | false) 
\ obtain the MAC address of an IP address, making ARP requests if necessary
\ return MAC true if successful or false if a MAC address cannot be obtained
	4 0 DO										\ allow initial cache lookup plus three ARP request attempts
		dup ARP.lookupARP						\ loopup the IP address in the ARP cache
		-1 = IF 								\ a complete entry is available
			4 + -1 EXIT							\ reference the MAC address and exit true
		THEN
		dup ARP.request							\ initiate an ARP request for this IP address
		i IF 10000 ELSE 1000 THEN ms			\ allow time for the ARP layer (1 sec initially, then 10 secs)
	LOOP
	drop 0										\ failed to obtain a MAC address
;

: ARP.in ( --)
\ ARP protocol handles an incoming frame from the network
	inFrame
	dup 14 + ARP.ExpectedHeader 6 mem= 			\ confirm the expected ARP header
	IF
		dup 20 + w@n							\ retrieve ARP opcode
		CASE
			1 OF 								\ it is an ARP request
				dup 38 + hostIP IP=	IF			\ does target IP = host IP ?
					ARP.updateCache
					ARP.sendReply
				ENDIF
			ENDOF
			2 OF								\ it is an ARP reply
				dup 28 + hostIP IP= IF			\ does sender IP = host IP ?
					." IP conflict"
				ELSE
					ARP.updateCache
				THEN
			ENDOF
		ENDCASE
	THEN
	drop
;

\ ..............................................................................................................
\ Frames received from the protocol stack are passed to the network.............................................

: Ethernet.dispatchIP ( frame MAC --)
\ Dispatch an IP datagram to Ethernet address MAC
	swap
	hostMAC over 6 + 6 move						\ set the source MAC address
	dup 12 + 2048 swap !n						\ set the EthernetType = 0x0800
	dup -rot 6 move								\ set the destination MAC address
	dup 16 + w@n 14 +							\ retrieve IP length and add 14 for Ethernet
	( frame len) \ putfame
;

: IP.forward ( frame --)
\ Forward an IP frame via direct delivery or indirect delivery
	subnet !n								( frame subnet)
	over 30 + !n							( frame subnet destIP)
	over and >R								( frame subnet R:destNET)
	hostIP !n and R>						( frame hostNET destNET)
	= IF									\ are destination and host on same subnet?
		dup 30 + ARP.getMAC					\ direct delivery to the MAC of destination IP
	ELSE
		router ARP.getMAC					\ indirect delivery to router
	THEN
	( frame MAC true | false) IF Ethernet.dispatchIP ELSE drop THEN
;

: IP.dispatchUDP ( IP --)
\ Prepare an IP frame starting from the UDP frame and then dispatch via IP forwarding
\ The UDP segment of datagram will already have been completed by the caller
	UDPframe
	dup 14 + 69 swap c!						\ version and IHT
	dup 15 + 0 swap c!						\ DS and ECN
	dup 38 + w@n 20 +						\ retreive UDP.length and add 20 for IP header
	over 16 + w!n							\ length
	dup 18 + 0 swap w!						\ identification
	dup 20 + 0 swap w!						\ flags and fragment offset
	dup 22 + 64 swap c!						\ time to live
	dup 23 + 17 swap c!						\ protocol = 17 for UDP
	dup 24 + 0 swap w!						\ initial value of checksum
	hostIP over 26 + 4 move					\ copy in source IP address
	swap over 30 + 4 move					\ copy in destination IP address
	dup 14 + 20 checksum swap 24 + w!		\ compute and save header checksum
	( UDPframe) IP.forward
;

\ ..............................................................................................................
\ Frames received from the network are passed up the protocol stack.............................................

: UDPin
\ Receive a UDP frame from the IP layer
	." UDP"
;

: IP.check ( -- protocol)
\ Check an IP frame.  If the datagram does not meet assumptions or the destination IP does not match the 
\ host IP, return 0.  If the datagram is good, return the protocol
	inFrame 
	\ include checksum check
	\ include no fragments check
	dup 14 + c@ 69 = 						\ confirm version = IPv4 and no optional headers
	IF										 	
		dup 30 + hostIP IP= 				\ confirm destination IP = host IP		
		IF									
			23 + c@	EXIT					\ retreive IP protocol			
		THEN
	THEN
	drop 0
;
	
: IP.in  ( --)
\ Receive an IP frame from the Ethernet layer
\ Check the frame and pass it up the protocol stack
	IP.check
	CASE
		17 OF		\ 0x11 is a UDP datagram
			UDP.in
		ENDOF
	ENDCASE
	\ all other datagrams silently dropped
;

: Ethernet.check ( -- EthernetType)
\ Check an Ethernet frame. If the frame either does not meet assumptions or if the destination does not match the 
\ host MAC / broadcast, return 0. Is the frame is good, return the EthernetType
	inframe
	dup hostMAC MAC= 							\ destination MAC = host MAC
	over Ethernet.broadcast MAC=  or			\ destination MAC = broadcast
	IF 12 + w@n									\ read Ethernet type
	ELSE drop 0	THEN
;

: Ethernet.in ( --)
\ Receive an IP frame form the MAC controller and pass it up the protocol stack
	Ethernet.check ( -- EthernetType)
	CASE
		2054 OF				\ 0x0806 is an ARP frame
			ARP.in			( --)
		ENDOF
		2048 OF				\ 0x0800 is an IP frame
			IP.in			( -- protocol type)
		ENDOF
	ENDCASE					\ all other frames / datagrams are silently discarded
;

: EthernetReceiveTask ( --)
\ super-loop running as a separate task that handles incoming frames
	BEGIN
		getFrame
		Ethernet.in
	AGAIN
;

\ UDP FORTH terminal ............................................................................

\ This minimal inplementation does not offer a generic API.  Instead there is a UDP Forth terminal
\ Notes:
\ The UDP destination port of incoming frames is ignored - all frames are forwarded to the buffer

create UDPdestIP 4 allot			\ IP address of outgoing UDP frames
variable UDPdestPort				\ Destination port of outgoing UDP frames

: setUDPdestIP ( x0 x1 x2 x3 --)
\ set the host IP address
	hostIP dup 3 + DO i c! -1 +LOOP
;

: UEMIT ( c --)
\ Place the character c in the outgoing UDP buffer.  Comments as for UTYPE
;

: UTYPE ( addr n --)
\ Copy the string at addr of length n to the outgoing UDP buffer
\ If the LF character is encountered then the UDP datagram, including the LF is transmitted
\ The UDP datagram is also transmitted if the number of characters in the buffer exceeds the limit
;

: UKEY? ( -- flag)
\ Return true if there is a character waiting in the incoming UDP buffer or false otherwise
;

: UKEY ( -- c)
\ Return the next character from the incoming UDP buffer or block until one is available
;

\ Testing .................................................................................

: parseFrame ( frame <FRAMESTRING> --)
\ Parse a hex string (e.g. copied from wireshark) and place it into frame
\ Requires that BASE already be hexadecimal
\ VFX Forth version - NUMBER? takes a counted string
\ Example usage:
\ 	HEX 
\ 	inFrame parseFRAME ffffffffffff6cf049eef42a080600010800060400016cf049eef42ac0a80112000000000000c0a80101
\ 	decimal

	BL word 				( frame caddr)
	dup c@ 1 rshift			( frame caddr bytes)
	rot dup rot + swap DO	
		2 over c!			( caddr)			\ make a counted string of length 2
		dup NUMBER?			
		IF	i c! ELSE CR ." parse failed" abort THEN
		2+
	LOOP
	drop
;

: .MAC ( MAC --)
\ print the MAC address at MAC
	dup 6 + swap DO
		i c@ .
	LOOP
;

: .IP ( IP --)
\ print the IP address at IP
	dup 4 + swap DO
		i c@ .
	LOOP
;

: .EthernetFields ( frame --)
\ print the Ethernet fields in frame
	CR ." Ethernet " CR
	CR ." Destination MAC " dup .MAC
	CR ." Source MAC " dup 6 + .MAC
	CR ." Ethernet type " dup 12 + w@n .
	drop
;

: .IPfields ( frame --)
\ print all of the IP fields in frame
	dup .EthernetFrame
	CR ." IP "
	CR ." Version & IHL " dup 14 + c@ .
	CR ." DS & ECN " dup 15 + c@ .
	CR ." Length " dup 16 + w@n .
	CR ." Identification " dup 18 + w@n .
	CR ." Flags & frament offset " dup 20 + w@n .
	CR ." Time to live " dup 22 + c@ .
	CR ." Protocol " dup 23 + c@ .
	CR ." Checksum " dup 24 + w@n .
	CR ." Source IP address " dup 26 + .IP
	CR ." Destination IP address " dup 30 + .IP	
	drop
;

: .UDPfields ( frame --)
\ Print all of the fields in frame
	dup .IPframe
	CR ." UDP "
	CR ." Source port " dup 34 + w@n .
	CR ." Destination port " dup 36 + w@n .
	CR ." Length " dup 38 + w@n .
	CR ." Checksum " dup 40 + w@n .
	drop
;

