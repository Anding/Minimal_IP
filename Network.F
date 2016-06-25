\ N.I.G.E. Machine hardware registers
hex
03f860 constant MACreadyRX
03f864 constant MACdataRX
03f868 constant MACchecksum_err
03f86c constant MACreadyTX
03f870 constant MACdataTX
03f874 constant MACtransmit_req
03f878 constant SMIaddr
03f87C constant SMIdataWrite
03f880 constant SMIread_request
03f884 constant SMIready
03f888 constant SMIdataRead
decimal

\ Host data .........................................................................

\ This implementation does not queue frame.  We reserve space for a single incoming
\ frame and a single frame for each top level protocol. Each must be completely
\ processed before the next is created.  The in and out FIFO buffers provide a 
\ buffer of one frame between the harware MAC controller and this software
create inFrame 1518 allot					\ An incoming Ethernet frame
create UDPframe 1518 allot					\ An outgoing UDP frame
create ARPframe 1518 allot					\ an outgoing ARP frame

\ MAC and IP addresses are stored as a sequence of bytes in network (big) endian
\ format for easy copy/comparison with the respective fields in Ethernet/IP frames	
create hostMAC 6 allot						\ Host MAC address
create hostIP 4 allot						\ Host IP address
create subnet 4 allot						\ Host's local network subnet mask
create router 4 allot						\ Host's local network router IP

\ configuration  .....................................................................

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

\ Helper words ....................................................................

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

: @n ( addr - x)
\ read a 32 bit longword in network endian format
	0 swap				( 0 addr)			
	dup 4 + swap DO		
		256 * i c@ or
	LOOP
;

: mem= (addr1 addr2 n -- flag)
\ compare n bytes of data at two memory locations
	over + swap DO
		dup c@ i c@ != IF drop unloop 0 exit THEN
		1+
	LOOP
	drop -1
;

\ Link layer........................................................................

create Ethernet.broadcast 255 c, 255 c, 255 c, 255 c, 255 c, 255 c,
\ the broadcast Ethernet address

\ Protocol access to an Ethernet frame
: Ethernet.destination ( Ethernet_frame_addr -- field_addr) 0 + ;
: Ethernet.source 6 + ;
: Ethernet.type 12 + ;

: MAC= ( MAC1 MAC2 -- flag)
\ compare two MAC addresses referenced by pointers
	6 mem=
;
: EthernetIn ( -- EthernetType) 
\ wait for an incoming Ethernet frame and place it into the buffer
\ return the Ethernet type or 0 if the frame either does not meet assumptions
\ or if the destination does not match the host MAC / broadcast

	\ wait for an incoming frame
	BEGIN								
		MACreadyRX @
		pause
	UNTIL		
	
	\ place the incoming frame from the FIFO buffer to local storage				
	inFrame 1518 + inFrame DO						\ 1518 bytes of data may be copied
		MACdataRX @ i c!
		MACreadyRX @ 0= IF unloop exit THEN			\ ... but exit as soon as the FIFO is empty
	LOOP
	
	\ test the frame
	MACchecksum_err @ 0= IF	EthernetInTest ELSE 0 THEN
;

: EthernetInTest ( -- EthernetType)
\ return the Ethernet type of inFrame or 0 if the frame either does not meet assumptions
\ or if the destination does not match the host MAC / broadcast
	inframe
	dup Ethernet.destination hostMAC MAC=					\ host's MAC
	dup Ethernet.destination Ethernet.broadcast MAC= or		\ broadcase MAC
	IF
		Ethernet.type w@n
	ELSE
		drop 0
	THEN
;

\ IP layer ..............................................................................

\ Protocol access to an IP datagram within an Ethernet frame
: IP.version&IHL ( Ethernet_frame_addr -- field_addr) 14 + ;
: IP.totalLength 16 + ;
: IP.TTL 22 + ;
: IP.protocol 23 + ;
: IP.checksum 24 + ;
: IP.source 26 + ;
: IP.destination 30 + ;

: IP=  ( IP1 IP2 -- flag)
\ compare two IP addresses referenced by pointers
	4 mem=
;

: IPin ( -- protocol)
\ IP protocol handles an incoming datagram
\ return the protocol of the IP frame or 0 either if the datagram does not meet assumptions
\ or if the destination IP does not match the host IP
	inFrame 								
	dup IP.version&IHL c@ 69 = 							\ IPv4 and no optional headers	
	IF										
		dup IP.destination hostIP IP= 		
		IF									
			IP.protocol c@	EXIT			
		THEN
	THEN
	drop 0
;

\ ARP layer ................................................................................

create ARP.ExpectedHeader 00 c, 01 c, 08 c, 00 c, 06 c, 04 c, 
\ Expected format of an Ethernet/IP ARP header

\ Protocol access to an ARP frame within an Ethernet frame assuming no optional IP headers
: ARP.header 14 + ;
: ARP.opcode 20 + ;
: ARP.sendersMAC 22 + ;
: ARP.sendersIP 28 + ;
: ARP.targetMAC 32 + ;
: ARP.targetIP 36 + ;

: ARPin
\ ARP protocol handles an incoming frame
	inFrame
	dup ARP.header ARP.ExpectedHeader 6 mem= 		\ confirm the expected ARP type
	IF
		dup ARP.opcode w@n
		CASE
			1 OF 									\ is ARP request
				dup ARP.targetIP hostIP IP=
				IF
					dup ARP.updateCache
					\ dispatch reply
				ENDIF
			ENDOF
			2 OF									\ is ARP reply
				dup ARP.updateCache
			ENDOF
		ENDCASE
	THEN
	drop
;

\ UDP layer ..................................................................................

\ Protocol access to a UDP frame within an Ethernet frame assuming no optional IP headers
: UDP.source 34 + ;
: UDP.destination 36 + ;
: UDP.length 38 + ;
: UDP.checksum 40 + ;
: UDP.data 42 + ;

: UDPin
\ UDP protocol handles an incoming datagram
	inFrame 
	dup UDP.source w@n .
	dup UDP.destination w@n .
	dup UDP.length w@n .
	dup UDP.checksum w@n .
	drop
;

\ Access routines ............................................................................

: inLoop ( --)
\ inLoop is a super-loop running in a separate process.  It handles incoming frames by passing 
\ them to each protocol layer in turn.  There is no client/server model for each protocol layer 
\ in this implementation

\	BEGIN
		EthernetInTest			( -- EthernetType)
		CASE
			2054 OF				\ 0x0806 is an ARP frame
				ARPin			( --)
			ENDOF
			2048 OF				\ 0x0800 is an IP frame
				IPin			( -- protocol type)
				CASE
					17 OF		\ 0x11 is a UDP datagram
						UDPin
					ENDOF
				ENDCASE
			ENDOF
		ENDCASE					\ all other frames / datagrams are silently discarded
\	AGAIN
;

\ Testing .................................................................................

: parseFrame ( <FRAMESTRING> --)
\ Parse a hex string (e.g. copied from wireshark) and place it into inFrame
\ Requires that BASE already be hexadecimal

\ VFX Forth version - NUMBER? takes a counted string
	BL word 				( caddr)
	dup c@ 1 rshift			( caddr bytes)
	inFrame + inFrame DO
		2 over c!			( caddr)			\ make a counted string of length 2
		dup NUMBER?			
		IF	i c! ELSE ." parse failed" abort THEN
		2+
	LOOP
	drop
;

\ Example usage:
\ HEX 
\ parseFRAME ffffffffffff6cf049eef42a080600010800060400016cf049eef42ac0a80112000000000000c0a80101
\ decimal