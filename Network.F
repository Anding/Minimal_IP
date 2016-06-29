\ Mimimal UDP/IP stack 
\ Andrew Read June 2016

\ Implementation overview .........................................................
\ This implementation does not queue frame.  We reserve space for a single incoming
\ frame and a single frame for each top level protocol. Each must be completely
\ processed before the next is created.  The in and out FIFO buffers provide a 
\ buffer of one frame between the harware MAC controller and this software

\ MAC and IP addresses are stored as a sequence of bytes in network (big) endian
\ format for easy copy/comparison with the respective fields in Ethernet/IP frames
\ MAC and IP addresses are always referenced by pointer, never held on the stack

\ The internet checksum routine assumes a cell size of not less that 32 bits

\ Host data .........................................................................
create inFrame 1518 allot					\ An incoming Ethernet frame
create UDPframe 1518 allot					\ An outgoing UDP frame
create ARPframe 1518 allot					\ An outgoing ARP frame

create hostMAC 6 allot						\ Host MAC address
create hostIP 4 allot						\ Host IP address
create subnet 4 allot						\ Host's local network subnet mask
create router 4 allot						\ Host's local network router IP

\ Hardware specific (N.I.G.E. Machine)................................................
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
		
		\ place the incoming frame from the FIFO buffer to local storage				
		inFrame dup 1518 + swap DO						\ maximum 1518 bytes of data may be copied
			MACdataRX @ i c!
			MACreadyRX @ 0= IF unloop exit THEN			\ ... but exit as soon as the FIFO is empty
		LOOP
		
		\ confirm checksum validity
		MACchecksum_err @ not
	UNTIL
;

\ Host configuration  ................................................................

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

\ Ethernet layer......................................................................

create Ethernet.broadcast 255 c, 255 c, 255 c, 255 c, 255 c, 255 c,
\ the broadcast Ethernet address

: MAC= ( MAC1 MAC2 -- flag)
\ compare two MAC addresses referenced by pointers
	6 mem=
;

: EthernetIn ( -- EthernetType)
\ return the Ethernet type of inFrame or 0 if the frame either does not meet assumptions
\ or if the destination does not match the host MAC / broadcast
	inframe
	dup hostMAC MAC= 							\ destination MAC = host MAC
	over Ethernet.broadcast MAC=  or			\ destination MAC = broadcast
	IF 12 + w@n								\ read Ethernet type
	ELSE drop 0	THEN
;

\ IP layer ..............................................................................

: IP=  ( IP1 IP2 -- flag)
\ compare two IP addresses referenced by pointers
	4 mem=
;

: IPin ( -- protocol)
\ IP protocol handles an incoming datagram
\ return the protocol of the IP frame or 0 either if the datagram does not meet assumptions
\ or if the destination IP does not match the host IP
	inFrame 
	\ include checksum check
	\ include no fragments check
	dup 14 + c@ 69 = 						\ version & IHL check
	IF										\ IPv4 and no optional headers	
		dup 30 + hostIP IP= 				\ destination IP check		
		IF									
			23 + c@	EXIT					\ retreive IP protocol			
		THEN
	THEN
	drop 0
;

: IPout_UDP ( IP --)
\ dispatch a UDP datagram to an IP address referenced at IP
\ The UDP segment of datagram will already have been completed by the caller of this routine
\ complete the IP frame fields
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
;

\ ARP layer ................................................................................

create ARP.ExpectedHeader 00 c, 01 c, 08 c, 00 c, 06 c, 04 c, 
\ Expected format of an Ethernet/IP ARP header

\ ARP chache is a simple array with space for 8 entries
create ARP.cacheMAC	6 8 * allot
create APR.cacheIP 4 8 * allot
create ARP.cacheExpiry 1 cells 8 * allot

: ARP.MACtoIP ( MAC -- IP) 
\ accept a MAC address (as a pointer) and return the IP address (as a pointer), or 0 if unavailable
\ If unavailable an ARP request will automatically be made
;

: ARP.updateCache ( --)
\ assumes that inFrame is an ARP reply or APR request and updates the ARP cache for the sender's MAC and IP
;

: ARPin
\ ARP protocol handles an incoming frame
	." ARP"
	inFrame
	dup 14 + ARP.ExpectedHeader 6 mem= 			\ confirm the expected ARP header
	IF
		dup 20 + w@n							\ retrieve ARP opcode
		CASE
			1 OF 								\ is ARP request
				dup 38 + hostIP IP=				\ target IP = host IP
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

: UDPin
\ UDP protocol handles an incoming datagram
." UDP"
;

: UDPterm ( --)
\ UDPterm is a super-loop running in a separate process that handles incoming frames

\	BEGIN
		EthernetIn				( -- EthernetType)
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

