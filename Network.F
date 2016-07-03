\ Mimimal UDP/IP stack 
\ Andrew Read June 2016

\ ..............................................................................................................
\ Description ..................................................................................................
\ This is a "minimal" implementaton of a UDP/IP stack. UDP, IP and ARP are implemented except as noted below
\ The code is designed for the N.I.G.E. Machine but should be suitable for other systems that have
\ (a) multitasking (we require two tasks)
\ (b) ANSI Forth
\ (c) an Ethernet MAC controller (accessed via the functions below)
\
\ ticks ( -- ms, provide the system timer counter values in milliseconds)
\ getFrame ( frame -- , wait for an incoming Ethernet frame and copy it to frame)
\ putFrame ( frame len -- , send the Ethernet frame of length len to the MAC controller)
\ 	we assume that the Ethernet CRC checksum will be computed in hardware by the MAC controller 

\ The Forth system assesses the UDP/IP stack with the words UDP.send and UDP.in (see the code).  Otherwise there
\ are no generic 'sockets' or API. Words are provided for datagram inspection, etc..  See the section 'debugging'
\ Features not implemented (among other): ICMP, DHCP, IP loopback (127.x.x.x), IP fragmentation

\ ..............................................................................................................
\ Implementation notes... ......................................................................................
\ 1.This implementation is multitasking but it is not based on the client server model.  There are two tasks,
\ one to handle incoming frames (all the way up the protocol stack) and one to handle outgoing frames (all the
\ way down the protocol stack).  Each incoming / outgoing frame must be completely processed before the next.
\ 2. We reserve space for a single incoming frame and a single frame for each top level protocol (UDP, ARP)
\ The MAC controller FIFO buffers provide an additional buffer of one frame in each direction
\ 3. MAC and IP addresses are stored as a sequence of bytes in network (big) endian. They are always referenced by 
\ pointer never held on the stack
\ 4. The internet checksum routine assumes a cell size of not less that 32 bits

decimal
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
variable ARPsemaphore 0 ARPsemaphore !

\ ..............................................................................................................
\ Helper words .................................................................................................

create MACbroadcast 255 c, 255 c, 255 c, 255 c, 255 c, 255 c,
create MACempty 00 c, 00 c, 00 c, 00 c, 00 c, 00 c,
create ARPheader 00 c, 01 c, 08 c, 00 c, 06 c, 04 c, 

arpcache 0 over ! 1 over c! w@ 1 AND 1-		( 0 | -1)				\ use ARPcache as a scratch
constant endian	\ endian returns TRUE on a big endian machine and FALSE on a little endian machine

: w@n ( addr -- u)
\ read a 16 bit word in network endian format
\ this word can be used on both big and little endian machines. 
\ alternatively on big endian machines, simply use w@
	dup c@ 256 *		( addr hh00)	\ high byte in network endian
	swap 1+ c@ +		( hhll)			\ low byte
;

: w!n ( u addr --)
\ write a 16 bit word in network endian format
\ this word can be used on both big and little endian machines. 
\ alternatively on big endian machines, simply use w!
	over 8 rshift over c!
	1 + c!
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

: checksum-add ( sum addr n -- sum)
\ Sum over 16 bit words in a 32 bit cell and accumulate to sum.
\ Checksum calculations are performed in the natural endian of the machine for speed.
\ Hence need to check machine endian to deal with any odd byte
	\ sum over complete words
	>R BEGIN				( sum addr R:n)
		R@ 1 >
	WHILE
		dup w@ 				( sum addr u)
		rot + swap			( sum' addr)
		2 +					( sum' addr')
		R> 2 - >R			\ decrement n
	REPEAT R>				( sum addr 0|1)
	\ deal with any left over byte
	IF C@ endian IF 256 * THEN +
	ELSE drop THEN	( sum)
;

: checksum-add&move ( sum src dst n -- sum)
\ as checksum-add but move the data from src to dst at the same time
	\ sum over complete words
	swap >R >R BEGIN		( sum src R:dst n)
		R@ 1 >
	WHILE
		dup w@				( sum src u R:dst n)		\ read the word
		R> 2 - -rot			( sum n' src u R:dst)		\ decrement n
		R> over over w! 	( sum n' src u dst)			\ copy the word to dst
		2 + >R rot >R		( sum src u R:dst' n)		\ increment dst
		rot + swap			( sum' src R:dst' n)		\ accumulate to sum
		2 +					( sum' src' R:dst' n)		\ increment src
	REPEAT R> 				( sum addr 0|1 R:dst)
	\ deal with any left over byte
	IF
		c@ dup R> c!		( sum u)					\ copy the byte to dst
		endian IF 256 * THEN
		+					( sum)						\ accumulate to sum
	ELSE 
		R> drop drop 
	THEN					( sum)
;

: checksum-fold ( sum -- checksum)
\ fold the accumulated carry in a 32 bit-cell back into the 16 bit sum
	BEGIN					( sum)
		dup 
		16 Rshift dup		( sum sum>>16 sum>>16)
	WHILE
		swap 65535 and		( sum>>16 sumAND0xffff)
		+
	REPEAT
		drop				( sum)
	\ invert 16 bit checksum
	NOT 65535 and			( x)
	\ 0x0000 and 0xffff both stand for 0 in ones's complement: exchange the latter for the former
	dup 65535 = IF drop 0 THEN
;

: checksum ( addr n -- x)
\ return the internet checksum for n bytes starting at addr
\ routine adapted from https://tools.ietf.org/html/rfc1071
	0 -rot					( 0 addr n)
	checksum-add
	checksum-fold
;

\ ..............................................................................................................
\ Debugging  ...................................................................................................

: .MAC ( MAC --)
\ print the MAC address at MAC
	6 0 DO
		dup i + c@  2 .r
		i 5 < IF ."  :" THEN
	LOOP
	drop
;

: .IP ( IP --)
\ print the IP address at IP
	4 0 DO
		dup i + c@  3 .r
		i 3 < IF ."  ." THEN
	LOOP
	drop
;

: .EthernetFields ( frame --)
\ print the Ethernet fields in frame
	CR ." Ethernet "
	CR ." Destination MAC " dup .MAC
	CR ." Source MAC      " dup 6 + .MAC
	CR ." Ethernet type " dup 12 + w@n 2 .r
	drop
;

: .IPfields ( frame --)
\ print all of the IP fields in frame
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
\ Print all of the UDP fields in frame
	CR ." UDP "
	CR ." Source port      " dup 34 + w@n .
	CR ." Destination port " dup 36 + w@n .
	CR ." Length " dup 38 + w@n .
	CR ." Checksum " dup 40 + w@n .
	drop
;

: .ARPfields ( frame --)
\ Print all of the ARP fields in a frame
	CR ." ARP"
	CR ." Opcode " dup 20 + w@n .
	CR ." Sender's MAC " dup 22 + .MAC
	CR ." Sender's IP  " dup 28 + .IP
	CR ." Target MAC   " dup 32 + .MAC
	CR ." Target IP    " dup 38 + .IP
	drop
;

: .ARPcache ( --)
\ Print the ARP cache in the format IP, MAC, timestamp
	ARPcache dup 112 + swap DO
		CR i .IP 9 emit i 4 + .MAC 9 emit i 10 + @ u.
	14 +LOOP
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
\ ARP protocol  ................................................................................................
\ Note ARP can be accessed by both the process receiving frames and the process sending frames
\ Therefore always mediate access with ACQUIRE and RELEASE ARPsemaphore

: Ethernet.dispatchARP ( MAC --)
\ Dispatch the ARP protocol frame to Ethernet address MAC
	ARPframe
	dup -rot 6 move								\ copy in the Ethernet destination MAC address	
	hostMAC over 6 + 6 move						\ copy in the Ethernet source MAC address
	dup 12 + 2054 swap w!n						\ set EthernetType = 0x0806
	42											\ APR length of 28 plus 14 for Ethernet
	( frame len) putframe
;

: ARP.initCache ( --)
\ initialize the ARP cache
	ARPcache 112 erase				\ zero the cache memory
	ticks							( timestamp)	
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
		over i IP=
		IF drop i LEAVE THEN		\ IP address found, replace 0 with the pointer to the entry
	14 +LOOP 
	
	\ review the IP chache entry where the IP address was found
	nip ( 0 | addr) dup IF			\ if IP was found		
		dup 4 + MACempty MAC= IF	\ MAC address is zero		
			1 exit						\ this is a partial entry		
		ELSE						\ MAC address is not zero
			dup 10 + @ ticks swap -		\ measure ticks since timestamp
				1200000 > IF			\ more than 20 minutes ?
					1 exit					\ MAC address is out of date - this is a partial entry
				ELSE
					-1 exit					\ this is a complete entry
				THEN
		THEN
	THEN	
	drop					
	
	\ IP not found, find the Least Recently Used (LRU) cache entry
	ARPcache ticks over 10 + @ over swap -	( oldestEntry ticks oldestAge)		\ first entry by default
	ARPcache 14 + dup 98 + swap DO												\ iterate over entries 1 - 7
		i swap >R 10 + @ over swap - 		( oldestEntry ticks age R:oldestAge)
		R> over over > IF					( oldestEntry ticks age oldestAge)	
			drop rot drop i -rot			( oldestEntry' ticks oldestAge')	\ this entry is older
		ELSE
			nip
		THEN
	14 +LOOP								( oldestEntry ticks oldestAge)
	drop drop 0
;	

: ARP.updateCache ( --)
\ Updates the ARP cache by reference to an ARP reply or request received from the network
\ assumes that inFrame is the incoming ARP frame
	inFrame 28 + ARP.lookupIP	( addr flags)   \ lookup sender's IP
	0= IF inFrame 28 + over 4 move THEN			\ copy sender's IP address if this is a new entry
	inFrame 22 + over 4 + 6 move				\ copy sender's MAC address
	10 + ticks swap !							\ timestamp the chache entry
;

: ARP.request ( IP --)
\ create and send an ARP request WhoIs? IP
	ARPframe
	ARPheader over 14 + 6 move					\ copy in the ARP header
	dup 20 + 1 swap w!n							\ opcode 1 is an ARP request
	hostMAC over 22 + 6 move					\ copy in sender's (i.e. host) MAC
	hostIP over 28 + 4 move						\ copy in sender's IP
	dup 32 + 6 erase							\ zeros for target MAC
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
\ obtain the MAC address of an IP address return MAC true if successful, 
\ or if a MAC address cannot be obtained make an asynchronous ARP request and exit false
	dup ARP.lookupIP -1 = IF 				\ Only recognize complete entries (i.e. -1, not 1 or 0)
		nip 4 + -1							\ reference the MAC address and signal true
	ELSE 
		drop ARP.request	0 				\ No MAC address available - do APR request
	THEN																		
;

: ARP.in ( --)
\ ARP protocol handles an incoming frame from the network
	inFrame
	\ ." ARP from" dup 28 + .IP CR				\ debug
	dup 14 + ARPheader 6 mem= 					\ confirm the expected ARP header
	IF
		dup 20 + w@n							\ retrieve ARP opcode
		CASE
			1 OF 								\ it is an ARP request
				38 + hostIP IP=	IF				\ does target IP = host IP ?
					ARP.updateCache
					ARP.reply
				THEN
			ENDOF
			2 OF								\ it is an ARP reply
				28 + hostIP IP= IF				\ does sender IP = host IP ?
					." IP conflict"
				ELSE
					ARP.updateCache
				THEN
			ENDOF
		ENDCASE
	THEN
;

\ ..............................................................................................................
\ Frames received from the protocol stack are passed to the network.............................................

: Ethernet.dispatchIP ( frame MAC --)
\ Dispatch an IP datagram to Ethernet address MAC
	swap
	hostMAC over 6 + 6 move						\ set the source MAC address
	2048 over 12 + w!n					 		\ set the EthernetType = 0x0800
	dup -rot 6 move								\ set the destination MAC address
	dup 16 + w@n 14 +							\ retrieve IP length and add 14 for Ethernet
	( frame len) putframe
;

: IP.enquireARP ( IP -- MAC true | false) 
\ repeatedly try to obtain the MAC address of an IP address by contacting the ARP 
\ return MAC true if successful or false if a MAC address cannot be obtained
	2 0 DO										\ allow initial cache lookup plus two ARP request attempts
		ARPsemaphore ACQUIRE
			dup ARP.getMAC	( IP, MAC true | false) \ request ARP for this IP address
		ARPsemaphore RELEASE					\ important to RELEASE so ARP can handle incoming ARP replies
		IF nip -1 UNLOOP EXIT THEN				\ MAC found, exit TRUE
		i IF 1500 ELSE 500 THEN ms				\ allow time for the ARP request (0.5 sec initially, then 1.5 sec)
	LOOP
	drop 0										\ failed to obtain a MAC address
;

: IP.forward ( frame --)
\ Forward an IP frame via direct delivery or indirect delivery
	subnet @								( frame subnet)
	over 30 + @								( frame subnet destIP)
	over and >R								( frame subnet R:destNET)
	hostIP @ and R>							( frame hostNET destNET)
	= IF									\ are destination and host on same subnet?
		dup 30 +							\ direct delivery to the MAC of destination IP
	ELSE
		router								\ indirect delivery to router
	THEN
	( frame IP ) IP.enquireARP
	( frame MAC true | false)  IF Ethernet.dispatchIP ELSE drop THEN
;

: IP.dispatchUDP ( IP --)
\ Prepare an IP frame starting from the UDP frame and then dispatch via IP forwarding
\ The UDP segment of datagram will already have been completed by the caller
	UDPframe
	69 over 14 + c!						\ version and IHT
	 0 over 15 + c!						\ DS and ECN
	dup 38 + w@n 20 +					\ retreive UDP.length and add 20 for IP header
	over 16 + w!n						\ length
	ticks over 18 + w!n					\ identification - need to change each packet
	 0 over 20 + w!						\ flags and fragment offset
	64 over 22 + c!						\ time to live
	17 over 23 + c!						\ protocol = 17 for UDP
	 0 over 24 + w!						\ initial value of checksum
	hostIP over 26 + 4 move				\ copy in source IP address
	swap over 30 + 4 move				\ copy in destination IP address
	dup 14 + 20 checksum over 24 + w!	\ compute and save header checksum
	( UDPframe) IP.forward
;

\ ..............................................................................................................
\ UDP FORTH terminal ...........................................................................................

create UDPdestIP 4 allot			\ IP address for outgoing UDP frames
variable UDPdestPort				\ Destination port of outgoing UDP frames. Word length. MUST USE W@ / W!
variable UDPsrcPort					\ Source port of outgoing UDP frames. Word lenght. MUST USE W@ / W!

: setUDPdestIP ( x0 x1 x2 x3 --)
\ set the host IP address
	UDPdestIP dup 3 + DO i c! -1 +LOOP
;

: UDP.send ( addr n --)
\ send n characters at address addr by UDP
	\ prepare UDP fields
	UDPframe							( addr n frame)
	UDPsrcPort w@ over 34 + w!n
	UDPdestPort w@ over 36 +  w!n
	over 8 + over 38 + w!n				\ add 8 bytes of header to compute UDP size
	0 over 40 + w!						\ zero checksum field initially	
	\ compute checksum starting with the UDP-pseudo header 				
	0 hostIP 4 checksum-add				( addr n frame sum)
	UDPdestIP 4 checksum-add			
	17 endian 0= IF 256 * THEN +		\ protocol byte
	over 38 + w@ +						\ UDP length
	over 34 + 8 checksum-add			\ accumulate true UDP header
										( src n frame sum)
	swap >R	-rot R@ 42 + swap			( sum src dest n R:frame)
	checksum-add&move					( sum R:frame)
	checksum-fold						( sum R:frame)
	R> 40 + w!							\ write the checksum field
	UDPdestIP IP.dispatchUDP
;

: UDP.checksum ( frame -- checksum)
\ return the checksum of a UDP frame within an IP frame
	\ start with the UDP-pseudo header 		
	0 over 26 + 8 checksum-add					\ IP addresses	
	17 endian 0= IF 256 * THEN +				\ protocol byte
	over 38 + w@ +								\ UDP length
	\ UDP header and frame	
	over dup 38 + w@n swap 34 + swap 			( frame sum addr n)
	checksum-add checksum-fold nip
;

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
	
	\ ************************************************
	\ adapt code from here for the intended applicaton
	?dup IF
		CR ." UDP to port " dup .
		UDPsrcPort w@ = IF				\ incoming destPort = local scrPort ?
			inframe dup 42 + over 38 + w@n 8 - 	( frame addr n)
			type CR
			drop
		THEN
	THEN
;

\ ..............................................................................................................
\ Frames received from the network are passed up the protocol stack.............................................

: IP.check ( -- protocol)
\ Check an IP frame.  If the datagram does not meet assumptions or the destination IP does not match the 
\ host IP, return 0.  If the datagram is good, return the protocol
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
\ Check an Ethernet frame. If the frame either does not meet assumptions or if the destination does not match the 
\ host MAC / broadcast, return 0. Is the frame is good, return the EthernetType
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

: EthernetReceiveTask ( --)
\ super-loop running as a separate task that handles incoming frames
	ARPsemaphore ACQUIRE
		ARP.initcache
	ARPsemaphore RELEASE
	BEGIN
		inframe getFrame
		Ethernet.in
	AGAIN
;
