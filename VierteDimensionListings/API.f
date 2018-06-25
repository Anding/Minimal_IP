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

: Ethernet.in ( --)
\ Receive an IP frame form the MAC controller and pass it up the protocol stack
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