\ Include this file before Network.F

\ ..............................................................................................................
\ Hardware specific (N.I.G.E. Machine)..........................................................................
hex
03f860 constant MACreadyRX
03f864 constant MACdataRX
03f868 constant MACchecksum_err
03f86c constant MACreadyTX
03f870 constant MACdataTX
03f874 constant MACtransmit_req
03F828 constant	msCounter
decimal

: getFrame ( frame -- ) 
\ wait for an incoming Ethernet frame and place it into inFrame
	BEGIN
		\ wait for an incoming frame
		BEGIN								
			MACreadyRX @
			pause
		UNTIL		
		\ copy the incoming frame from the FIFO buffer to local storage				
		dup 1518 + swap DO								\ maximum 1518 bytes of data may be copied
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

: ticks ( -- ms)
\ return the ms count
	msCounter @
;

: erase ( addr n --)
\ write 0 to n bytes from addr
	over + swap DO
		0 i c!
	LOOP
;
		