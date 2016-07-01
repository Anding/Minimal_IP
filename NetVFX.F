\ Include this file before Network.F

\ ..............................................................................................................
\ Hardware specific (VFX stubs).................................................................................

: getFrame ( frame -- ) 
\ wait for an incoming Ethernet frame and place it into inFrame
	drop
;

: putFrame ( frame len --)
\ wait until MAC controller is free and then send the Ethernet frame of length len
\ the Ethernet CRC checksum will be computed in hardware by the MAC controller 
	drop drop
;
	
\ ..............................................................................................................
\ Debugging ....................................................................................................

: parseFrame ( frame <FRAMESTRING> --)
\ Parse a hex string (e.g. copied from wireshark) and place it into frame
\ Requires that BASE already be hexadecimal
\ Example usage:
\ 	hex inFrame parseFRAME ffffffffffff6cf049eef42a080600010800060400016cf049eef42ac0a80112000000000000c0a80101
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
