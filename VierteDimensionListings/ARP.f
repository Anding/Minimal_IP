: ARP.lookupIP ( IP -- addr flags) 
\ lookup IP in cache.  Returns flags and addr as follows
\  0  : IP not found. Address addr can be used to hold this IP entry
\  1  : partial IP (no MAC) entry available at address addr
\ -1  : complete IP/MAC entry available at address addr
;	

: ARP.request ( IP --)
\ create and send an ARP request WhoIs? IP
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
