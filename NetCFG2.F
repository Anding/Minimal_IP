\ Network configuration file #2 for N.I.G.E. Machine

\ Network configuration
hex
02 4e 49 47 45 02 setMAC		\ 02 (indicates a locally administered MAC) + 4e 49 47 45 (ASCII "NIGE") + 02

decimal
255 255 255 0 setSubnet			\ check this setting with the local network router			
192 168 1 1 setRouter			\ " "		
192 168 1 102 setIP				\ fixed IP address, need to check no conflicts		

\ Initialize network communications
: debugEthernet
\	>remote						\ uncomment this line to send output to the RS232 serial port instead of the screen
	EthernetReceiveTask
;

: start-test
	0 ['] debugEthernet ( n XT) RUN ( task# true | false) 
	CR IF ." EthernetReceiveTask is " . ELSE ." New task failed" THEN
; 

\ UDP experiments
192 168 1 101 setUDPdestIP		\ set this to the IP of the partner machine	
5000 UDPsrcPort w!				\ source port of outgoing frames. Word length: MUST USE W! \ W@	
5000 UDPdestPort w!				\ destination port of outgoing frames. Word length: MUST USE W! \ W@

start-test

\ outgoing UDP datagram usage
\ 	s" My message" (addr n --) UDP.send

\ by default incoming UDP datagrams will be typed if their destination port = UDPsrcPort
\ 	otherwise adapt UDP.in for the intended application