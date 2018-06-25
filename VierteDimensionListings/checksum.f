\        /* Compute Internet Checksum for "count" bytes
\            *         beginning at location "addr".
\            */
\       register long sum = 0;
\
\        while( count > 1 )  {
\           /*  This is the inner loop */
\               sum += * (unsigned short) addr++;
\               count -= 2;
\       }
\
\           /*  Add left-over byte, if any */
\       if( count > 0 )
\               sum += * (unsigned char *) addr;
\
\           /*  Fold 32-bit sum to 16 bits */
\       while (sum>>16)
\           sum = (sum & 0xffff) + (sum >> 16);
\
\       checksum = ~sum;

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


