\ Simulation test in VXF environment to check an example of
\ 1. IPchecksum
\ 2. UDPchecksum of an incoming frame
\ 3. UDPchecksum of a synthesized frame


decimal
10 11 12 13 14 15 setMAC
192 168 1 99 setIP			\ 0xC0A80163
255 255 255 0 setSubnet
192 168 1 1 setRouter		\ 0xC0A80101
HEX
CR
\ 1. IP checksum
UDPframe parseframe 00507f7c9ab06cf049eef42a08004500003c1c46400040060000ac100a63ac100a0c
UDPframe 0E + 14 checksum 
CR . ." should be E6B1"	\ checksum appears byte reversed on a little endian machine

\ 2. UDPchecksum of an incoming frame
\ checksum bytes indicated                                                                          14de
UDPframe parseframe 00507f7c9ab06cf049eef42a08004500005078910000801100009801331b980e5e4ba08f2694000a14DE626245
UDP.checksum
CR . ." should be 0000"

\ 3. UDPchecksum of a synthesized frame
98 01 33 1b setIP
98 0e 5e 4b setUDPdestIP
a08f UDPsrcPort w!
2694 UDPdestPort w!
inframe parseframe 626245
inframe 2 UDP.send  		\ suggest edit the last line of UDP.send to omit the actual dispatch
UDPframe 28 + w@n
CR . ." should be 14de"

\ Some other UDP frames
\ checksum bytes indicated                                                                          XXXX
UDPframe parseframe 6cf049eef42a00507f7c9ab00800450000500a4400007011f1e83eb74dffc0a8011241cff526003ca0336000000000003b15200100009d3890d7040bbe30c148b200200100009d386ab8283706592df943660104c65626ef040401000000
UDP.checksum CR . ." should be 0000"
UDPframe parseframe 6cf049eef42a00507f7c9ab00800450000500a4400007011f1e83eb74dffc0a8011241cff526003c00006000000000003b15200100009d3890d7040bbe30c148b200200100009d386ab8283706592df943660104c65626ef040401000000
UDP.checksum CR . ." should be 33A0"
UDPframe parseframe 6cf049eef42a00507f7c9ab0080045000050020200006311aefd5f99854ac0a80112b8bdf526003c6c586000000000003b15200100009d386ab820c74742a0667ab5200100009d386ab8283706592df943660104275b0429040400000000
UDP.checksum CR . ." should be 0000"
UDPframe parseframe 6cf049eef42a00507f7c9ab0080045000050020200006311aefd5f99854ac0a80112b8bdf526003c6c586000000000003b15200100009d386ab820c74742a0667ab5200100009d386ab8283706592df943660104275b0429040400000000
UDP.checksum CR . ." should be 0000"