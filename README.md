# Minimal_IP
A minimal UDP/IP stack in FORTH for the N.I.G.E. Machine

The purpose of this package is to support a UDP/IP terminal on the N.I.G.E. Machine via the Nexys4 / Nexys4DDR Ethernet adapter.  However it should be adaptable to other systems.  See the comments in `network.f`

Instructions: copy the files to a microSD card, connect the N.I.G.E. Machine to the network with an Ethernet cable, power on, and at the Forth prompt enter
```forth
mount
include netnige.f
include network.f
include netcfg1.f 
```
See the file `netcfg1.f` for how to proceed from here.

You can also connect two N.I.G.E. Machines together!  Do so directly using a crossover Ethernet cable (typically red in colour), or simply by connecting each N.I.G.E. Machine to a router/switch with a standard Ethernet cable. On the second N.I.G.E. Machine use the alternative configuration file:
```forth
include netcfg2.f 
```
