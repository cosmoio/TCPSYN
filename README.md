# TCPSYN
A TCP Syn flooder, which I quickly, coded many years ago for the University. The code should only be used 
for educational purposes! The source code is provided without warranty and I warn you that to use that code on some target, 
which you do not own, might result in damage that you will have to account for (legal regulations are strict theses days).

### Description

The tool basically creates handcrafted TCP packets w. a random IP address to fool a remote host (aka victim) into thinking that a random 
IP wants to initiate a connection (SYN flag set). Obviously that is not the case and fills the backlog of the victim until (ideally) the victim starts to drop connections. That's were the DoS comes from.


### Usage

./syn

### Compile Options 

gcc tcpsyn.c -o syn

### Output

>cosmo@#####:~/#####/Programming/C/TCP/TCPSYN$ sudo ./syn 

>Are you root.. yes!

>Packet from: 122.10.180.145 to: 127.0.0.1 sent.

>Packet from: 190.13.111.170 to: 127.0.0.1 sent.

>Packet from: 179.222.197.164 to: 127.0.0.1 sent.

>Packet from: 137.209.152.40 to: 127.0.0.1 sent.

