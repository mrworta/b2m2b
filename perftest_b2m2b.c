#include <pcap.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <netinet/ether.h> 
#include <netinet/in.h> 
#include <netinet/ip.h> 
#include <net/if.h> 
#include <netinet/udp.h> 
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/ioctl.h>
 
// Our packet types:
#define PACKET_BOGUS (0)
#define PACKET_BCAST (1)
#define PACKET_MCAST (2)

// #######################################################
// ###### CONFIG ####### 
// #######################################################

static const int DEBUG = 1;
 
char intf_mcast[64];
char intf_bcast[64];

static const char BCAST_DMAC[] = "ff:ff:ff:ff:ff:ff";
static const char BCAST_DSTIP[] = "255.255.255.255";

static const char MCAST_GROUP[] = "239.66.66.66";
static const char MCAST_DMAC[] = "01:00:5e:42:42:42"; // $ToDo: Calculate

// IF you want optimized filtering, replace "multicast" with your mcast group as "dst host". 
static char PCAP_MFILTER[] = "udp and dst net 239.66.66.66";
static char PCAP_BFILTER[] = "broadcast and portrange 1024-65535";

static int LAZY = 1;

// #######################################################

// Working Capture
pcap_t* bcap;		// broadcast capture handle
pcap_t* mcap;		// multicast capture  handle
int sock;		// socket handle

unsigned char intf_mcast_mac[6];
unsigned char intf_bcast_mac[6];
 
struct ipheader {
 unsigned char      iph_ihl:5, iph_ver:4;
 unsigned char      iph_tos;
 unsigned short int iph_len;
 unsigned short int iph_ident;
 unsigned char      iph_flag;
 unsigned short int iph_offset;
 unsigned char      iph_ttl;
 unsigned char      iph_protocol;
 unsigned short int iph_chksum;
 unsigned int       iph_sourceip;
 unsigned int       iph_destip;
};
 
// UDP Checksum

unsigned short int udp_checksum(const void *buff, int len)
{
        const unsigned short int *buf=buff;
	static char src_addr[15], dest_addr[15];
         
        src_addr[0] = 0x0a; src_addr[1] = 0x3c; src_addr[2] = 0x07; src_addr[3] = 0x45;        
        dest_addr[0] = 0x0a; dest_addr[1] = 0x3c; dest_addr[2] = 0x07; dest_addr[3] = 0xff;
         
        unsigned short int *ip_src=(void *)&src_addr, *ip_dst=(void *)&dest_addr;                
        unsigned short int sum;
        size_t length=len;
 
        // Calculate the sum                                            //
        sum = 0;
        while (len > 1)
        {
                sum += *buf++;
                if (sum & 0x80000000)
                        sum = (sum & 0xFFFF) + (sum >> 16);
                len -= 2;
        }
 
        if ( len & 1 )
                // Add the padding if the packet lenght is odd          //
                sum += *((unsigned char *)buf);
 
        // Add the pseudo-header                                        //
        sum += *(ip_src++);
        sum += *ip_src;
 
        sum += *(ip_dst++);
        sum += *ip_dst;
 
        sum += htons(IPPROTO_UDP);
        sum += htons(length);
 
        // Add the carries                                              //
        while (sum >> 16)
                sum = (sum & 0xFFFF) + (sum >> 16);
 
        // Return the one's complement of sum                           //
        return ( (unsigned short int)(~sum)  );
}
// #####

// IP Header Checksum
static unsigned short compute_checksum(unsigned short *addr, unsigned int count) {
  register unsigned long sum = 0;
  while (count > 1) { sum += * addr++; count -= 2; }

  if(count > 0) {
    sum += ((*addr)&htons(0xFF00));
  }

  while (sum>>16) {
      sum = (sum & 0xffff) + (sum >> 16);
  }

  sum = ~sum;

  return ((unsigned short)sum);
}

// Fetch MAC Address from interface
int get_mac(char *iface, unsigned char *mac_address)
{
  struct ifreq s;
  int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
  
  strcpy(s.ifr_name, iface);
  if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
    memcpy(mac_address, s.ifr_addr.sa_data, 6);
    return 1;
  }
  return 0;
}

// Fetch IP Address from interface
int get_ip(char *iface, unsigned char *ip_address)
{
  struct ifreq s;
  int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

  strncpy(s.ifr_name, iface, IFNAMSIZ-1);
  if (0 == ioctl(fd, SIOCGIFADDR, &s)) {
    memcpy(ip_address, inet_ntoa(((struct sockaddr_in *)&s.ifr_addr)->sin_addr), 15);
    return 1;
  }
  return 0;
}

void print_counter(int b, int m, int bogus)
{
  fprintf(stdout, "B:%d - M:%d - Bogus:%d\r", b,m,bogus); 
  fflush(stdout);
}


// Packet Handler for libpcap
void bm_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{

    if (DEBUG > 6) { printf("h"); fflush(stdout); }

    static int count_bogus = 0; 
    static int count_mcast = 0;
    static int count_bcast = 0;

    int packet_type = PACKET_BOGUS;

    // Packer headers
    const struct ether_header *e_hdr; 
    struct ip* ip_hdr;   
    struct udphdr* udp_hdr; 

    u_int length = pkthdr->len;  	/* packet header length  */
    
    e_hdr = (struct ether_header*) packet;

    ip_hdr = (struct ip*)(packet + sizeof(struct ether_header));
        length -= sizeof(struct ether_header);

    udp_hdr = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));

    char *work;
    char mac_dst[18];
    char ip_dst[16];

    work = inet_ntoa(ip_hdr->ip_dst); 
    strncpy(ip_dst, work, sizeof(ip_dst));
    if (strcmp(ip_dst,MCAST_GROUP) == 0) { packet_type = PACKET_MCAST; };

    work = ether_ntoa((const struct ether_addr *)&e_hdr->ether_dhost);
    strncpy(mac_dst, work, sizeof(mac_dst));
    if (strcmp(mac_dst,BCAST_DMAC) == 0) { packet_type = PACKET_BCAST; };

    switch (DEBUG)
    {
	case 5:
    	        work = inet_ntoa(ip_hdr->ip_src); 
		fprintf(stdout, "\n%s:", work);

    		u_short udp_dst = ntohs(udp_hdr->dest);
		fprintf(stdout, "%d", udp_dst);

		if (packet_type == PACKET_MCAST) { fprintf(stdout, "(m@%s >> b@%s)", intf_mcast, intf_bcast); };
                if (packet_type == PACKET_BCAST) { fprintf(stdout, "(b@%s >> m@%s)", intf_bcast, intf_mcast); };
		break;

	case 3:
           	print_counter(count_bcast, count_mcast, count_bogus); 
		break;
	
        case 1: 
		break;
    }


    switch (packet_type)
    {  
	case PACKET_MCAST:
		count_mcast++;

		if ( DEBUG > 0 ) {
		  if ( count_mcast % 100 == 0) { 
    		    syslog (LOG_INFO, "%s[%d]/%s[%d] bogus:[%d]", intf_mcast, count_mcast, intf_bcast, count_bcast, count_bogus);  
		  }
		}

		// #### L2
		// Set source MAC to own:
		memcpy (&e_hdr->ether_shost, intf_bcast_mac, sizeof(e_hdr->ether_shost));

		// Set destination MAC to bcast:
		ether_aton_r(BCAST_DMAC, (struct ether_addr *)&e_hdr->ether_dhost);

		// #### L3
		// Set destination IP to bcast:
		inet_pton(AF_INET, BCAST_DSTIP, &ip_hdr->ip_dst);


		// Checksumming:

		udp_hdr->check = 0x0;
	  	//udp_hdr->check = udp_checksum(packet, pkthdr->len);
	
		ip_hdr->ip_sum = 0x0;
		ip_hdr->ip_sum = compute_checksum((unsigned short*)ip_hdr, ip_hdr->ip_hl<<2);

		// Send packet
		pcap_inject(bcap, packet, pkthdr->len);
		break;

	case PACKET_BCAST:
		count_bcast++;

		// #### L2
		// Set source MAC to own:
		memcpy (&e_hdr->ether_shost, intf_mcast_mac, sizeof(e_hdr->ether_shost));

		// Set destination MAC to mcast group:
		ether_aton_r(MCAST_DMAC, (struct ether_addr *)&e_hdr->ether_dhost);

		// #### L3
		// Set  destination IP to mcast group:
		inet_pton(AF_INET, MCAST_GROUP, &ip_hdr->ip_dst);

		// Checksumming:


		udp_hdr->check = 0x0;
	  	//udp_hdr->check = udp_checksum(packet, pkthdr->len);

		ip_hdr->ip_sum = 0x0;
		ip_hdr->ip_sum = compute_checksum((unsigned short*)ip_hdr, ip_hdr->ip_hl<<2);

		// Send packet
		pcap_inject(mcap, packet, pkthdr->len);
		break;

	case PACKET_BOGUS:
		count_bogus++;
		break;
    }
}

int join_mc_group()
{
   int status;
   unsigned char ip_address[16];
   struct ip_mreq imreq;
   struct sockaddr_in saddr;

   get_ip(intf_mcast, ip_address);
   
   // set content of struct saddr and imreq to zero
   memset(&saddr, 0, sizeof(struct sockaddr_in));
   memset(&imreq, 0, sizeof(struct ip_mreq));

   // open a UDP socket
   sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

   saddr.sin_family = PF_INET;
   saddr.sin_port = htons(27015); 

   saddr.sin_addr.s_addr = inet_addr(ip_address);
   status = bind(sock, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));

   imreq.imr_multiaddr.s_addr = inet_addr(MCAST_GROUP);
   imreq.imr_interface.s_addr = inet_addr(ip_address);

   // JOIN multicast group on default interface
   status = setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, 
              (const void *)&imreq, sizeof(struct ip_mreq));

 
  return 0;
}


int main(int argc,char **argv)
{ 
    char errbufM[PCAP_ERRBUF_SIZE];
    char errbufB[PCAP_ERRBUF_SIZE];
    struct bpf_program fpm;
    struct bpf_program fpb;
    const u_char *packet;
    bpf_u_int32 bmask;		
    bpf_u_int32 mmask;		
    bpf_u_int32 bnet;	
    bpf_u_int32 mnet;	
    struct pcap_pkthdr hdr;    
    struct ether_header *eptr;  

    openlog("b2m2b", LOG_PID, LOG_LOCAL0);

    if ( argc == 3 ) { memcpy(intf_mcast, argv[1],64); memcpy(intf_bcast, argv[2],64); 
    } else { printf("Syntax: b2m2b <mcast-if> <bcast-if>\n\n"); exit(1); }

    get_mac(intf_mcast, intf_mcast_mac); 
    get_mac(intf_bcast, intf_bcast_mac);

    printf ("Bridge for interfaces m:%s b:%s\n", intf_mcast, intf_bcast);  
    syslog (LOG_NOTICE, "Bridge for interfaces m:%s b:%s\n", intf_mcast, intf_bcast);  

    fflush(stdout); 

    join_mc_group();

    pcap_lookupnet(intf_bcast, &bnet, &bmask, errbufB); 
    bcap = pcap_open_live(intf_bcast,BUFSIZ,0,LAZY,errbufB);

    if(bcap == NULL) { printf("%s\n",errbufB); exit(1); };

    pcap_lookupnet(intf_mcast, &mnet, &mmask, errbufM);
    mcap = pcap_open_live(intf_mcast,BUFSIZ,0,LAZY,errbufM);

    if(mcap == NULL) { printf("%s\n",errbufB); exit(1); };

    pcap_compile(bcap, &fpb, PCAP_BFILTER, 0, bnet);
    pcap_compile(mcap, &fpm, PCAP_MFILTER, 0, mnet);

    pcap_setfilter(bcap, &fpb);
    pcap_setfilter(mcap, &fpm);

    pcap_setdirection(bcap, PCAP_D_IN); // Capture only inbound packets. $ToDo: TEST Loop Protection
    pcap_setdirection(mcap, PCAP_D_INOUT); // Capture packets both ways. $ToDo: bcast may be duplicated

    if ( DEBUG > 1 ) {
       printf("Current filter mcast: %s\n", PCAP_MFILTER); 
       printf("Current filter bcast: %s\n", PCAP_BFILTER); 
       printf("Processing....\n"); fflush(stdout); 
    }

    int b=0; int m=0;

    while ( 1) 
    {
      m = pcap_dispatch(mcap,1,bm_callback,NULL);
      b = pcap_dispatch(bcap,1,bm_callback,NULL);

      if (DEBUG > 10) { printf("."); fflush(stdout); }
      if (DEBUG > 5) { if ((m+b) >0) { printf("b:%d m:%d\n",b ,m); fflush(stdout); sleep(0.01); }}
    }

    return 0;
}
