#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<arpa/inet.h>
#include<pcap.h>
#include<time.h>
#include<sys/socket.h>
#include<net/ethernet.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<netinet/ip6.h>
#include<net/if.h>
#include<netinet/in.h>
struct ip_header{
    u_char ip_vhl;
    u_char ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
    u_char ip_ttl;
    u_char ip_p;
    u_short ip_sum;
    struct in_addr ip_src;
    struct in_addr ip_dst;
};
struct tcp_header{
    u_short th_sport;
    u_short th_dport;
    tcp_seq th_seq;
    tcp_seq th_ack;
    u_char th_hlr;
    u_char th_flag;
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
};
struct udp_header{
    u_short uh_sport;
    u_short uh_dport;
    u_short uh_ulen;
    u_short uh_sum;
};

int count[2048]={0};
unsigned char src[2048][25];
unsigned char dst[2048][25];

void ipprocess(const unsigned int length,const unsigned char *content){
unsigned char *IP_src;
unsigned char *IP_dst;
struct ip_header *ipinfo=(struct ip_header *)(content+ ETHER_HDR_LEN);
int size;
int i;
IP_src=inet_ntoa(ipinfo->ip_src);
IP_dst=inet_ntoa(ipinfo->ip_dst);
printf("IP Source:%s\n",IP_src);
printf("IP Destination :%s\n",IP_dst);
for(i=0;i<2048;i++){
    if(count[i]==0){
        count[i]++;
     strcpy(src[i],IP_src);
     strcpy(dst[i],IP_dst);
        break;
    }
    else if(!strncmp(IP_src,src[i],25)&&!strncmp(IP_dst,dst[i],25)) {
        count [i]++;
    break;
    }
}
if(ipinfo->ip_p==IPPROTO_TCP){
size =(ipinfo->ip_vhl&0x0f)*4;
struct tcp_header *tcpinfo = (struct tcp_header *) (content + ETHER_HDR_LEN + size );
printf("TCP PROTOCOL\n");
printf("Src Port >>%u\n", ntohs(tcpinfo->th_sport));
printf("Dst Port >> %u\n", ntohs(tcpinfo->th_dport));
}
else if(ipinfo->ip_p==IPPROTO_UDP){
size =(ipinfo->ip_vhl&0x0f)*4;
struct udp_header *udpinfo = (struct udp_header *) (content + ETHER_HDR_LEN + size );
printf("UDP PROTOCOL\n");
printf("Src Port >>%u\n", ntohs(udpinfo->uh_sport));
printf("Dst Port >> %u\n", ntohs(udpinfo->uh_dport));
}
else printf("%d PROTOCOL\n",ipinfo->ip_p);
}
void decide(  unsigned short type,const unsigned int length,const unsigned char *content ){
	
		if(type==0x0800){
            printf("It's IP protocol\n");
            ipprocess(length,content);
        }
		else if(type==0x0806)printf("It's ARP protocol\n");
		else if(type==0x0835)printf("It's REVARP protocol\n");
        else if(type==0x86DD)printf("It's IPv6 protocol\n");


}

void callback(unsigned char *argument ,const struct pcap_pkthdr *header,const unsigned char *content ){
	unsigned char *mac_src;
    unsigned char *mac_dst;
    struct ether_header *ethernet_protocol=(struct ether_header *)content;
    printf("------------------------------------------------------------\n");
	printf("TIME:%s\n", ctime((time_t *)&(header->ts.tv_sec))); 
    mac_src=(unsigned char *)ethernet_protocol->ether_shost;
    mac_dst=(unsigned char *)ethernet_protocol->ether_dhost;
    printf("Mac Source:%02x:%02x:%02x:%02x:%02x:%02x\n",*(mac_src),*(mac_src+1),*(mac_src+2),*(mac_src+3),*(mac_src+4),*(mac_src+5));
	printf("Mac Destination :%02x:%02x:%02x:%02x:%02x:%02x\n",*(mac_dst),*(mac_dst+1),*(mac_dst+2),*(mac_dst+3),*(mac_dst+4),*(mac_dst+5));
   decide(ntohs(ethernet_protocol->ether_type),header->caplen,content);
}
int main (int argc ,char *argv[]){
    pcap_t *pcap_handle;
    char *dev;
    char errorbuf[PCAP_ERRBUF_SIZE];

if(argc>2){
    pcap_handle=pcap_open_offline(argv[2],errorbuf);
}
else {
    dev=pcap_lookupdev(errorbuf);
    pcap_handle=pcap_open_live(dev,100000,0,10,errorbuf);
}
pcap_loop(pcap_handle,-1,callback,NULL);
 printf("IP statistics\n");
 for(int i = 0;; i++){
     if(count[i]!=0)printf("FROM %15s TO  %15s Total Packets : %4d\n", src[i], dst[i], count[i]);
     else break;
    }

return 0;
}
