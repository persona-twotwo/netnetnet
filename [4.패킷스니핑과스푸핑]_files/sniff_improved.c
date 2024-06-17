#include <stdio.h>
// 패킷 캡처 라이브러리인 pcap를 포함
#include <pcap.h> 
// 인터넷 작업을 위한 라이브러리로, IP 주소 변환 함수 등이 포함
#include <arpa/inet.h>

/* ethernet headers are always exactly 14 bytes [1] */
// 이더넷 헤더의 크기를 정의
#define SIZE_ETHERNET 14
/* Ethernet addresses are 6 bytes */
//이더넷 주소의 길이를 정의
#define ETHER_ADDR_LEN  6
//최대 패킷 길이를 정의
#define PACKET_LEN   1500

/* Ethernet header */
/*
이더넷 헤더는 목적지 호스트 주소, 
출발지 호스트 주소, 이더넷 타입을 포함
*/
struct ethheader {
  u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
  u_short ether_type;                     /* IP? ARP? RARP? etc */
};


/* IP Header */
/*
IP 헤더는 IP 버전, 헤더 길이, 서비스 타입, 
패킷 길이, 식별자, 플래그, 오프셋, TTL, 프로토콜, 체크섬, 
출발지 및 목적지 IP 주소를 포함
*/
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


/*
패킷이 캡처되면 호출되며, 이더넷 헤더를 확인하고 
IP 패킷인 경우 IP 헤더 정보를 출력. 
프로토콜 유형(TCP, UDP, ICMP 등)을 식별하여 출력
*/
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) 
{ 
  int i=0;
  int size_data=0;
  
  printf("\nGot a packet\n"); 

  struct ethheader *eth=(struct ethheader *)packet;
  // 네트워크 바이트 순서에서 호스트 바이트 순서로 변환 후 비교
  if(ntohs(eth->ether_type) == 0x800) // IP 패킷인지 확인
  {
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    printf("	From: %s\n",inet_ntoa(ip->iph_sourceip));
    printf("	To: %s\n",inet_ntoa(ip->iph_destip));
    
    switch(ip->iph_protocol) {
      case IPPROTO_TCP:
        printf("	Protocol: TCP\n");
        // TCP 패킷 추가 처리
	break;
      case IPPROTO_UDP:
        printf("	Protocol: UDP\n");
        // UDP 패킷 추가 처리
        break;
      case IPPROTO_ICMP:
        printf("	Protocol: ICMP\n");
        // ICMP 패킷 추가 처리
        // int ip_header_len = ip->iph_ihl * 4;
        // u_char *icmp = (struct icmpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
        break;
      default:
        printf("	Protocol: Others\n");
        break;
    }
  }
  return;
}

int main() 
{ 
  pcap_t *handle; 
  char errbuf[PCAP_ERRBUF_SIZE]; 
  struct bpf_program fp; 
  char filter_exp[] = "icmp"; 
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with interface name
  // 10.9.0.xxx networks --> br-14fa1da8e8b8
  handle = pcap_open_live("br-14fa1da8e8b8", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code 
  pcap_compile(handle, &fp, filter_exp, 0, net); 
  pcap_setfilter(handle, &fp);

  // Step 3: Capture packets 
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle); //Close the handle 
  
  return 0;
}
