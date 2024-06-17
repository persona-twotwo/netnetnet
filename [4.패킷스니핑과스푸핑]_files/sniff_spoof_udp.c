/*
지정된 네트워크 인터페이스에서 실시간으로 패킷을 캡처하고, 필터링된 패킷을 처리.
캡처된 패킷 중 UDP 패킷을 식별하여, 특정 조건 (목적지 포트가 9999일 때)에서 변조된 UDP 응답 패킷을 생성하여 전송.
변조된 패킷은 출발지와 목적지 IP 주소, 포트를 바꾸고, 새로운 데이터를 포함하도록 수정.
최종적으로 원시 소켓을 통해 변조된 패킷을 네트워크로 전송.
*/

// 표준 입출력, 문자열 처리, 네트워크 관련 함수 및 라이브러리를 사용
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap.h>

#define ETHER_ADDR_LEN  6
#define PACKET_LEN 1500

/* Ethernet header */
// 이더넷 헤더 구조체로, 목적지 주소, 출발지 주소, 이더 타입을 포함
struct ethheader {
  u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
  u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP Header */
// IP 헤더 구조체로, IP 헤더 길이, 버전, 
// 서비스 타입, 패킷 길이, 식별자, 플래그, 오프셋, 
// TTL, 프로토콜, 체크섬, 출발지 및 목적지 IP 주소를 포함
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

/* UDP Header */
// UDP 헤더 구조체로, 출발지 포트, 목적지 포트, 길이, 체크섬을 포함
struct udpheader
{
  u_int16_t udp_sport;           /* source port */
  u_int16_t udp_dport;           /* destination port */
  u_int16_t udp_ulen;            /* udp length */
  u_int16_t udp_sum;             /* udp checksum */
};

/* ICMP Header */
//  ICMP 헤더 구조체로, 메시지 타입, 코드, 체크섬, 식별자, 순서 번호를 포함
struct icmpheader {
  unsigned char icmp_type; //ICMP message type
  unsigned char icmp_code; //Error code
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int icmp_id; //Used in echo request/reply to identify request
  unsigned short int icmp_seq;//Identifies the sequence of echo messages, 
                              //if more than one is sent.
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet); 
void spoof_reply_udp(const struct ipheader* ip);
void send_raw_ip_packet(const struct ipheader* ip);
unsigned short in_cksum(unsigned short *buf,int length);

/*
네트워크 인터페이스를 통해 실시간으로 패킷을 캡처.
필터를 설정하여 UDP 패킷만 캡처.
패킷을 처리하는 got_packet 함수를 호출. 
*/
int main()
{
  pcap_t *handle; 
  char errbuf[PCAP_ERRBUF_SIZE]; 
  struct bpf_program fp; 
  char filter_exp[] = "udp"; 
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with interface name
  handle = pcap_open_live("br-14fa1da8e8b8", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code 
  pcap_compile(handle, &fp, filter_exp, 0, net); 
  pcap_setfilter(handle, &fp);

  // Step 3: Capture packets 
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle); //Close the handle 
  return 0;
}

/*
캡처된 패킷을 이더넷 헤더로 파싱.
IP 프로토콜을 확인하여 IP 패킷만 처리합.
IP 헤더를 파싱하고, 프로토콜 타입에 따라 적절한 처리. 
UDP 패킷의 경우 spoof_reply_udp 함수를 호출하여 변조된 응답을 전송.
*/
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) 
{ 
  struct ethheader *eth=(struct ethheader *)packet;
	
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
        spoof_reply_udp(ip);
        break;
      case IPPROTO_ICMP:
        printf("	Protocol: ICMP\n");
        break;
      default:
        printf("	Protocol: Others\n");
        break;
    }
    printf("\n---------------------------------------------------\n");
  }
  return;
}
/*
UDP 패킷을 변조하여 출발지 포트와 목적지 포트를 바꾸고, 새로운 데이터를 포함하는 패킷을 생성.
IP 헤더를 수정하고, UDP 헤더를 수정하여 새 패킷을 구성.
변조된 패킷을 전송하기 위해 send_raw_ip_packet 함수를 호출. 
*/
void spoof_reply_udp(const struct ipheader* ip)
{
  printf("\n---------------------------------------------------\n");
  const char buffer[PACKET_LEN];
 	
  int ip_header_len = ip->iph_ihl * 4;
  struct udpheader *udp = (struct udpheader *)((u_char *)ip + ip_header_len);
 	
  if(ntohs(udp->udp_dport) != 9999) {
    // only spoof UDP packet with destination port 9090
    printf("111 ===> udp->udp_dport = %d\n", ntohs(udp->udp_dport));
    printf("777 ===> udp->udp_sport = %d\n\n", ntohs(udp->udp_sport));
    //printf("bbb ===> udp->udp_sport = %d\n", udp->udp_sport);
    return;
  }
  else {
    printf("222 ===> udp->udp_dport = %d\n", ntohs(udp->udp_dport));
    printf("888 ===> udp->udp_sport = %d\n\n", ntohs(udp->udp_sport));
  }
 	
  // Step 1: Make a copy from the original packet
  memset((char *)buffer, 0, PACKET_LEN);
  memcpy((char *)buffer, ip, ntohs(ip->iph_len));
 	
  struct ipheader *newip = (struct ipheader *)buffer;
  struct udpheader *newudp = (struct udpheader *)(buffer + ip_header_len);
 	
  char *data = (char *)newudp + sizeof(struct udpheader);
 	
  // Step 2: Construct the UDP payload, keep track of payload size
  const char *msg = "Hello\n";
  int data_len = strlen(msg);
  strncpy(data, msg, data_len);
 	
  // Step 3: Construct the UDP header
  newudp->udp_sport = udp->udp_dport;
  printf("333 ===> udp->udp_dport = %d\n", ntohs(udp->udp_dport));
  printf("444 ===> newudp->udp_sport = %d\n\n", ntohs(newudp->udp_sport));
 	
  newudp->udp_dport = udp->udp_sport;
  printf("555 ===> udp->udp_sport = %d\n", ntohs(udp->udp_sport));
  printf("666 ===> newudp->udp_dport = %d\n\n", ntohs(newudp->udp_dport));
 	
  newudp->udp_ulen = htons(sizeof(struct udpheader) + data_len);
  newudp->udp_sum = 0;
  //newudp->udp_sum = in_cksum((unsigned short *)newudp, sizeof(struct udpheader) + data_len);
 	
  // Step 4: Construct the IP header (no change for other fields)
  newip->iph_sourceip = ip->iph_destip;
  newip->iph_destip = ip->iph_sourceip;
  newip->iph_ttl = 50;
  newip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct udpheader) + data_len);
 	
  // Calculate the IP checksum
  newip->iph_chksum = 0;
  //newip->iph_chksum = in_cksum((unsigned short *)newip, sizeof(struct ipheader) + sizeof(struct udpheader) + data_len);
 	
  // Step 5: Send Spoofed reply
  send_raw_ip_packet(newip);
}

/*
원시 소켓을 생성하여 패킷을 전송.
목적지 주소를 설정하고, 패킷을 전송.
*/
void send_raw_ip_packet(const struct ipheader* ip)
{
  struct sockaddr_in dest_info;
  int enable = 1;
  	
  int ip_header_len = ip->iph_ihl * 4;
  struct udpheader *udp = (struct udpheader *)((u_char *)ip + ip_header_len);
  	
  //Create a raw socket
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
 	
  //Destination info
  dest_info.sin_family = AF_INET;
  dest_info.sin_addr = ip->iph_destip;
	
  //Send the packet out
  printf("\nSending spoofed IP packet...\n");
  if(sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info)) < 0)
  {
    perror("PACKET NOT SENT\n");
    return;
  }
  else
  {
    printf("\n---------------------------------------------------\n");
    printf("	From:%s\n",inet_ntoa(ip->iph_sourceip));
    printf("	To:%s\n",inet_ntoa(ip->iph_destip));
    printf("999 ===> udp->udp_dport = %d\n", ntohs(udp->udp_dport));
    printf("AAA ===> udp->udp_sport = %d\n", ntohs(udp->udp_sport));
    printf("\n---------------------------------------------------\n");
  }
  close(sock);
}
/*
체크섬을 계산하는 함수. IP 및 UDP 헤더의 무결성을 확인하기 위해 사용.
*/
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


/*
void spoof_reply_icmp(struct ipheader* ip)
{
	printf("\n---------------------------------------------------\n");
 	int ip_header_len = ip->iph_ihl * 4;
 	const char buffer[PACKET_LEN];
 
 	memset((char*)buffer, 0, PACKET_LEN);
 	memcpy((char*)buffer, ip, ntohs(ip->iph_len));

	//Construct icmp header
 
	//Set icmp header for reply
 
 	//Construct ip header
 
 	//Send Spoofed reply
 	send_raw_ip_packet(newip); 
}
*/

