#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

// 패킷의 최대 길이를 1500 바이트로 정의
#define PACKET_LEN   1500
// 위조할 출발지 IP 주소를 "1.2.3.4"로 정의
#define SRC_IP   "1.2.3.4"
// 목적지 IP 주소를 "10.9.0.5"로 정의
#define DEST_IP  "10.9.0.5"

/* IP Header */
// IP 헤더의 각 필드를 정의하는 구조체
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
// ICMP 헤더의 각 필드를 정의하는 구조체
struct icmpheader {
	unsigned char icmp_type; //ICMP message type
	unsigned char icmp_code; //Error code
	unsigned short int icmp_chksum; //Checksum for ICMP Header and data
	unsigned short int icmp_id; //Used in echo request/reply to identify request
 	unsigned short int icmp_seq;//Identifies the sequence of echo messages, 
				    //if more than one is sent.
};

// CMP 헤더의 각 필드를 정의하는 구조체
unsigned short in_cksum(unsigned short *buf,int length);
// 주어진 IP 패킷을 원시 소켓을 통해 전송하는 함수
void send_raw_ip_packet(struct ipheader* ip);

/******************************************************************
  Spoof an ICMP echo request using an arbitrary source IP Address
*******************************************************************/
int main() {		
  char buffer[PACKET_LEN];
  memset(buffer, 0, PACKET_LEN);

  // Step 1: Fill the ICMP Header
  // ICMP 에코 요청 메시지를 생성하고 체크섬을 계산
  struct icmpheader *icmp;
  icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));

  icmp->icmp_type = 8; //ICMP Type: 8 is request, 0 is reply.

  // Calculate the checksum for integrity
  icmp->icmp_chksum = 0; 
  icmp->icmp_chksum = in_cksum((unsigned short *)icmp, sizeof(struct icmpheader));

  // Step 2: Construct the IP header.
  // IP 헤더를 생성하고 출발지 및 목적지 IP 주소, 프로토콜 등을 설정
  struct ipheader *ip = (struct ipheader *) buffer;
  ip->iph_ver = 4;
  ip->iph_ihl = 5;
  ip->iph_ttl = 20; 
  ip->iph_sourceip.s_addr = inet_addr(SRC_IP);
  ip->iph_destip.s_addr = inet_addr(DEST_IP);
  ip->iph_protocol = IPPROTO_ICMP; // The value is 1, representing ICMP.
  ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));
	
  // No need to set the following fileds, as they will be set by the system.
  // ip->iph_chksum = ...;

  // Step 3: Finally, send the spoofed packet
   // 원시 소켓을 통해 설정된 패킷을 전송
   send_raw_ip_packet (ip);

   return 0;
}

/******************************************************************************* 
  Given an IP packet, send it out using raw socket. 
*******************************************************************************/
void send_raw_ip_packet(struct ipheader* ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // Create a raw network socket, and set its options.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    // Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Send the packet out.
    printf("Sending spoofed IP packet...\n");
    if(sendto(sock,ip,ntohs(ip->iph_len),0,(struct sockaddr *)&dest_info,sizeof(dest_info)) < 0)
    {
        perror("PACKET NOT SENT\n");
        return;
    }
    else {
        printf("\n---------------------------------------------------\n");
        printf("   From: %s\n",inet_ntoa(ip->iph_sourceip));
        printf("   To: %s\n",inet_ntoa(ip->iph_destip));
        printf("\n---------------------------------------------------\n");
    }
    close(sock);
}

/*
in_cksum 함수는 IP 헤더나 ICMP 헤더의 체크섬을 계산하는 함수. 
체크섬은 데이터 무결성을 확인하기 위한 값으로, 데이터 전송 중 발생할 수 있는 오류를 감지하는 데 사용. 
이 함수는 16비트 단위로 데이터를 더하고, 그 합의 1의 보수를 취해 체크섬을 계산 
*/
unsigned short in_cksum(unsigned short *buf,int length)
{
  // buf는 체크섬을 계산할 데이터 버퍼로, 16비트 단위로 접근하기 위해 포인터 w에 할당
  unsigned short *w = buf;
  // nleft는 남은 데이터의 길이를 저장
  int nleft = length;
  // 합계를 저장할 변수 sum을 초기화
  int sum = 0;
  // 마지막 1바이트를 처리할 임시 변수 temp를 초기화
  unsigned short temp=0;

  /*
   * The algorithm uses a 32 bit accumulator (sum), adds
   * sequential 16 bit words to it, and at the end, folds back all the
   * carry bits from the top 16 bits into the lower 16 bits.
   */
  // 남은 데이터가 2바이트 이상이면 루프를 계속 돌면서 2바이트씩 합산 
  while (nleft > 1)  {
    // 포인터 w가 가리키는 16비트 값을 sum에 더하고, 포인터 w를 다음 16비트로 이동
    sum += *w++;
    // 남은 데이터 길이를 2바이트 감소
    nleft -= 2;
  }

  /* treat the odd byte at the end, if any */
  // 남은 데이터가 1바이트인 경우
  if (nleft == 1) {
    // 마지막 1바이트를 temp의 하위 1바이트에 저장
    *(u_char *)(&temp) = *(u_char *)w ;
    // 이를 sum에 합산
    sum += temp;
  }

  /* add back carry outs from top 16 bits to low 16 bits */
  // 합산된 sum에서 상위 16비트를 하위 16비트에 더합니다
  sum = (sum >> 16) + (sum & 0xffff);     // add hi 16 to low 16 
  // 이를 sum에 합산
  sum += (sum >> 16);                     // add carry 
  // sum의 1의 보수를 취해 체크섬을 반환
  return (unsigned short)(~sum);
}

