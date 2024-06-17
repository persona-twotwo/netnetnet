#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include"myheader.h"

#define SRC_IP   "100.2.3.4"
#define DEST_IP  "10.0.2.7"
#define DST_PORT 9090


void send_raw_ip_packet(struct ipheader* ip);
 

void main()
{
 char buffer[PACKET_LEN];
 memset(buffer, 0, PACKET_LEN);

 // Find the starting point of each layer
 struct ipheader *ip = (struct ipheader *)buffer;
 struct udpheader *udp = (struct udpheader *)
                         (buffer + sizeof(struct ipheader));
 char   *data = buffer + sizeof(struct ipheader) 
                       + sizeof(struct udpheader);




 // Add UDP data 
 char *msg="Hello Server.\n";
 int data_len=strlen(msg);
 strncpy(data, msg, data_len);


 // Construct UDP Header
 udp->udp_dport = htons(DST_PORT);
 udp->udp_sport = htons(9999);
 udp->udp_ulen  = htons(sizeof(struct udpheader) + data_len);
 udp->udp_sum   = 0;




 // Construct IP Header
 ip->iph_ver = 4;
 ip->iph_ihl = 5;
 ip->iph_ttl = 20;
 ip->iph_sourceip.s_addr = inet_addr(SRC_IP);
 ip->iph_destip.s_addr   = inet_addr(DEST_IP);
 ip->iph_protocol = IPPROTO_UDP;
 ip->iph_len = htons(sizeof(struct ipheader) + 
                     sizeof(struct udpheader) + data_len);
 ip->iph_chksum = 0; // Leave it to OS to set this field


 // Send out the construct packet 
 send_raw_ip_packet(ip);
}


void send_raw_ip_packet(struct ipheader* ip)
{
  struct sockaddr_in dest_info;
  int enable = 1;
  //Create a raw socket
  int sock = socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
 
  setsockopt(sock,IPPROTO_IP,IP_HDRINCL,&enable,sizeof(enable));
 	
  //Destination info
  dest_info.sin_family=AF_INET;
  dest_info.sin_addr=ip->iph_destip;
	
  //Send the packet out
  printf("Sending spoofed IP packet...\n");
  if(sendto(sock,ip,ntohs(ip->iph_len), 0, 
        (struct sockaddr *)&dest_info, sizeof(dest_info)) < 0){
     perror("PACKET NOT SENT\n");
     return;
  }
  else {
     printf("\n---------------------------------------------\n");
     printf("	From: %s\n",inet_ntoa(ip->iph_sourceip));
     printf("	To:   %s\n",  inet_ntoa(ip->iph_destip));
     printf("---------------------------------------------\n");
  }
  close(sock);
}

