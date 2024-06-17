#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

int main()
{
  int sockfd, newsockfd;
  struct sockaddr_in my_addr, client_addr;
  char buffer[100];
  
  // step 1: create a socket
  // AF_INET: IPv4 주소 체계
  // SOCK_STREAM: TCP 소켓 유형
  // 0: 기본 프로토콜 사용 (TCP의 경우 IPPROTO_TCP)
  // 서버 소켓, socket 함수로 생성 
  // 클라이언트의 연결 요청을 수신 대기(listen)하고 수락(accept)하기 위해 사용
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  
  // step 2: bind a port number
  memset(&my_addr, 0, sizeof(struct sockaddr_in));
  my_addr.sin_family = AF_INET;
  my_addr.sin_port = htons(9090);
  my_addr.sin_addr.s_addr = INADDR_ANY; // 모든 인터페이스에서 수신 대기
  
  bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr_in));
  
  // step 3: listen for connections
  // 소켓 파일 디스크립터 sockfd를 통해 최대 5개의 연결 요청을 대기
  // 연결이 완료되지 않은 상태에서 대기할 수 있는 최대 클라이언트 수
  // 소켓은 수신 대기 상태가 되며, 클라이언트는 이 서버에 연결 요청 가능
  // 서버 소켓은 이 요청을 큐에 저장
  // 서버는 accept 함수를 호출하여 큐에 있는 연결 요청을 처리
  listen(sockfd, 5);
  
  // step 4: accept a connection request
  int client_len = sizeof(client_addr);
  // 클라이언트와의 연결을 처리하는 소켓, 
  // accept 함수가 sockfd를 통해 생성
  // 개별 클라이언트와의 통신에 사용
  newsockfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
  
  // step 5: read data from the connection
  memset(buffer, 0, sizeof(buffer));
  int len = read(newsockfd, buffer, 100);
  printf("received %d bytes: %s\n", len, buffer);
  
  while(len > 0) {
    memset(buffer, 0, sizeof(buffer));
    len = read(newsockfd, buffer, 100);
    printf("received %d bytes: %s\n", len, buffer);
  }
  
  // step 6: close the connection
  close(newsockfd);
  close(sockfd);
  
  return 0;
}

