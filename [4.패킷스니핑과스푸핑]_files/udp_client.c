#include <unistd.h>
// POSIX 운영 체제 API 접근을 위한 헤더 파일
#include <stdio.h>
// 표준 입출력 함수들을 위한 헤더 파일
#include <string.h>
// 문자열 처리 함수들을 위한 헤더 파일
#include <sys/socket.h>
// 소켓 프로그래밍을 위한 헤더 파일
#include <netinet/ip.h>
// 인터넷 프로토콜(IP) 관련 구조체를 위한 헤더 파일
#include <arpa/inet.h>
// 인터넷 주소 변환 함수를 위한 헤더 파일

void main()
{
  struct sockaddr_in dest_info;
  // 목적지 주소 정보를 저장할 구조체
  
  char *data = "UDP message\n";
  // 전송할 데이터를 저장할 문자열
  
  // Step 1: Create a network socket
  /*
  IPv4 주소 체계(AF_INET)와 UDP 소켓(SOCK_DGRAM)을 사용하여 소켓을 생성. 
  IPPROTO_UDP는 UDP 프로토콜을 의미 
  */
  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  
  // Step 2: Provide information about destination.
  memset((char *)&dest_info, 0, sizeof(dest_info));
  // dest_info 구조체를 0으로 초기화
  dest_info.sin_family = AF_INET;
  // 주소 체계를 IPv4로 설정
  dest_info.sin_addr.s_addr = inet_addr("10.9.0.5");
  // 목적지 IP 주소를 설정. 
  // "10.9.0.5"는 문자열 형태의 IP 주소를 네트워크 바이트 순서의 이진 값으로 변환.
  dest_info.sin_port = htons(9090);
  // 목적지 포트를 설정. 
  // htons 함수는 호스트 바이트 순서에서 네트워크 바이트 순서로 포트 번호를 변환
  .
  // Step 3: Send out the packet.
  sendto(sock, data, strlen(data), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
  // UDP 패킷을 전송
  // sock: 전송에 사용할 소켓의 파일 디스크립터.
  // data: 전송할 데이터.
  // strlen(data): 전송할 데이터의 길이.
  // 0: 플래그(기본값 0), 기본값 0은 특별한 옵션을 설정하지 않는 것을 의미
  //(struct sockaddr *)&dest_info: 목적지 주소 정보.
  // sizeof(dest_info): 목적지 주소 정보의 크기.
  
  close(sock);
  // 소켓을 닫아 자원을 해제
}
