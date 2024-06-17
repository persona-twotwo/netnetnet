// POSIX 운영 체제 API를 위한 기본적인 시스템 서비스와 API 함수를 제공
#include <unistd.h>

//입출력 관련 함수를 포함
#include <stdio.h>

// 소켓 프로그래밍을 위한 기본 헤더 파일
#include <sys/socket.h>
#include <arpa/inet.h>

// 로우 소켓을 사용하기 위한 구조체 및 상수 정의를 제공
#include <linux/if_packet.h>
#include <net/ethernet.h>


int main()
{
  int PACKET_LEN = 32;
  char buffer[PACKET_LEN];

  // 네트워크 주소를 저장하는 데 사용되는 일반적인 데이터 구조
  struct sockaddr saddr;

  // 리눅스의 패킷 소켓에서 멀티캐스트 그룹 멤버십이나 
  // 프로미스큐어스 모드(promiscuous mode)와 같은 기능을 설정할 때 사용
  struct packet_mreq mr;
  
  // Create the raw socket
  /*
  AF_PACKET는 리눅스에서 네트워크 레이어와 데이터 링크 레이어 사이의 통신을 위해 사용.
  SOCK_RAW는 로우 소켓을 의미하며, 
  htons(ETH_P_ALL)는 모든 이더넷 프로토콜의 패킷을 수신하도록 설정.
  */
  int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); // (1)
  
  // Turn on the promiscuous mode
  /*
  멀티캐스트 요청 구조체를 프로미스큐어스 모드로 설정하여 모든 패킷을 수신하도록 설정. 
  프로미스큐어스 모드는 네트워크 인터페이스가 자신에게 보내지 않은 패킷도 수신.
  */
  mr.mr_type = PACKET_MR_PROMISC; // (2)

  // 설정된 멀티캐스트(여기서는 프로미스큐어스 모드) 요청을 소켓에 적용.
  setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)); // (3)
  /*
  sock: 이 매개변수는 socket() 함수 호출에 의해 생성된 소켓의 파일 디스크립터. 
         이는 수정하려는 소켓 자체를 지정.
  SOL_PACKET: 이 옵션은 소켓 레벨을 지정. 
              SOL_PACKET은 패킷 소켓에 대한 옵션을 설정하고자 할 때 사용, 
                 패킷 소켓은 데이터 링크 계층에서 직접 데이터를 수신하고 전송.
  PACKET_ADD_MEMBERSHIP: 이 옵션은 소켓이 특정 인터페이스의 패킷을 수신하도록 구성. 
                 멀티캐스트 그룹에 조인하거나 프로미스큐어스 모드를 활성화하기 위해 사용.
  &mr: struct packet_mreq 타입의 구조체로, 멤버십 정보를 설정하는 데 필요한 정보를 포함. 
        이 구조체는 멀티캐스트 그룹 설정이나 프로미스큐어스 모드 등의 구성을 포함. 
       mr 구조체의 mr_type 필드는 사용할 멤버십 타입을 지정하며, 
        예를 들어 PACKET_MR_PROMISC는 소켓이 프로미스큐어스 모드로 동작하도록 설정.
  sizeof(mr): setsockopt 함수에 전달되는 mr 구조체의 크기를 바이트 단위로 지정. 
                올바른 크기 정보는 커널이 해당 옵션을 정확히 처리하는 데 필수.
  */
  
  // Getting captured packets
  while(1) {
    /*
    설정된 소켓을 통해 패킷을 수신. 
    buffer는 수신된 데이터를 저장하는 배열이며, PACKET_LEN은 수신할 데이터의 최대 크기.
    saddr는 소켓 주소 구조체로, 수신된 패킷의 소스 주소 정보를 저장
    */
    int data_size = recvfrom(sock, buffer, PACKET_LEN, 0,
                             &saddr, (socklen_t*)sizeof(saddr));  // (4)
    if(data_size) printf("get one packet\n");
  }
  
  close(sock);
  
  return 0;
  
}
