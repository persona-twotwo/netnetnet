#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>

void main()
{
  struct sockaddr_in server;
  struct sockaddr_in client;
  
  int clientlen = sizeof(client);
  char buf[1500];
  
  // step 1
  /* 
  이 줄은 인터넷 도메인에서 사용할 수 있는 UDP 소켓을 생성. 
  AF_INET은 IPv4 인터넷 프로토콜을 사용한다는 것을 의미, 
  SOCK_DGRAM은 데이터그램 기반의 비연결형 소켓을 생성한다는 것을 의미. 
  IPPROTO_UDP는 UDP 프로토콜을 사용함을 지정. 
  */

  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  
  
  // step 2
  /*
  서버 주소 구조체를 초기화한 후, 이를 사용하여 소켓에 주소를 할당. 
  구체적으로 AF_INET은 IPv4 주소 체계를 사용하는 것을 의미, 
  AF_INET6는 IPv6 인터넷 프로토콜을 의미
  INADDR_ANY는 서버가 모든 인터페이스의 IP 주소에 바인드 되어야 함을 의미, 
  포트 9090에 바인드. 바인딩이 실패할 경우 에러 메시지를 출력.
  */
  memset((char *) &server, 0, sizeof(server));
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = htonl(INADDR_ANY);
  server.sin_port = htons(9090);
  
  if(bind(sock, (struct sockaddr *)&server, sizeof(server)) < 0) 
    perror("ERROR on binding");
    
  // step 3
  /*
  무한 루프 안에서 서버는 클라이언트로부터 데이터를 수신. 
  recvfrom 함수는 클라이언트가 보낸 데이터를 버퍼에 저장, 
  데이터를 보낸 클라이언트의 주소 정보를 client 구조체에 저장. 
  받은 메시지는 화면에 출력. 버퍼의 크기를 하나 작게 설정하여 
  NULL 문자를 위한 공간을 확보하는 것을 주목.
  */
  while(1) {
    bzero(buf, 1500);
    recvfrom(sock, buf, 1500-1, 0, (struct sockaddr *)&client, &clientlen);
    printf(""%s\n", buf);
  }
  
  /*
  이 코드는 루프를 빠져나와 소켓을 닫는 경우에 사용. 
  그러나 위의 코드에서는 무한 루프가 있기 때문에 실제로 이 부분은 실행되지 않음. 
  프로그램을 종료하려면 외부에서 인터럽트를 보내거나 
  프로그램 내에서 조건을 통해 루프에서 빠져나오도록 구현이 필요.
  */

  close(sock);
}
