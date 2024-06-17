/*
이 프로그램은 기본적인 패킷 캡처 기능을 수행하며, 
"icmp" 필터를 사용하여 ICMP 패킷만 캡처. 
캡처된 패킷이 있을 때마다 단순히 "Got a packet" 메시지를 출력. 
실제 응용 프로그램에서는 got_packet 함수에서 더 복잡한 패킷 처리 로직을 구현
*/

/*
표준 라이브러리(stdlib.h, stdio.h)와 
패킷 캡처 라이브러리(pcap.h)를 포함
*/
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h> 

/*
패킷이 캡처될 때 호출되는 콜백 함수.
패킷이 캡처되면 "Got a packet"이라는 메시지를 출력.
args, header, packet은 각각 추가 인자, 패킷 헤더, 패킷 데이터를 의미
*/
void got_packet(u_char *args, const struct pcap_pkthdr *header, 
                              const u_char *packet) 
{ 
  printf("Got a packet\n");
}

int main() 
{ 
  pcap_t *handle;
  // pcap 세션 핸들을 저장하는 포인터
   
  char errbuf[PCAP_ERRBUF_SIZE]; 
  // 오류 메시지를 저장하기 위한 버퍼
  
  struct bpf_program fp; 
  // 필터 프로그램을 저장하는 구조체
  
  char filter_exp[] = "icmp";
  // 필터 표현식. 이 경우 ICMP 패킷을 필터링
  
  bpf_u_int32 net = 0;
  // 네트워크 주소를 저장할 변수

  // Step 1: Open live pcap session on NIC with interface name
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
  /*
  "enp0s3" 인터페이스에서 라이브 패킷 캡처 세션 오픈.
  BUFSIZ는 버퍼 크기를, 1은 프로미스큐어스 모드 설정을, 1000은 타임아웃을 표시.
  errbuf는 오류 메시지를 저장.
  */
  
  // Step 2: Compile filter_exp into BPF psuedo-code 
  pcap_compile(handle, &fp, filter_exp, 0, net);
  // filter_exp를 BPF(버클리 패킷 필터) 가상 코드로 컴파일. 
  if(pcap_setfilter(handle, &fp) != 0) {
    pcap_perror(handle, "Error: ");
    exit(EXIT_FAILURE);
  }
  /*
  컴파일된 필터를 handle에 설정. 
  설정 실패 시 오류 메시지를 출력하고 프로그램을 종료.
  */
  
  // Step 3: Capture packets 
  pcap_loop(handle, -1, got_packet, NULL);
  /*
  pcap_loop 함수로 무한히 패킷을 캡처. 
  (두 번째 인자 -1은 무한 캡처를 의미.)
  캡처된 패킷이 있을 때마다 got_packet 콜백 함수가 호출
  */


  pcap_close(handle); //Close the handle 
  // pcap 세션을 종료하고 자원을 해제
  return 0;
}
