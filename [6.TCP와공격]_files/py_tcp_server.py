#!/bin/env python3

# 이 프로그램은 클라이언트와 연결을 수락하고, 데이터를 수신하며, 
# 받은 데이터를 확인한 후 응답 메시지를 보내는 기본적인 TCP 서버의 역할을 수행

# 소켓 통신을 하기 위해 파이썬의 내장 모듈인 socket을 임포트
import socket

# IPv4 주소 체계 (AF_INET)와 TCP 소켓 (SOCK_STREAM)을 사용하는 소켓 객체를 생성
tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# 소켓을 0.0.0.0의 IP 주소와 포트 9090에 바인딩
# 0.0.0.0 은 모든 네트워크 인터페이스에서의 연결을 수신 대기한다는 의미
tcp.bind(("0.0.0.0", 9090))

#  소켓을 수신 대기 상태로 설정합니다. 기본적으로 하나의 연결만 대기
tcp.listen()

# 클라이언트로부터의 연결을 수락하고, 연결된 소켓 (conn)과 클라이언트의 주소 (addr)를 반환
conn, addr = tcp.accept()

# conn 객체와 함께 컨텍스트 매니저를 사용하여 연결을 처리. 
# 연결이 끝나면 자동으로 소켓이 close.
with conn:
  print('connected by ', addr)
  while True:
    data = conn.recv(1024)
    if not data:
      break
    print(data)
    conn.sendall(b"Got the data!\n")
