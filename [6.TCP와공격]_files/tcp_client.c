#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

int main()
{
  // step 1: create a socket
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);

  // step 2: set the destination information
  struct sockaddr_in dest;
  memset(&dest, 0, sizeof(struct sockaddr_in));
  dest.sin_family = AF_INET;
  dest.sin_addr.s_addr = inet_addr("10.9.0.5");
  dest.sin_port = htons(9090);

  // step 3: connect to the server
  connect(sockfd, (struct sockaddr *)&dest, sizeof(struct sockaddr_in));

  // step 4: send data to the server
  char *buffer1 = "Hello Server!\n";
  char *buffer2 = "Hello Again!\n";

  write(sockfd, buffer1, strlen(buffer1));
  write(sockfd, buffer2, strlen(buffer2));

  // step 5: close the connection
  close(sockfd);
  return 0;
}
