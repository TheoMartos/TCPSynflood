#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <chrono>
#include <thread>

#define SOCKET_ERROR -1
#define PACKET_SIZE 4096

#define SRC_IP "192.168.0.100"
#define DST_IP "192.168.0.11"
#define SRC_PORT 25000
#define DST_PORT 8080

struct pseudo_header;

typedef int SOCKET;
typedef struct sockaddr SOCKADDR;
typedef struct sockaddr_in SOCKADDR_IN;
typedef struct iphdr IPHDR;
typedef struct tcphdr TCPHDR;
typedef struct pseudo_header PSD_HEADER;

void fill_ip_header(IPHDR *ip_header);
void fill_tcp_header(TCPHDR *tcp_header, size_t data_len);
unsigned short csum(unsigned short *ptr,int nbytes);