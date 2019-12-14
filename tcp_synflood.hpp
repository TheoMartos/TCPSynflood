#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <cstring>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define SOCKET_ERROR -1
#define PACKET_SIZE 4096
#define IP_SIZE sizeof("255.255.255.255")

// #define SRC_IP "192.168.0.18"
// #define DST_IP "192.168.0.11"
// #define SRC_PORT 25000
// #define DST_PORT 8080

struct pseudo_header;

typedef int SOCKET;
typedef struct sockaddr SOCKADDR;
typedef struct sockaddr_in SOCKADDR_IN;
typedef struct iphdr IPHDR;
typedef struct tcphdr TCPHDR;
typedef struct tcpopt TCPOPT;
typedef struct pseudo_header PSD_HEADER;

void exploit(unsigned int time_to_sleep, int packet_to_send);
void fill_ip_header(IPHDR *ip_header);
void fill_tcp_opt(TCPOPT* tcp_opt);
void fill_tcp_header(TCPHDR *tcp_header, TCPOPT* tcp_opt);
unsigned short checksum(unsigned short *buffer, int nb_bytes);
unsigned short get_rand();

struct pseudo_header
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
};

struct tcpopt
{
    unsigned char mms_knd;
    unsigned char mms_len;
    unsigned short mms_val;
    unsigned char nop_1;
    unsigned char ws_knd;
    unsigned char ws_len;
    unsigned char ws_val;
    unsigned char nop_2;
    unsigned char nop_3;
    unsigned char sck_knd;
    unsigned char sck_len;
};