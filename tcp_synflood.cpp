#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <netinet/in.h>

#define SOCKET_ERROR -1
#define ETH_PACKET_SIZE 65536

typedef int SOCKET;
typedef struct sockaddr SOCKADDR;
typedef struct sockaddr SOCKADDR;
typedef struct sockaddr_in SOCKADDR_IN;
typedef struct iphdr IPHDR;
typedef struct tcphdr TCPHDR;

using namespace std;

int main(int argc, char *argv[])
{
    char packet[ETH_PACKET_SIZE];
    IPHDR* ip_header = (IPHDR*)packet;
    TCPHDR* tcp_header = (TCPHDR*)((unsigned char*)ip_header + sizeof(tcp_header));
    char new_ip[sizeof("255.255.255.255")];

    SOCKET socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    int app_exit_code = 0;
    
    if (socket_fd == SOCKET_ERROR)
    {
        printf("Socket creation failed.\n");

        app_exit_code = -1;
    }
    else
    {
        printf("socket ok\n");
    }

    return app_exit_code;
}