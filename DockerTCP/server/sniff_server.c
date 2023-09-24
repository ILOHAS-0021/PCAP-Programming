#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <sys/socket.h>
#include "myheader.h"

void print_mac_address(u_char *mac_address)
{
    for (int i = 0; i < 6; i++)
    {
        printf("%02X", mac_address[i]);
        if (i < 5) printf(":");
    }
    printf("\n");
}

void print_ip_address(struct in_addr ip_address)
{
    printf("%s\n", inet_ntoa(ip_address));
}

void print_tcp_payload(const u_char *packet, int offset, int length)
{
    printf("Message: \n   ");
    for (int i = 0; i < length && i < 20; i++)
    {
        char byte = packet[offset + i];
        if (isprint(byte))
        {
            printf("%c", byte);
        }
        else
        {
            printf(".");
        }
    }
    printf("\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800)
    {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        if (ip->iph_protocol == IPPROTO_TCP)
        {
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));

            printf("Ethernet Header:\n");
            printf("   Source MAC: ");
            print_mac_address(eth->ether_shost);
            printf("   Destination MAC: ");
            print_mac_address(eth->ether_dhost);

            printf("IP Header:\n");
            printf("   Source IP: ");
            print_ip_address(ip->iph_sourceip);
            printf("   Destination IP: ");
            print_ip_address(ip->iph_destip);

            printf("TCP Header:\n");
            printf("   Source Port: %d\n", ntohs(tcp->tcp_sport));
            printf("   Destination Port: %d\n", ntohs(tcp->tcp_dport));

            int payload_offset = sizeof(struct ethheader) + sizeof(struct ipheader) + TH_OFF(tcp) * 4;
            int payload_length = ntohs(ip->iph_len) - sizeof(struct ipheader) - TH_OFF(tcp) * 4;

            if (payload_length > 0)
            {
                print_tcp_payload(packet, payload_offset, payload_length);
            }

            printf("\n");
        }
    }
}

void server_run()
{
    int server_socket, client_socket;
    struct sockaddr_in server_address, client_address;
    socklen_t client_address_len = sizeof(client_address);
    char server_message[1024];

    server_socket = socket(AF_INET, SOCK_STREAM, 0);

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(8888);
    server_address.sin_addr.s_addr = INADDR_ANY;

    bind(server_socket, (struct sockaddr *)&server_address, sizeof(server_address));

    listen(server_socket, 1);
}

int main()
{
    server_run();

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0)
    {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);

    return 0;
}
