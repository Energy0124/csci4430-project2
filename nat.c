#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>    // for inet_pton()
#include <errno.h>    // for "errno"
#include <string.h>    // for strerror()
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include "checksum.h"


#define MAX_NAT_TABLE_SIZE 2001


// Global variables
struct sockaddr_in public_addr;
struct sockaddr_in internal_addr;
char *subnet_mask;
int original_port[MAX_NAT_TABLE_SIZE]; // -1 is unused
int translated_port[MAX_NAT_TABLE_SIZE];
in_addr_t original_IP[MAX_NAT_TABLE_SIZE];
int used_port_count = 0; //max = 20001

//assumes little endian
void printBits(size_t const size, void const *const ptr) {
    unsigned char *b = (unsigned char *) ptr;
    unsigned char byte;
    int i, j;

    for (i = size - 1; i >= 0; i--) {
        for (j = 7; j >= 0; j--) {
            byte = (b[i] >> j) & 1;
            printf("%u", byte);
        }
    }
    puts("");
}

void print_mapping(in_addr_t o_IP, int o_port, char *s_IP, int s_port) {
    struct in_addr o_ip_struct;
    o_ip_struct.s_addr = o_IP;
    printf("Original source IP address: %s\n", inet_ntoa(o_ip_struct));
    printf("Original source port: %d\n", o_port);
    printf("Translated source IP address: %s\n", s_IP);
    printf("Translated source port : %d\n", s_port);
}

void print_table() {
    printf("nat table:\n");
    int i;
    for (i = 0; i < used_port_count; ++i) {
        printf("Entry : %d\n", i);

        struct in_addr o_ip_struct;
        o_ip_struct.s_addr = original_IP[i];
        printf("Original source IP address: %s\n", inet_ntoa(o_ip_struct));
        printf("Original source port: %d\n", original_port[i]);
        printf("Translated source IP address: %s\n", inet_ntoa(public_addr.sin_addr));
        printf("Translated source port : %d\n", translated_port[i]);
    }

}


static int Callback(struct nfq_q_handle *qh, struct nfgenmsg *msg,
                    struct nfq_data *pkt, void *data) {
    int i;
    unsigned int id = 0;
    int shouldDrop = false;

    struct nfqnl_msg_packet_hdr *header;
    struct nfqnl_msg_packet_hw *hwph;


    // print hw_protocol, hook and id

    printf("\n");
    if ((header = nfq_get_msg_packet_hdr(pkt))) {
        id = ntohl(header->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
               ntohs(header->hw_protocol), header->hook, id);
    }

    // print hw_address

    hwph = nfq_get_packet_hw(pkt);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);
        printf("hw_src_addr=");
        for (i = 0; i < hlen - 1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen - 1]);
    }

    // Print the payload;

    printf("\n[");
    unsigned char *pktData;
    int len = nfq_get_payload(pkt, (char **) &pktData);
    if (len > 0) {
        for (i = 0; i < len; i++) {
            printf("%02x ", pktData[i]);
        }
    }
    printf("]\n");

    // Get IP header
    struct iphdr *iph = (struct iphdr *) pktData;

    char *saddr = inet_ntoa(*(struct in_addr *) &iph->saddr);
    fprintf(stdout, "before source=%s; ", saddr);

    char *daddr = inet_ntoa(*(struct in_addr *) &iph->daddr);
    fprintf(stdout, "destination=%s}\n", daddr);



    //do thing only when protocol == tcp
    if (iph->protocol == IPPROTO_TCP) {

        struct tcphdr *tcph = NULL;
        // Get TCP header
        tcph = (struct tcphdr *) (((char *) iph) + (iph->ihl << 2));


        uint16_t sport, dport;           /* Source and destination ports */



        int mask_int = atoi(subnet_mask);
        int local_mask = 0xffffffff << (32 - mask_int);
        //    printf("mask_int: \n");
        //    printBits(sizeof(mask_int), &mask_int);
        //
        //    printf("local_mask: \n");
        //    printBits(sizeof(local_mask), &local_mask);


        unsigned int local_network = ntohl(internal_addr.sin_addr.s_addr) & local_mask;
        //    printf("local_network: \n");
        //    printBits(sizeof(local_network), &local_network);
        //    char temp_str[INET_ADDRSTRLEN];
        //    inet_ntop(AF_INET, &(internal_addr.sin_addr), temp_str, INET_ADDRSTRLEN);
        //    printf("local network: %s\n",temp_str);
        sport = ntohs(tcph->source);
        dport = ntohs(tcph->dest);
        //change tcp header
        //    iph->saddr= internal_addr.sin_addr.s_addr;
        //    tcph->source=htons(10000);//fix hard code source port



        int tempip = ntohl(iph->saddr);
        //    printf("source ip: \n");
        //    printBits(sizeof(tempip), &tempip);
        tempip = ntohl(iph->saddr) & local_mask;
        //    printf("source ip&local_mask: \n");
        //    printBits(sizeof(tempip), &tempip);

        if ((ntohl(iph->saddr) & local_mask) == local_network) {
            // outbound traffic
            printf("this is outbound\n");


            // NAT port entries checking
            int port = 0;
            int counter = 0;
            int found = 0;

            // First check is the source IP already in NAT table
            while (counter < MAX_NAT_TABLE_SIZE) {
                if (original_port[counter] == sport) {
                    port = 10000 + counter;
                    found = 1;
                    break;
                }

                counter++;

            }

            counter = 0;
            // If not, create entry and print map update
            if (!found) {
                while (counter < MAX_NAT_TABLE_SIZE) {

                    if (original_port[counter] == -1) {
                        port = 10000 + counter;
                        original_port[counter] = sport;
                        original_IP[counter] = iph->saddr;
                        translated_port[counter] = port;
                        print_mapping(original_IP[counter], original_port[counter], inet_ntoa(public_addr.sin_addr),
                                      translated_port[counter]);
                        used_port_count++;
                        break;
                    }

                    counter++;
                }
            }

            // replace source port of every outgoing datagram to NAT IP address, new port
            //todo: remove hard code
            //port =10100;
            tcph->source = htons(port);
            printf("port:%d dest:%d\n", ntohs(tcph->source), dport);
            iph->saddr = public_addr.sin_addr.s_addr;

            saddr = inet_ntoa(*(struct in_addr *) &iph->saddr);
            fprintf(stdout, "after change address=%s; \n", saddr);
        } else {
            // inbound traffic
            printf("this is inbound\n");
            printf("Inbound~~~~~~~~~~!!!!!!!\n");
            printf("Inbound~~~~~~~~~~!!!!!!!\n");
            printf("Inbound~~~~~~~~~~!!!!!!!\n");
            printf("Inbound~~~~~~~~~~!!!!!!!\n");
            printf("Inbound~~~~~~~~~~!!!!!!!\n");
            int port = dport - 10000;
            // port exist
            if (port >= 0 && original_port[port] != -1) {
                tcph->dest = htons(original_port[port]);

            } else {
                printf("port is not in table!\n");
            }
            printf("port:%d dest:%d\n", sport, dport);
            iph->daddr = original_IP[port];


            daddr = inet_ntoa(*(struct in_addr *) &iph->daddr);
            fprintf(stdout, "after change address=%s; \n", daddr);
        }

        // TCP packets
        /*    if (iph->protocol == IPPROTO_TCP) {
                printf("");
            }*/
        print_table();
        //recal tcp cksum
        printf("ocheck: %d\n", iph->check);
        tcph->check = 0;
        iph->check = 0;

        tcph->check = tcp_checksum(pktData);
        iph->check = ip_checksum(pktData);
        struct iphdr *iph2 = (struct iphdr *) pktData;
        printf("ncheck: %d\n", iph2->check);

    } else { //not tcp should drop
        shouldDrop = true;
    }



    // for the first 20 packeks, a packet[id] is accept, if
    // accept[id-1] = 1.
    // All packets with id > 20, will be accepted
    if (!shouldDrop) {


        printf("\nACCEPT\n");
        return nfq_set_verdict(qh, id, NF_ACCEPT, len, pktData);


    } else {
        printf("\nDROP\n");
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }

}

/*
 * Main program
 */
int main(int argc, char **argv) {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int len;
    char buf[4096];

    if (argc != 4) {
        printf("Three argument expected.\n");
        exit(-1);
    } else {
        int i;
        for (i = 0; i < MAX_NAT_TABLE_SIZE; i++) {
            original_port[i] = -1; /* initialize to -1*/
            translated_port[i] = -1;
            original_IP[i] = 0;
        }
        if (inet_pton(AF_INET, (const char *) argv[1], &public_addr.sin_addr) == 0) {
            fprintf(stderr, "%s (line %d): %s - inet_pton():\n", __FILE__, __LINE__, __FUNCTION__);
            fprintf(stderr, "\tError message: Wrong public IP address format\n");
            exit(1);
        }

        if (inet_pton(AF_INET, (const char *) argv[2], &internal_addr.sin_addr) == 0) {
            fprintf(stderr, "%s (line %d): %s - inet_pton():\n", __FILE__, __LINE__, __FUNCTION__);
            fprintf(stderr, "\tError message: Wrong internal IP address format\n");
            exit(1);
        }

        subnet_mask = argv[3];

        // Open library handle
        if (!(h = nfq_open())) {
            fprintf(stderr, "Error: nfq_open()\n");
            exit(-1);
        }

        // Unbind existing nf_queue handler (if any)
        if (nfq_unbind_pf(h, AF_INET) < 0) {
            fprintf(stderr, "Error: nfq_unbind_pf()\n");
            exit(1);
        }

        // Bind nfnetlink_queue as nf_queue handler of AF_INET
        if (nfq_bind_pf(h, AF_INET) < 0) {
            fprintf(stderr, "Error: nfq_bind_pf()\n");
            exit(1);
        }

        // bind socket and install a callback on queue 0
        if (!(qh = nfq_create_queue(h, 0, &Callback, NULL))) {
            fprintf(stderr, "Error: nfq_create_queue()\n");
            exit(1);
        }

        // Setting packet copy mode
        if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
            fprintf(stderr, "Could not set packet copy mode\n");
            exit(1);
        }

        fd = nfq_fd(h);

        while ((len = recv(fd, buf, sizeof(buf), 0)) && len >= 0) {
            nfq_handle_packet(h, buf, len);

        }

        printf("unbinding from queue 0\n");
        nfq_destroy_queue(qh);

        nfq_close(h);

    }

    return 0;

}

