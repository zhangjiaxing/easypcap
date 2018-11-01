#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap/pcap.h>

#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define SNAPLEN (1024*1024)

void print_ether_host(const uint8_t ether_host[ETH_ALEN]){
     for(int i=0; i<ETH_ALEN; i++){
        uint8_t n = ether_host[i];
        printf("%02X", n);
     }
}

void udp_print(uint32_t caplen, const u_char *packet){
    if(caplen < sizeof(struct udphdr)){
        return;
    }
    struct udphdr *uh = (struct udphdr*)packet;
    printf("[UDP] src port: %u, ", ntohs(uh->uh_sport));
    printf("dst port: %u, ", ntohs(uh->uh_dport));
    printf("len: %u, ", ntohs(uh->uh_ulen));
}

void ip_print(uint32_t caplen, uint32_t length, const u_char *packet){
    if(caplen < sizeof (struct ip)){
        return;
    }

    struct iphdr *ip_ptr = (struct iphdr*)packet;
    ssize_t iphdr_size = sizeof(struct iphdr);
    ssize_t ip_header_len = ip_ptr->ihl * 4; // 4byte == 32bit

    if (ip_header_len < iphdr_size){
        return;
    }

    caplen -= ip_header_len;
    length -= ip_header_len;
    packet += ip_header_len;

    struct in_addr saddr = {
        .s_addr = ip_ptr->saddr
    };

    struct in_addr daddr = {
        .s_addr = ip_ptr->daddr
    };
    char ip_str[64];

    printf("[IP] protocol: %u, ", ip_ptr->protocol);
    printf("ttl: %d, ", ip_ptr->ttl);
    printf("src ip: %s, ", inet_ntop(AF_INET, &saddr, ip_str, 64));
    printf("dest ip: %s ", inet_ntop(AF_INET, &daddr, ip_str, 64));

    switch(ip_ptr->protocol){
        case IPPROTO_UDP:
            udp_print(caplen, packet);
            break;
        case IPPROTO_TCP:
            printf("[TCP] ======== , ");
            break;
        case IPPROTO_ICMP:
            printf("[ICMP] ========, ");
            break;
        default:
            break;

    }
}

void ethernet_print(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    static uint32_t count = 0;

    struct timeval ts = header->ts;
    bpf_u_int32 caplen = header->caplen;
    bpf_u_int32 length = header->len;

    if(caplen < ETHER_HDR_LEN){
        return;
    }

    count ++;
    const struct ether_header *ehp = (const struct ether_header *)packet;

    printf("[Ethernet] ");
    printf("MAC: ");
    print_ether_host(ehp->ether_shost);
    printf(" > MAC: ");
    print_ether_host(ehp->ether_dhost);
    printf(", ");

    caplen -= ETHER_HDR_LEN;
    length -= ETHER_HDR_LEN;
    packet += ETHER_HDR_LEN;

    switch(ntohs(ehp->ether_type)){
    case ETHERTYPE_IP:
        ip_print(caplen, length, packet);
        break;
    case ETHERTYPE_IPV6:
        printf("[IPV6] ");
        break;
    case ETHERTYPE_ARP:
        printf("[ARP] ");
        break;
    case ETHERTYPE_REVARP:
        printf("[RARP] ");
        break;
    case ETHERTYPE_VLAN:
        printf("[VLAN] ");
        break;
    case ETHERTYPE_LOOPBACK:
        printf("[LOOPBACK] ");
        break;
    default:
        break;
    }

    printf("count: %d\n", count);
}

int main(void){
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = pcap_lookupdev(errbuf);
    
    if(dev == NULL){
        printf("lookupdev error: %s", errbuf);
        exit(1);
    }

    
    pcap_t *handle = pcap_open_live(dev, SNAPLEN, 1, 1000, errbuf);
    if (handle == NULL){
        printf("open device error");
        exit(1);
    }

    int datalink_type = pcap_datalink(handle);
    const char *datalink_name = pcap_datalink_val_to_name(datalink_type);
    const char *datalink_desc = pcap_datalink_val_to_description(datalink_type);

    printf("datalink type: %s, description: %s\n", datalink_name, datalink_desc);

    if (datalink_type == DLT_EN10MB){ // Ethernet
        pcap_loop(handle, -1, ethernet_print, NULL);
    }

    pcap_close(handle);
    printf("%s", dev);
    return 0;
}
