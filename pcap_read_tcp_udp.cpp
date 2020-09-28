#include <arpa/inet.h>
#include <net/ethernet.h> //ethernet
#include <netinet/ip.h> //ip
#include <netinet/tcp.h> //tcp
#include <netinet/udp.h> //udp
#include <cstdio>
#include <iostream>
#include <cstring>
#include <pcap.h> //pcap

using namespace std;

void dump_pkt(const u_char *pkt_data, struct pcap_pkthdr* header);

void usage(){
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]){
    if (argc != 2){
        usage();
        return -1;
    }

    char* dev = argv[1]; //argv[0]: file name, argv[1]: data
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(handle==nullptr){
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while(true){ //packet capture
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if(res==0) continue;
        if(res==-1 || res==-2){
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        dump_pkt(packet, header);
    }
    pcap_close(handle);    
}

void dump_pkt(const u_char *pkt_data, struct pcap_pkthdr* header){
    struct ether_header *eth_hdr = (struct ether_header *)pkt_data; //get ether_header from captured packet
    u_int16_t eth_type = ntohs(eth_hdr->ether_type); //get ether_type from eth_header

    //if type is not IP, return function
    if(eth_type!=ETHERTYPE_IP) return;

    struct ip *ip_hdr = (struct ip *)(pkt_data+sizeof(ether_header)); //ip header struct

    u_int8_t ip_type = ip_hdr->ip_p; //get ip type from ip header
    u_int8_t ip_offset = ip_hdr->ip_hl; //get ip offset

    printf("\nIP Packet Info====================================\n");

    //print pkt length
    printf("%u bytes captured\n", header->caplen); //captured header len

    //print mac addr
    u_int8_t *dst_mac = eth_hdr->ether_dhost; //dst mac addr
    u_int8_t *src_mac = eth_hdr->ether_shost; //src mac addr

    printf("Dst MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
        dst_mac[0],dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);

    printf("Src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
        src_mac[0],src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
    
    //print ip addr
    char src_ip[16], dst_ip[16];
    char* tmp = inet_ntoa(ip_hdr->ip_src); //get src ip from ip header
    strcpy(src_ip, tmp);
    tmp = inet_ntoa(ip_hdr->ip_dst);
    strcpy(dst_ip, tmp);

    printf("Src IP : %s\n", src_ip);
    printf("Dst IP : %s\n", dst_ip);

    //print payload
    u_int32_t payload_len = header->caplen - sizeof(ether_header) - ip_offset*4;
    u_int32_t max = payload_len >= 16 ? 16 : payload_len; //get 16bytes
    const u_char* pkt_payload = pkt_data + sizeof(ether_header)+ip_offset*4;
    printf("Payload : ");

    if(!payload_len){
        printf("No payload\n");
    }else{
        for(int i=0;i<max;i++) printf("%02x ", *(pkt_payload+i));
        printf("\n");
    }
    
    
    if(ip_hdr->ip_p == IPPROTO_TCP){
        printf("\nThis is TCP Packet====================\n");
        struct tcphdr *tcp_hdr = (struct tcphdr *)(pkt_data+ip_hdr->ip_hl*4); //TCP header

        //SHOW IP TCP INfo
        printf("Src Port : %d\n", ntohs(tcp_hdr->source));
        printf("Dst Port : %d\n", ntohs(tcp_hdr->dest));
    }
    else if(ip_hdr->ip_p == IPPROTO_UDP){
        printf("\nThis is UDP Packet====================\n");
        struct udphdr *udp_hdr = (struct udphdr *)(pkt_data+ip_hdr->ip_hl*4); //UDP header

        //SHOW IP TCP INfo
        printf("Src Port : %d\n", ntohs(udp_hdr->source));
        printf("Dst Port : %d\n", ntohs(udp_hdr->dest));
    }
}
