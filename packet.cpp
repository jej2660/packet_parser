//
//  main.cpp
//  packaet_parger
//
//  Created by jjw on 2020/07/23.
//  Copyright © 2020 jjw. All rights reserved.
//

#include <pcap.h>
#include <stdio.h>
#include <libnet.h>
#include <netinet/in.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

void Slice(uint32_t source_ip, uint32_t dest_ip){//ip 를 보기 좋게 자름
    printf("Source_ip: %d.%d.%d.%d\tDest_ip: %d.%d.%d.%d\n", (source_ip & 0xFF000000) >> 24, (source_ip & 0x00FF0000) >> 16, (source_ip & 0x0000FF00) >> 8, (source_ip & 0x000000FF), (dest_ip & 0xFF000000) >> 24, (dest_ip & 0x00FF0000) >> 16, (dest_ip & 0x0000FF00) >> 8, (dest_ip & 0x000000FF));
}
//1111 1111 0000 0000 0000
//1011 0011 1110 1111 1111

void Print_ether_info(const u_char *source){
    struct libnet_ethernet_hdr *eth = (libnet_ethernet_hdr *)source;
    printf("Source_mac: %02x:%02x:%02x:%02x:%02x:%02x\tDest_mac: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_shost[0],eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5], eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
}

int Print_ip_info(const u_char *source){
    struct libnet_ipv4_hdr *ipv = (libnet_ipv4_hdr *)source;
    Slice(ntohl(ipv->ip_src.s_addr), ntohl(ipv->ip_dst.s_addr));
    //printf("ipv4_header_len: %d\n", ipv->ip_hl *4);
    return ipv->ip_hl * 4;
}

int Print_tcp_info(const u_char *source){
    struct libnet_tcp_hdr *tcp = (libnet_tcp_hdr *)source;
    printf("Source_port: %d\tDest_port: %d\n", ntohs(tcp->th_sport), ntohs(tcp->th_dport));
    //printf("TCP_header_len: %d\n", tcp->th_off *4);
    return tcp->th_off * 4;
}

void Print_payload_info(const u_char *source){//16바이트 데이터 출력
    for(int i = 0;i <= 15;i++){
        printf("%02x ", *source);
        source++;
    }
    printf("\nComplete!!\n\n");
}

void Print_info(const u_char *source, int len){
    int pos = 0;
    libnet_ipv4_hdr *ipv = (libnet_ipv4_hdr *)(source+14);
    if(ipv->ip_p != 6) return;//프로토콜을 확인하여 tcp 인지 아닌지 판단
    Print_ether_info(source);
    pos = Print_ip_info(source + 14);
    pos += Print_tcp_info(source + 14 + pos);
    //printf("POS:   %d\n", pos);
    //printf("DATA:    %02x\n", *(source + 14 + pos));
    if(pos + 14 != len){//L5 데이터가 있는지 없는지 판단
        Print_payload_info(source + 14 + pos);
    }
    else{
        printf("No Applicationlayer data\n");
        printf("Complete!!\n\n");
    }
    /*
    struct libnet_ethernet_hdr *eth = (libnet_ethernet_hdr *)source;
    struct libnet_ipv4_hdr *ipv = (libnet_ipv4_hdr *)source;
    struct libnet_tcp_hdr *tcp = (libnet_tcp_hdr *)source;
    printf("Source_mac: %02x:%02x:%02x:%02x:%02x:%02x\tDest_mac: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_shost[0],eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5], eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    Slice(ntohl(ipv->ip_src.s_addr), ntohl(ipv->ip_dst.s_addr));
    //Slice(ipv->ip_src.s_addr, ipv->ip_dst.s_addr);
    printf("Source_port: %d\tDest_port: %d\n\n", tcp->th_sport, tcp->th_dport);
    //printf("dasdadas %d", ipv->ip_hl);//내일 여기서부터 수정해 그 해더 렌스 길이가 제대로 출력 안됨
    printf("Ip_header_len: %d\t Tcp_header_len: %d\n",ipv->ip_hl,tcp->th_off);
    printf("%c",source[14 + ipv->ip_hl + tcp->th_off]);
     */
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL){
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        Print_info(packet, header->caplen);
        //printf("%u bytes captured\n", header->caplen);
    }
    pcap_close(handle);
}
