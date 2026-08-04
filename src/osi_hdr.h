#ifndef PCAP_TEST_H
#define PCAP_TEST_H

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806

#define MAC_SIZE 6
#define IPv4_SIZE 4

#include <pcap.h>
#include "mac.h"
#include "ip.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

static inline void print_mac(const uint8_t *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

#pragma pack(push, 1)

struct Eth_Hdr{
    Mac dhost;
    Mac shost;
    uint16_t type;
};

enum Arp_Operation : uint16_t {
    ARP_REQUEST = 1,
    ARP_REPLY = 2
};

struct Arp_Hdr{
    uint16_t hrd;        //하드웨어 타입
    uint16_t p;          //프로토콜 타입
    uint8_t hln;         //하드웨어 주소 길이
    uint8_t pln;         //프로토콜 주소 길이
    uint16_t op;        //연산 코드

    Mac smac;     //출발지 MAC 주소
    Ip sip;        //출발지 IP 주소
    Mac dmac;     //목적지 MAC 주소
    Ip dip;        //목적지 IP 주소
};

struct IP_Hdr{
    uint8_t ver;        //버전 (상위 4비트 + IHL)
    uint8_t     tos;    //서비스 타입
    uint16_t    len;    //전체 길이
    uint16_t    id;     //식별자
    uint16_t    off;    // 단편화 오프셋
    uint8_t     ttl;    //생존시간
    uint8_t     p;      //상위 프로토콜 번호
    uint16_t    csum;    //헤더 체크썸

    Ip sip;
    Ip dip;
};

struct TCP_Hdr{
    uint16_t    sport;     //출발지 포트 번호
    uint16_t    dport;     //목적지 포트 번호
    uint32_t seq;          // 시퀀스 번호
    uint32_t ack;          // 확인 응답 번호
    uint8_t x2;            //예약
    uint8_t off;           //데이터 오프셋(4바이트 단위)
    uint8_t     flags;     //플래그(FIN, SYN, RST, PSH, ACK, URG)
    uint16_t    win;       //윈도우 크기
    uint16_t    csum;      //체크썸
    uint16_t    urp;       //urg 포인터(긴급)
};

#pragma pack(pop)

#endif // PCAP_TEST_H