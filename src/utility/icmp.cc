// SPDX-License-Identifier: MIT
#include "utility/icmp.h"
#include <iostream>
#include <spdlog/spdlog.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

namespace Candy {

#if defined(_WIN32) || defined(_WIN64)
// clang-format off
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
// clang-format on

void sendICMP(uint32_t ip) {
    // TODO: Windows 发送 ICMP 定向广播
}
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>

unsigned short checksum(unsigned short *data, int len) {
    unsigned long sum = 0;
    while (len > 1) {
        sum += *data++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(unsigned char *)data;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

void sendICMP(uint32_t ip) {
    static int id = 0;
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        spdlog::warn("icmp: socket");
        return;
    }

    int on = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0) {
        spdlog::warn("icmp: set broadcast");
        close(sockfd);
        return;
    }

    struct icmp *icmp = (struct icmp *)malloc(sizeof(struct icmp));
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_id = id++;
    icmp->icmp_seq = 0;

    icmp->icmp_cksum = checksum((unsigned short *)icmp, sizeof(struct icmp));

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = htonl(ip);

    int n = sendto(sockfd, icmp, sizeof(struct icmp), 0, (struct sockaddr *)&dest, sizeof(dest));
    if (n < 0) {
        spdlog::warn("icmp: send");
        close(sockfd);
        return;
    }

    close(sockfd);
}
#endif

} // namespace Candy
