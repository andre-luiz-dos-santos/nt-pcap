#include "net.h"

#include <netdb.h>
#include <stdio.h>
#include <unistd.h>

#include <cstring>
#include <system_error>

const uint8_t ipv6_zeros[16] = {0};

Socket::Socket(int family, int type, int protocol)
    : family(family), type(type), protocol(protocol) {
    this->fd = -1;
}

void Socket::open() {
    if (this->fd >= 0) {
        ::close(this->fd);
    }

    this->fd = ::socket(this->family, this->type, this->protocol);
    if (this->fd < 0) {
        throw std::system_error(errno, std::system_category(), "Error creating socket");
    }
}

void Socket::close() {
    if (this->fd >= 0) {
        ::close(this->fd);
        this->fd = -1;
    }
}

void Socket::connect(sockaddr *addr, socklen_t addr_size) {
    if (::connect(this->fd, addr, addr_size) < 0) {
        throw std::system_error(errno, std::system_category(), "Error connecting socket");
    }
}

void Socket::getsockname(sockaddr *addr, socklen_t *addr_size) {
    if (::getsockname(this->fd, addr, addr_size) < 0) {
        throw std::system_error(errno, std::system_category(), "Error getting socket name");
    }
}

void Socket::getsockname(sockaddr_in &addr) {
    socklen_t addr_size = sizeof(addr);
    this->getsockname((sockaddr *)&addr, &addr_size);
}

void Socket::getsockname(sockaddr_in6 &addr) {
    socklen_t addr_size = sizeof(addr);
    this->getsockname((sockaddr *)&addr, &addr_size);
}

uint32_t get_source_ip_to(uint32_t dst_ip4) {
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = dst_ip4;
    addr.sin_port = 0;

    Socket sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sock.open();
    sock.connect(addr);
    sock.getsockname(addr);
    return addr.sin_addr.s_addr;
}

void get_source_ip_to(uint8_t src_ip6[16], const uint8_t dst_ip6[16]) {
    sockaddr_in6 addr;
    addr.sin6_family = AF_INET6;
    memcpy(addr.sin6_addr.s6_addr, dst_ip6, 16);
    addr.sin6_port = 0;

    Socket sock(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    sock.open();
    sock.connect(addr);
    sock.getsockname(addr);
    memcpy(src_ip6, addr.sin6_addr.s6_addr, 16);
}

const char *ip_to_str(uint32_t ip4) {
    in_addr addr;
    addr.s_addr = ip4;
    return ip_to_str(addr);
}

const char *ip_to_str(in_addr &addr) {
    static char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, str, sizeof(str));
    return str;
}

const char *ip_to_str(const uint8_t ip6[16]) {
    in6_addr addr;
    memcpy(&addr, ip6, 16);
    return ip_to_str(addr);
}

const char *ip_to_str(in6_addr &addr) {
    static char str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &addr, str, sizeof(str));
    return str;
}

uint32_t str_to_ip4(std::string &str) {
    return str_to_ip4(str.c_str());
}

uint32_t str_to_ip4(const char *str) {
    in_addr addr;
    if (inet_pton(AF_INET, str, &addr) != 1) {
        throw std::runtime_error("Invalid IPv4 address: " + std::string(str));
    }
    return addr.s_addr;
}

void str_to_ip6(uint8_t ip6[16], std::string &str) {
    str_to_ip6(ip6, str.c_str());
}

void str_to_ip6(uint8_t ip6[16], const char *str) {
    in6_addr addr;
    if (inet_pton(AF_INET6, str, &addr) != 1) {
        throw std::runtime_error("Invalid IPv6 address: " + std::string(str));
    }
    memcpy(ip6, addr.s6_addr, 16);
}
