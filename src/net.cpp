#include "net.h"

#include <netdb.h>
#include <stdio.h>
#include <unistd.h>

#include <cstring>
#include <system_error>

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

void Socket::connect(struct sockaddr *addr, socklen_t addr_size) {
    if (::connect(this->fd, addr, addr_size) < 0) {
        throw std::system_error(errno, std::system_category(), "Error connecting socket");
    }
}

void Socket::getsockname(struct sockaddr *addr, socklen_t *addr_size) {
    if (::getsockname(this->fd, addr, addr_size) < 0) {
        throw std::system_error(errno, std::system_category(), "Error getting socket name");
    }
}

void Socket::getsockname(struct sockaddr_in &addr) {
    socklen_t addr_size = sizeof(addr);
    this->getsockname((struct sockaddr *)&addr, &addr_size);
}

void Socket::getsockname(struct sockaddr_in6 &addr) {
    socklen_t addr_size = sizeof(addr);
    this->getsockname((struct sockaddr *)&addr, &addr_size);
}

uint32_t get_source_addr(uint32_t dst_addr) {
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = dst_addr;
    addr.sin_port = 0;

    Socket sock(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sock.open();
    sock.connect(addr);
    sock.getsockname(addr);
    return addr.sin_addr.s_addr;
}

void get_source_addr(char src_addr[16], const char dst_addr[16]) {
    struct sockaddr_in6 addr;
    addr.sin6_family = AF_INET6;
    memcpy(addr.sin6_addr.s6_addr, dst_addr, 16);
    addr.sin6_port = 0;

    Socket sock(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    sock.open();
    sock.connect(addr);
    sock.getsockname(addr);
    memcpy(src_addr, addr.sin6_addr.s6_addr, 16);
}
