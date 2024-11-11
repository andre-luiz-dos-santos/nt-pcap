#ifndef NET_H
#define NET_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cstdint>
#include <string>

extern const uint8_t ipv6_zeros[16];

class Socket {
public:
    int family;
    int type;
    int protocol;
    int fd;

    Socket(int family = 0, int type = 0, int protocol = 0);
    ~Socket() { close(); }

    void open();
    void close();

    void connect(sockaddr *addr, socklen_t addr_size);
    void connect(sockaddr_in &addr) { this->connect((sockaddr *)&addr, sizeof(addr)); }
    void connect(sockaddr_in6 &addr) { this->connect((sockaddr *)&addr, sizeof(addr)); }
    void getsockname(sockaddr *addr, socklen_t *addr_size);
    void getsockname(sockaddr_in &addr);
    void getsockname(sockaddr_in6 &addr);
};

uint32_t get_source_ip_to(uint32_t dst_ip4);
void get_source_ip_to(uint8_t src_ip6[16], const uint8_t dst_ip6[16]);

const char *ip_to_str(in_addr &addr);
const char *ip_to_str(in6_addr &addr);
const char *ip_to_str(uint32_t ip4);
const char *ip_to_str(const uint8_t ip6[16]);

uint32_t str_to_ip4(const char *str);
uint32_t str_to_ip4(std::string &str);
void str_to_ip6(uint8_t ip6[16], const char *str);
void str_to_ip6(uint8_t ip6[16], std::string &str);

#endif
