#ifndef NET_H
#define NET_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cstdint>

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

    void connect(struct sockaddr *addr, socklen_t addr_size);
    void connect(struct sockaddr_in &addr) { this->connect((struct sockaddr *)&addr, sizeof(addr)); }
    void connect(struct sockaddr_in6 &addr) { this->connect((struct sockaddr *)&addr, sizeof(addr)); }
    void getsockname(struct sockaddr *addr, socklen_t *addr_size);
    void getsockname(struct sockaddr_in &addr);
    void getsockname(struct sockaddr_in6 &addr);
};

uint32_t get_source_addr(uint32_t dst_addr);
void get_source_addr(char src_addr[16], const char dst_addr[16]);

#endif
