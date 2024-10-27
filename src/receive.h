#ifndef RECEIVE_H
#define RECEIVE_H

#include <pcap.h>

#include <string>

class Receiver {
private:
    pcap_t *handle;
    int datalink;
    int iph_offset;

public:
    std::string dev;

    void open();
    void loop();
    void receive(const struct pcap_pkthdr *pkthdr, const u_char *packet);
};

#endif
