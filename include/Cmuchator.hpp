#ifndef CMUCHATOR_H
#define CMUCHATOR_H

#include "types.hpp"
#include <pcap.h>
#include <cstdio>
#include <iostream>
#include <iomanip>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <sstream>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

class Cmuchator
{
    SnifferOptions options;
    pcap_t *handle;

public:
    Cmuchator(SnifferOptions options);
    ~Cmuchator();

    void loop();

    static void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

    static void printPacketTimestamp(timeval timestamp);

    static void listInterfaces();
};

#endif // CMUCHATOR_H