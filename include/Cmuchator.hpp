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
#include <signal.h>           // for signal handling
#include <netinet/if_ether.h> // for reading Ethernet headers, ARP headers, etc.
#include <netinet/ip.h>       // for reading IPv4 headers
#include <netinet/ip6.h>      // for reading IPv6 headers
#include <netinet/tcp.h>      // for reading TCP headers
#include <netinet/udp.h>      // for reading UDP headers

class Cmuchator
{
    SnifferOptions options;
    pcap_t *handle;
    static Cmuchator *inst;
    std::string filter;

public:
    Cmuchator(SnifferOptions options);
    ~Cmuchator();

    void addFilter(std::string filter, std::string op);
    void addFilters();

    void loop();

    bool gotPacket(const struct pcap_pkthdr *header, const u_char *packet);

    void printPacketTimestamp(timeval timestamp);
    void printMacAddresses(const u_char *packet);
    void printIPAddresses(const u_char *packet);
    void printPortAddresses(const u_char *packet);
    void printData(const u_char *packet, int length);

    static void listInterfaces();
    static void handleSignal(int signal);
};

#endif // CMUCHATOR_H