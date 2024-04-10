#ifndef TYPES_H
#define TYPES_H

#include <string>

struct SnifferOptions
{
    std::string interface;
    int port = -1; // Default value indicating no port specified
    bool tcp = false;
    bool udp = false;
    bool arp = false;
    bool icmp4 = false;
    bool icmp6 = false;
    bool igmp = false;
    bool mld = false;
    int num = 1; // Default value indicating to display only one packet
    int portSource = -1;
    int portDestination = -1;
};

#endif // TYPES_H