/**
 * @file types.hpp
 * @author Tomáš Hobza <xhobza03@vutbr.cz>
 * @brief Header file for the types
 * @date 2024-04-21
 */

#ifndef TYPES_H
#define TYPES_H

#include <string>
#include <pcap.h>

/**
 * @brief Struct to hold the parsed options
 *
 */
struct SnifferOptions
{
    std::string interface;    // Interface to capture on
    int port = -1;            // Filter by port
    bool tcp = false;         // Filter by TCP
    bool udp = false;         // Filter by UDP
    bool arp = false;         // Filter by ARP
    bool icmp4 = false;       // Filter by ICMPv4
    bool icmp6 = false;       // Filter by ICMPv6
    bool igmp = false;        // Filter by IGMP
    bool mld = false;         // Filter by MLD
    bool ndp = false;         // Filter by NDP
    int num = 1;              // Number of packets to capture
    int portSource = -1;      // Filter by source port
    int portDestination = -1; // Filter by destination port
    // Flags
    bool interfaceSpecified = false; // Interface was specified
    bool help = false;               // Help was requested
};

#endif // TYPES_H