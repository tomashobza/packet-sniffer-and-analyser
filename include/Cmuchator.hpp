/**
 * @file Cmuchator.hpp
 * @author Tomáš Hobza <xhobza03@vutbr.cz>
 * @brief Header file for the Cmuchator class
 * @date 2024-04-21
 */

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
#include <vector>
#include <sstream>
#include <signal.h>           // for signal handling
#include <netinet/if_ether.h> // for reading Ethernet headers, ARP headers, etc.
#include <netinet/ip.h>       // for reading IPv4 headers
#include <netinet/ip6.h>      // for reading IPv6 headers
#include <netinet/tcp.h>      // for reading TCP headers
#include <netinet/udp.h>      // for reading UDP headers

/**
 * @brief Class to capture packets
 *
 */
class Cmuchator
{
    /** @brief The parsed options */
    SnifferOptions options;
    /** @brief The pcap handle */
    pcap_t *handle;
    /** @brief Instance of the class */
    static Cmuchator *inst;
    /** @brief The filter string */
    std::string filter;

public:
    Cmuchator(SnifferOptions options);
    ~Cmuchator();

    /**
     * @brief Add a filter to the filter string with the given operator
     *
     * @param filter the filter
     * @param op the operator
     */
    void addFilter(std::string filter, std::string op);

    /**
     * @brief Add the filters to the filter string
     *
     */
    void addFilters();

    /**
     * @brief Start capturing packets
     *
     */
    void loop();

    /**
     * @brief Print the packet data
     *
     * @param user the user data
     * @param header the packet header
     * @param packet the packet data
     */
    bool gotPacket(u_char *user, const struct pcap_pkthdr header, const u_char *packet);

    /**
     * @brief Print the packet timestamp
     *
     * @param timestamp
     */
    void printPacketTimestamp(timeval timestamp);

    /**
     * @brief Print the MAC addresses
     *
     * @param packet
     */
    void printMacAddresses(const u_char *packet);

    /**
     * @brief Print the IP addresses
     *
     * @param packet
     */
    void printIPAddresses(const u_char *packet);

    /**
     * @brief Print the port addresses
     *
     * @param packet
     */
    void printPortAddresses(const u_char *packet);

    /**
     * @brief Print the raw data
     *
     * @param packet
     * @param length
     */
    void printData(const u_char *packet, int length);

    /**
     * @brief Wrapper for the gotPacket method
     *
     * @param user the user data
     * @param header the packet header
     * @param packet the packet data
     */
    static void gotPacketWrapper(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);

    /**
     * @brief List the available interfaces
     *
     */
    static void listInterfaces();

    /**
     * @brief Handle a signal
     *
     * @param signal
     */
    static void handleSignal(int signal);
};

#endif // CMUCHATOR_H