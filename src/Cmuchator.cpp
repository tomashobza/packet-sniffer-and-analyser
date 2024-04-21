/**
 * @file Cmuchator.cpp
 * @author Tomáš Hobza <xhobza03@vutbr.cz>
 * @brief Implementation of the Cmuchator class
 * @date 2024-04-21
 */

#include "Cmuchator.hpp"

Cmuchator *Cmuchator::inst = nullptr; // Initialize the instance to nullptr

Cmuchator::Cmuchator(SnifferOptions options)
{
    // Check if there is already an instance of Cmuchator
    if (inst != nullptr)
    {
        throw std::runtime_error("Only one instance of Cmuchator is allowed");
    }

    // Set the instance to this
    Cmuchator::inst = this;

    // Set the options
    this->options = options;

    // If the interface is empty, throw an error
    if (options.interface.empty())
    {
        throw std::runtime_error("Invalid or empty network interface name");
    }

    // Open the network interface
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(options.interface.c_str(), 65536, 1, 1000, errbuf);
    // Check if the handle is valid
    if (handle == nullptr)
    {
        // Print the error message and throw an error
        throw std::runtime_error(errbuf);
    }

    // Set the interface to promiscuous mode
    pcap_set_promisc(handle, 1);
    // Set the datalink type to Ethernet
    pcap_set_datalink(handle, DLT_EN10MB); // LINKTYPE_ETHERNET

    // Check if the device provides Ethernet headers
    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        throw std::runtime_error("Device does not provide Ethernet headers - not supported");
    }

    // Add the filters
    addFilters();
}

Cmuchator::~Cmuchator()
{
    // Close the handle
    pcap_close(handle);
}

void Cmuchator::addFilter(std::string filter, std::string op = "or")
{
    // If the filter is empty, set it to the new filter
    if (this->filter.empty())
    {
        // Set the filter to the new filter
        this->filter = filter;
    }
    else
    {
        // Append the new filter to the existing filter
        this->filter += " " + op + " " + filter;
    }
}

void Cmuchator::addFilters()
{
    filter = "";                      // Filter string
    std::vector<std::string> filters; // Vector of filters

    // Add the filters based on the options
    if (options.tcp || options.udp)
    {
        std::string filter = "(("; // Open the protocol filter
        if (options.tcp)
        {
            filter += "tcp";
        }
        if (options.udp)
        {
            if (options.tcp)
            {
                filter += " or ";
            }
            filter += "udp";
        }

        filter += ")"; // Close the protocol filter

        if (options.port != -1)
        {
            filter += " and port " + std::to_string(options.port);
        }
        if (options.portSource != -1)
        {
            filter += " and src port " + std::to_string(options.portSource);
        }
        if (options.portDestination != -1)
        {
            filter += " and dst port " + std::to_string(options.portDestination);
        }

        filter += ")";             // Close the protocol and port filter
        filters.push_back(filter); // Add the filter to the vector
    }

    if (options.arp)
    {
        filters.push_back("arp"); // Add the ARP filter
    }
    if (options.icmp4)
    {
        filters.push_back("icmp"); // Add the ICMPv4 filter
    }
    if (options.icmp6)
    {
        filters.push_back("icmp6"); // Add the ICMPv6 filter
    }
    if (options.igmp)
    {
        filters.push_back("igmp"); // Add the IGMP filter
    }
    if (options.mld)
    {
        // Add the MLD filter
        filters.push_back("(icmp6 and ip6[40] >= 130 and ip6[40] <= 132)");
    }
    if (options.ndp)
    {
        // Add the NDP filter
        filters.push_back("(icmp6 and ip6[40] >= 133 and ip6[40] <= 137)");
    }

    // Add the filters to the filter string
    for (std::string filter : filters)
    {
        addFilter(filter);
    }

    // Compile the filter
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        std::cerr << "Failed to compile filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        throw std::runtime_error("Filter compilation failed");
    }

    // Set the filter
    if (pcap_setfilter(handle, &fp) == -1)
    {
        std::cerr << "Failed to set filter: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        throw std::runtime_error("Filter setting failed");
    }
}

void Cmuchator::loop()
{
    // Loop through packets and call Cmuchator::inst->gotPacket for each one
    pcap_loop(
        handle, options.num, Cmuchator::gotPacketWrapper,
        nullptr);
}

bool Cmuchator::gotPacket(u_char *user, const struct pcap_pkthdr header, const u_char *packet)
{
    (void)user;

    // Print the packet timestamp
    printPacketTimestamp(header.ts);

    // Print the MAC addresses
    printMacAddresses(packet);

    // Print the IP addresses
    std::cout << "frame length: " << (int)header.len << std::endl;

    // Print the MAC addresses
    printIPAddresses(packet);

    // Print the port addresses
    printPortAddresses(packet);

    // Print the raw data
    printData(packet, header.len);

    // Print a newline
    std::cout << std::endl;

    return true;
}

void Cmuchator::printPacketTimestamp(timeval timestamp)
{
    // Convert the timestamp to a struct tm
    struct tm *packet_tm = std::gmtime(&(timestamp.tv_sec));

    // Create a stringstream to format the time
    std::stringstream time_stream;
    time_stream << std::put_time(packet_tm, "%Y-%m-%dT%H:%M:%S");

    // Add milliseconds
    int milliseconds = timestamp.tv_usec / 1000;
    time_stream << '.' << std::setfill('0') << std::setw(3) << milliseconds;

    // Get timezone offset
    std::time_t rawtime;
    std::time(&rawtime);
    struct tm *local_tm = std::localtime(&rawtime);
    int hours = local_tm->tm_hour;
    int minutes = local_tm->tm_min;
    struct tm *utc_tm = std::gmtime(&rawtime);
    int timezone_offset = (hours - utc_tm->tm_hour) * 60 + (minutes - utc_tm->tm_min);

    // Format timezone offset
    char sign = (timezone_offset >= 0) ? '+' : '-';
    timezone_offset = std::abs(timezone_offset);
    int offset_hours = timezone_offset / 60;
    int offset_minutes = timezone_offset % 60;
    time_stream << sign << std::setfill('0') << std::setw(2) << offset_hours << ":"
                << std::setfill('0') << std::setw(2) << offset_minutes;

    // Print the formatted timestamp
    std::cout << "timestamp: " << time_stream.str() << std::endl;
}

void Cmuchator::printMacAddresses(const u_char *packet)
{
    // Point eth_header to the start of the Ethernet header
    struct ether_header *eth_header = (struct ether_header *)packet;

    // Print the source MAC address
    std::cout << "src MAC: ";
    for (int i = 0; i < ETHER_ADDR_LEN; i++)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)eth_header->ether_shost[i];
        if (i < 5)
        {
            std::cout << ":";
        }
    }
    std::cout << std::endl;

    // Print the destination MAC address
    std::cout << "dst MAC: ";
    for (int i = 0; i < ETHER_ADDR_LEN; i++)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)eth_header->ether_dhost[i];
        if (i < 5)
        {
            std::cout << ":";
        }
    }
    std::cout << std::endl;

    std::cout << std::dec;
}

void Cmuchator::printIPAddresses(const u_char *packet)
{
    // Point eth_header to the start of the Ethernet header
    struct ether_header *eth_header = (struct ether_header *)packet;

    // Check the Ethernet type
    switch (htons(eth_header->ether_type))
    {
    case ETHERTYPE_IP:
    {
        std::cout << "ethernet type: IPv4" << std::endl;
        // Point ip_header to the start of the IP header
        struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);

        std::cout << "src IP: " << inet_ntoa(ip_header->ip_src) << std::endl;
        std::cout << "dst IP: " << inet_ntoa(ip_header->ip_dst) << std::endl;

        break;
    }
    case ETHERTYPE_IPV6:
    {
        std::cout << "ethernet type: IPv6 " << std::endl;
        // Point ip6_header to the start of the IPv6 header
        struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet + ETHER_HDR_LEN);

        char src_ip_str[INET6_ADDRSTRLEN];
        char dst_ip_str[INET6_ADDRSTRLEN];

        // Convert the source and destination IP addresses to strings
        inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip_str, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip_str, INET6_ADDRSTRLEN);

        std::cout << "src IP: " << src_ip_str << std::endl;
        std::cout << "dst IP: " << dst_ip_str << std::endl;

        break;
    }
    case ETHERTYPE_ARP:
    {
        std::cout << "ethernet type: ARP" << std::endl;
        // Point arp_header to the start of the ARP header
        struct ether_arp *arp_header = (struct ether_arp *)(packet + ETHER_HDR_LEN);

        char src_ip_str[INET_ADDRSTRLEN];
        char dst_ip_str[INET_ADDRSTRLEN];

        // Convert the source and destination IP addresses to strings
        inet_ntop(AF_INET, arp_header->arp_spa, src_ip_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, arp_header->arp_tpa, dst_ip_str, INET_ADDRSTRLEN);

        std::cout << "src IP: " << src_ip_str << std::endl;
        std::cout << "dst IP: " << dst_ip_str << std::endl;

        break;
    }
    default:
        std::cerr << "Unsupported Ethernet type" << std::endl;
        break;
    }
}

void Cmuchator::printPortAddresses(const u_char *packet)
{
    // Point eth_header to the start of the Ethernet header
    struct ether_header *eth_header = (struct ether_header *)packet;

    // Check the Ethernet type
    const u_short eth_type = htons(eth_header->ether_type);

    // Check the Ethernet type
    switch (eth_type)
    {
    case ETHERTYPE_IP:
    {
        // Point ip_header to the start of the IP header
        struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);

        // Get the protocol
        const u_char protocol = ip_header->ip_p;

        // Based on the protocol, print the ports
        switch (protocol)
        {
        case IPPROTO_TCP:
        {
            std::cout << "protocol: TCP" << std::endl;
            // Point tcp_header to the start of the TCP header
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + ETHER_HDR_LEN + (ip_header->ip_hl << 2));

            std::cout << "src port: " << ntohs(tcp_header->th_sport) << std::endl;
            std::cout << "dst port: " << ntohs(tcp_header->th_dport) << std::endl;

            break;
        }
        case IPPROTO_UDP:
        {
            std::cout << "protocol: UDP" << std::endl;
            // Point udp_header to the start of the UDP header
            struct udphdr *udp_header = (struct udphdr *)(packet + ETHER_HDR_LEN + (ip_header->ip_hl << 2));

            std::cout << "src port: " << ntohs(udp_header->uh_sport) << std::endl;
            std::cout << "dst port: " << ntohs(udp_header->uh_dport) << std::endl;

            break;
        }
        default:
            // ICMP and IGMP do not have ports
            break;
        }
        break;
    }
    case ETHERTYPE_IPV6:
    {
        // Point ip6_header to the start of the IPv6 header
        struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet + ETHER_HDR_LEN);

        // Get the protocol
        const u_char protocol = ip6_header->ip6_nxt;

        // Based on the protocol, print the ports
        switch (protocol)
        {
        case IPPROTO_TCP:
        {
            std::cout << "protocol: TCP" << std::endl;
            // Point tcp_header to the start of the TCP header
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + ETHER_HDR_LEN + sizeof(struct ip6_hdr));

            std::cout << "src port: " << ntohs(tcp_header->th_sport) << std::endl;
            std::cout << "dst port: " << ntohs(tcp_header->th_dport) << std::endl;

            break;
        }
        case IPPROTO_UDP:
        {
            std::cout << "protocol: UDP" << std::endl;
            // Point udp_header to the start of the UDP header
            struct udphdr *udp_header = (struct udphdr *)(packet + ETHER_HDR_LEN + sizeof(struct ip6_hdr));

            std::cout << "src port: " << ntohs(udp_header->uh_sport) << std::endl;
            std::cout << "dst port: " << ntohs(udp_header->uh_dport) << std::endl;

            break;
        }
        default:
            // ICMPv6 does not have ports

            break;
        }
        break;
    }
    default:
        // ARP does not have ports
        break;
    }
}

void Cmuchator::printData(const u_char *packet, int length)
{
    // Point data to the start of the packet data
    const u_char *data = packet;

    // Get the length of the data
    int data_length = length;

    // For each 16 bytes of data, print the data in hex and ASCII
    for (int offset = 0; offset < data_length; offset += 16)
    {
        // Print the offset
        std::cout << "0x" << std::hex << std::setw(4) << std::setfill('0') << offset << ": ";

        // Get the actual length of this line
        int this_line_length = std::min(16, data_length - offset);

        // Print the data in hex
        for (int i = 0; i < this_line_length; i++)
        {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[offset + i] << " ";
        }

        // Print the padding
        for (int i = this_line_length; i < 16; i++)
        {
            std::cout << "   ";
        }

        std::cout << " ";

        // Print the data in ASCII
        for (int i = 0; i < this_line_length; i++)
        {
            char byte = data[offset + i];
            if (byte > 31 && byte < 127)
            {
                std::cout << byte;
            }
            else
            {
                std::cout << ".";
            }

            if (i == 7)
            {
                std::cout << " ";
            }
        }

        std::cout << std::endl;
    }
}

void Cmuchator::gotPacketWrapper(u_char *user, const struct pcap_pkthdr *header, const u_char *packet)
{
    // Call the gotPacket method of the instance
    Cmuchator::inst->gotPacket(user, *header, packet);
}

void Cmuchator::listInterfaces()
{
    char errbuf[PCAP_ERRBUF_SIZE]; // Buffer to hold error text
    pcap_if_t *alldevs;            // Pointer to first network interface

    // Fetch the list of network devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        throw std::runtime_error("pcap_findalldevs() failed!");
    }

    // Iterate over the list of devices and print their names
    for (pcap_if_t *dev = alldevs; dev != nullptr; dev = dev->next)
    {
        std::cout << dev->name << std::endl;
    }

    // Free the device list
    pcap_freealldevs(alldevs);
}

void Cmuchator::handleSignal(int signal)
{
    // Handle the SIGINT signal
    if (signal == SIGINT)
    {
        std::cout << "Received SIGINT signal. Exiting..." << std::endl;
        pcap_breakloop(Cmuchator::inst->handle);
        pcap_close(Cmuchator::inst->handle);
        exit(EXIT_SUCCESS);
    }
}
