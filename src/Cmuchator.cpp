#include "Cmuchator.hpp"

Cmuchator::Cmuchator(SnifferOptions options)
{
    this->options = options;

    char errbuf[PCAP_ERRBUF_SIZE];
    // TODO: add arguments to pcap_open_live
    handle = pcap_open_live(options.interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    pcap_set_promisc(handle, 1);

    if (handle == nullptr)
    {
        throw std::runtime_error(errbuf);
    }

    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        throw std::runtime_error("Device does not provide Ethernet headers - not supported");
    }
}

Cmuchator::~Cmuchator()
{
    pcap_close(handle);
}

void Cmuchator::loop()
{
    int i = 0;
    while (i < options.num)
    {
        struct pcap_pkthdr header;
        const u_char *packet;

        packet = pcap_next(handle, &header);
        if (packet == nullptr)
        {
            std::cerr << "Failed to capture a packet" << std::endl;
            pcap_close(handle);
            return;
        }

        if (got_packet(&header, packet))
        {
            i++;
        }
    }
}

bool Cmuchator::got_packet(const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ether_header *eth_header = (struct ether_header *)packet;
    if (htons(eth_header->ether_type) != ETHERTYPE_IPV6)
    {
        return false;
    }

    printPacketTimestamp(header->ts);

    printMacAddresses(packet);

    std::cout << "frame length: " << (int)header->len << std::endl;

    printIPAddresses(packet);

    printPortAddresses(packet);

    std::cout << std::endl;

    return true;
}

void Cmuchator::printPacketTimestamp(timeval timestamp)
{
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
    struct ether_header *eth_header = (struct ether_header *)packet;

    switch (htons(eth_header->ether_type))
    {
    case ETHERTYPE_IP:
    {
        std::cout << "ethernet type: IPv4" << std::endl;
        struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);

        std::cout << "src IP: " << inet_ntoa(ip_header->ip_src) << std::endl;
        std::cout << "dst IP: " << inet_ntoa(ip_header->ip_dst) << std::endl;

        break;
    }
    case ETHERTYPE_IPV6:
    {
        std::cout << "ethernet type: IPv6 " << std::endl;
        struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet + ETHER_HDR_LEN);

        char src_ip_str[INET6_ADDRSTRLEN];
        char dst_ip_str[INET6_ADDRSTRLEN];

        inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip_str, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip_str, INET6_ADDRSTRLEN);

        std::cout << "src IP: " << src_ip_str << std::endl;
        std::cout << "dst IP: " << dst_ip_str << std::endl;

        break;
    }
    case ETHERTYPE_ARP:
    {
        std::cout << "ethernet type: ARP" << std::endl;
        struct ether_arp *arp_header = (struct ether_arp *)(packet + ETHER_HDR_LEN);

        char src_ip_str[INET_ADDRSTRLEN];
        char dst_ip_str[INET_ADDRSTRLEN];

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
    struct ether_header *eth_header = (struct ether_header *)packet;

    const u_short eth_type = htons(eth_header->ether_type);

    switch (eth_type)
    {
    case ETHERTYPE_IP:
    {
        struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);

        const u_char protocol = ip_header->ip_p;

        switch (protocol)
        {
        case IPPROTO_TCP:
        {
            std::cout << "protocol: TCP" << std::endl;
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + ETHER_HDR_LEN + (ip_header->ip_hl << 2));

            std::cout << "src port: " << ntohs(tcp_header->th_sport) << std::endl;
            std::cout << "dst port: " << ntohs(tcp_header->th_dport) << std::endl;

            break;
        }
        case IPPROTO_UDP:
        {
            std::cout << "protocol: UDP" << std::endl;
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
        struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet + ETHER_HDR_LEN);

        const u_char protocol = ip6_header->ip6_nxt;

        switch (protocol)
        {
        case IPPROTO_TCP:
        {
            std::cout << "protocol: TCP" << std::endl;
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + ETHER_HDR_LEN + sizeof(struct ip6_hdr));

            std::cout << "src port: " << ntohs(tcp_header->th_sport) << std::endl;
            std::cout << "dst port: " << ntohs(tcp_header->th_dport) << std::endl;

            break;
        }
        case IPPROTO_UDP:
        {
            std::cout << "protocol: UDP" << std::endl;
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