#include "Cmuchator.hpp"

Cmuchator::Cmuchator(SnifferOptions options)
{
    this->options = options;

    char errbuf[PCAP_ERRBUF_SIZE];
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

    std::cout << "Got a packet" << std::endl;

    printPacketTimestamp(header->ts);

    printMacAddresses(packet);

    std::cout << "Frame length: " << (int)header->len << std::endl;

    printIPAddresses(packet);

    // TODO: print packet source port
    // TODO: print packet destination port

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
    struct tm *utc_tm = std::gmtime(&rawtime);
    int timezone_offset = (local_tm->tm_hour - utc_tm->tm_hour) * 60 + (local_tm->tm_min - utc_tm->tm_min);

    // Format timezone offset
    char sign = (timezone_offset >= 0) ? '+' : '-';
    timezone_offset = std::abs(timezone_offset);
    int offset_hours = timezone_offset / 60;
    int offset_minutes = timezone_offset % 60;
    time_stream << sign << std::setfill('0') << std::setw(2) << offset_hours << ":"
                << std::setfill('0') << std::setw(2) << offset_minutes;

    // Print the formatted timestamp
    std::cout << "Timestamp: " << time_stream.str() << std::endl;
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
        struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);

        std::cout << "src IP: " << inet_ntoa(ip_header->ip_src) << std::endl;
        std::cout << "dst IP: " << inet_ntoa(ip_header->ip_dst) << std::endl;

        break;
    }
    case ETHERTYPE_IPV6:
    {
        struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet + ETHER_HDR_LEN);

        char src_ip_str[INET6_ADDRSTRLEN];
        char dst_ip_str[INET6_ADDRSTRLEN];

        inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip_str, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip_str, INET6_ADDRSTRLEN);

        std::cout << "src IP: " << src_ip_str << std::endl;
        std::cout << "dst IP: " << dst_ip_str << std::endl;

        break;
    }
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