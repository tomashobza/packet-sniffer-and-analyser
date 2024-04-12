#include "Cmuchator.hpp"

Cmuchator::Cmuchator(SnifferOptions options)
{
    this->options = options;

    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(options.interface.c_str(), BUFSIZ, 1, 1000, errbuf);

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
    pcap_loop(handle, options.num, Cmuchator::got_packet, nullptr);
}

void Cmuchator::got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    std::cout << "Got a packet" << std::endl;
    // TODO: print packet timestamp
    printPacketTimestamp(header->ts);
    // TODO: print packet source MAC address

    // TODO: print packet destination MAC address
    // TODO: print packet frame length
    // TODO: print packet source IP address
    // TODO: print packet destination IP address
    // TODO: print packet source port
    // TODO: print packet destination port
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