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
    printf("Got a packet with length of [%d]\n", header->len);
}

void Cmuchator::listInterfaces()
{
    std::string command = "ifconfig | grep -oE '^[a-zA-Z0-9]+:' | tr -d ':'";

    std::array<char, 128> buffer;
    std::string result;

    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
    if (!pipe)
    {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
    {
        result += buffer.data();
    }
    std::cout << result;
}