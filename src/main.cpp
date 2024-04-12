#include <iostream>

#include "types.hpp"
#include "ArgParser.hpp"
#include "Cmuchator.hpp"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    printf("Got a packet with length of [%d]\n", header->len);
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    SnifferOptions options;

    options = ArgParser::parse(argc, argv);

    if (options.help)
    {
        ArgParser::help();
    }

    if (!options.interfaceSpecified)
    {
        std::cout << "Interface not specified. Listing available interfaces:" << std::endl;
        Cmuchator::listInterfaces();
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(options.interface.data(), BUFSIZ, 1, 1000, errbuf);

    if (handle == nullptr)
    {
        fprintf(stderr, "Couldn't open device eth0: %s\n", errbuf);
        return 2;
    }

    pcap_loop(handle, options.num, got_packet, nullptr);

    pcap_close(handle);

    return EXIT_SUCCESS;
}