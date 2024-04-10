#include "ArgParser.hpp"

SnifferOptions ArgParser::parse(int argc, char *argv[])
{
    SnifferOptions options;

    while (true)
    {
        static struct option long_options[] = {
            {"interface", required_argument, 0, 'i'},
            {"port-source", required_argument, 0, 's'},
            {"port-destination", required_argument, 0, 'd'},
            {"tcp", no_argument, 0, 't'},
            {"udp", no_argument, 0, 'u'},
            {"arp", no_argument, 0, 'a'},
            {"icmp4", no_argument, 0, '4'},
            {"icmp6", no_argument, 0, '6'},
            {"igmp", no_argument, 0, 'g'},
            {"mld", no_argument, 0, 'm'},
            {"n", required_argument, 0, 'n'},
            {0, 0, 0, 0}};
        int option_index = 0;

        int c = getopt_long(argc, argv, "i:p:tus:d:a46gmn:", long_options, &option_index);

        // Detect the end of the options.
        if (c == -1)
            break;

        switch (c)
        {
        case 'i':
            options.interface = optarg;
            options.interfaceSpecified = true;
            break;
        case 'p':
            options.port = std::stoi(optarg);
            break;
        case 't':
            options.tcp = true;
            break;
        case 'u':
            options.udp = true;
            break;
        case 's':
            options.portSource = std::stoi(optarg);
            break;
        case 'd':
            options.portDestination = std::stoi(optarg);
            break;
        case 'a':
            options.arp = true;
            break;
        case '4':
            options.icmp4 = true;
            break;
        case '6':
            options.icmp6 = true;
            break;
        case 'g':
            options.igmp = true;
            break;
        case 'm':
            options.mld = true;
            break;
        case 'n':
            options.num = std::stoi(optarg);
            break;
        case '?':
            break;
        default:
            abort();
        }
    }

    return options;
}