#include "ArgParser.hpp"

SnifferOptions ArgParser::parse(int argc, char *argv[])
{
    SnifferOptions options = {
        .interface = "",
        .port = -1,
        .tcp = false,
        .udp = false,
        .arp = false,
        .icmp4 = false,
        .icmp6 = false,
        .igmp = false,
        .mld = false,
        .num = 1,
        .portSource = -1,
        .portDestination = -1,
        .interfaceSpecified = false,
        .help = false};

    struct option longOptions[] = {
        {"interface", required_argument, nullptr, 'i'},
        {"tcp", no_argument, nullptr, 't'},
        {"udp", no_argument, nullptr, 'u'},
        {"port", required_argument, nullptr, 'p'},
        {"port-source", required_argument, nullptr, 1},
        {"port-destination", required_argument, nullptr, 2},
        {"arp", no_argument, nullptr, 3},
        {"icmp4", no_argument, nullptr, 4},
        {"icmp6", no_argument, nullptr, 5},
        {"igmp", no_argument, nullptr, 6},
        {"mld", no_argument, nullptr, 7},
        {"ndp", no_argument, nullptr, 8},
        {"n", required_argument, nullptr, 'n'},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0}};

    int optionIndex = 0;
    int opt = 0;
    while ((opt = getopt_long(argc, argv, "i:p:tun:h", longOptions, &optionIndex)) != -1)
    {
        switch (opt)
        {
        case 'i':
            options.interface = optarg;
            options.interfaceSpecified = true;
            break;
        case 't':
            options.tcp = true;
            break;
        case 'u':
            options.udp = true;
            break;
        case 'p':
            options.port = std::atoi(optarg);
            break;
        case 1: // port-source
            options.portSource = std::atoi(optarg);
            break;
        case 2: // port-destination
            options.portDestination = std::atoi(optarg);
            break;
        case 3: // arp
            options.arp = true;
            break;
        case 4: // icmp4
            options.icmp4 = true;
            break;
        case 5: // icmp6
            options.icmp6 = true;
            break;
        case 6: // igmp
            options.igmp = true;
            break;
        case 7: // mld
            options.mld = true;
            break;
        case 8: // ndp
            options.ndp = true;
            break;
        case 'n':
            options.num = std::atoi(optarg);
            break;
        case 'h':
            options.help = true;
            break;
        case '?':
            // Unrecognized option
            break;
        default:
            std::cerr << "Unknown option: " << char(opt) << std::endl;
            break;
        }
    }

    return options;
}

// TODO: check port arguments valid only with tcp or udp arguments
// TODO: check port specification validity

void ArgParser::help()
{
    std::cout << "Usage: ./ipk-sniffer [-i interface | --interface interface] {-p|--port-source|--port-destination port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num} [--help|-h]" << std::endl;
}
