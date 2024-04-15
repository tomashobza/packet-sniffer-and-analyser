#include <iostream>

#include "types.hpp"
#include "ArgParser.hpp"
#include "Cmuchator.hpp"

int main(int argc, char *argv[])
{
    signal(SIGINT, Cmuchator::handleSignal);

    // Read command line arguments
    SnifferOptions options = ArgParser::parse(argc, argv);

    // If help option is specified, print help message
    if (options.help)
    {
        ArgParser::help();
        return EXIT_SUCCESS;
    }

    // If interface is not specified, list available interfaces
    if (!options.interfaceSpecified)
    {
        std::cout << "Interface not specified. Listing available interfaces:" << std::endl;
        // List available interfaces
        Cmuchator::listInterfaces();
        return EXIT_SUCCESS;
    }

    // Create Cmuchator instance
    Cmuchator cmuchator(options);

    // Start packet sniffing
    cmuchator.loop();

    return EXIT_SUCCESS;
}