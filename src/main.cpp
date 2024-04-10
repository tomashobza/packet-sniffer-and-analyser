#include <iostream>

#include "types.hpp"
#include "ArgParser.hpp"

int main(int argc, char *argv[])
{
    SnifferOptions options = ArgParser::parse(argc, argv);

    return EXIT_SUCCESS;
}