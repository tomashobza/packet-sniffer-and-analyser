#ifndef ARG_PARSER_H
#define ARG_PARSER_H

#include <getopt.h>
#include <iostream>
#include <cstdlib>
#include "types.hpp"

class ArgParser
{
public:
    static SnifferOptions parse(int argc, char *argv[]);

    static void help();
};

#endif // ARG_PARSER_H