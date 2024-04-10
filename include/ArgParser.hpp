#ifndef ARG_PARSER_H
#define ARG_PARSER_H

#include <getopt.h>
#include "types.hpp"

class ArgParser
{
public:
    static SnifferOptions parse(int argc, char *argv[]);
};

#endif // ARG_PARSER_H