/**
 * @file ArgParser.hpp
 * @author Tomáš Hobza <xhobza03@vutbr.cz>
 * @brief Header file for the ArgParser class
 * @date 2024-04-21
 */

#ifndef ARG_PARSER_H
#define ARG_PARSER_H

#include <getopt.h>
#include <iostream>
#include <cstdlib>
#include "types.hpp"

/**
 * @brief Class to parse the command line arguments
 *
 */
class ArgParser
{
public:
    /**
     * @brief Parse the command line arguments
     *
     * @param argc number of arguments
     * @param argv arguments
     * @return SnifferOptions - the parsed options
     */
    static SnifferOptions parse(int argc, char *argv[]);

    /**
     * @brief Print the help message
     *
     */
    static void help();
};

#endif // ARG_PARSER_H