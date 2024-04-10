#ifndef CMUCHATOR_H
#define CMUCHATOR_H

#include "types.hpp"
#include <pcap.h>
#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>

class Cmuchator
{
public:
    Cmuchator();
    ~Cmuchator();

    static void listInterfaces();
};

#endif // CMUCHATOR_H