#include <iostream>
#include "logging.hpp"
#include "../config.h"

namespace Logger
{
    void log(LogLevel level, const std::string &message)
    {
        switch (level)
        {
        case DEBUG:
            if (!DEBUG_MODE)
                return;
            std::cout << "[ DEBUG ] ";
            break;
        case INFO:
            std::cout << "[ INFO ] ";
            break;
        case WARNING:
            std::cout << "[ WARNING ] ";
            break;
        case ERROR:
            std::cout << "[ ERROR ] ";
            break;
        default:
            return;
        }
        std::cout << message << std::endl;
    }
}