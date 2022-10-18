#include <iostream>
#include <chrono>
#include "logging.hpp"
#include "../config.h"

namespace Logger
{
    unsigned long int get_current_time(){
        return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    }
    void log(LogLevel level, const std::string &message)
    {
        switch (level)
        {
        case DEBUG:
            if (!DEBUG_MODE)
                return;
            std::cout << get_current_time() << "[ DEBUG ] ";
            break;
        case INFO:
            std::cout << get_current_time() << "[ INFO ] ";
            break;
        case WARNING:
            std::cout << get_current_time() << "[ WARNING ] ";
            break;
        case ERROR:
            std::cout << get_current_time() << "[ ERROR ] ";
            break;
        default:
            return;
        }
        std::cout << message << std::endl;
    }
}