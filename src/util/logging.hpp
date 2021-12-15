#ifndef __LOGGING_H
#define __LOGGING_H

enum LogLevel
{
    DEBUG,
    INFO,
    WARNING,
    ERROR
};

namespace Logger
{
    void log(LogLevel level, const std::string &message);
};

#endif // __LOGGING_H