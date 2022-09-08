#ifndef __DCCLIENT_H
#define __DCCLIENT_H

#include "crypto.hpp"
#include "client_comm.hpp"

class DC_Client
{
public:
    DC_Client(const int64_t client_id);
    int dc_client_run();
    int thread_listen_server();

    int client_send_base_run();
    int client_get_req_run();

    Crypto crypto;
    ClientComm client_comm;
};

#endif // __DCCLIENT_H