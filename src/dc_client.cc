#include <string>

#include "dc_client.hpp"
#include "util/logging.hpp"

DC_Client::DC_Client() {}

int DC_Client::dc_client_run()
{
    /* DC Client */
    Logger::log(LogLevel::INFO, "DC_Client running");
    
    /* 
    Incoming base case:
     1. create several dummy dc's
     2. sign and encrypt the dc's
     3. send dc's via network to all dc servers
    */

    /*
    Outgoing base case:
     1. open a reply port to wait for acks
     2. receive all acks from all dc servers
     3. decrypt and verify all acks
    */

    /* 
    Incoming optimization #1 - mcast:
     1. create several dummy dc's
     2. sign and encrypt the dc's
     3. send dc's via network to proxy port
     4. proxy mcast dc's to dc servers
     5. dc servers verify signatures
    */

    /* 
    Outgoing optimization #1 - one ack:
     1. dc servers sign their acks
     2. proxy receives acks from all dc servers
     3. proxy verifies all acks
     4. proxy creates a threshold signature 
     5. proxy sends back to client
     6. client decrypt and verify the ack
    */

    /* 
    Incoming optimization #2 - hmac & proxy in enclave:
     1. create several dummy dc's
     2. sign and encrypt the dc's
     3. send dc's via network to proxy port
     4. proxy verifies signatures
     5. proxy mcast dc's to dc servers via hmac
     6. dc servers do not verify because of hmac & proxy is trustworthy
    */

   /* 
    Outgoing optimization #2 - hmac & proxy in enclave:
     1. dc servers do not sign because of hmac & proxy is trustworthy
     2. proxy receives acks from all dc servers via hmac
     3. proxy creates a signature 
     4. proxy sends back to client
     5. client decrypt and verify the ack
    */

    return 0;
}