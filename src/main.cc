#include "config.h"
#include "capsule.pb.h"

#include <cstdlib>
#include <iostream>
#include <netinet/in.h> 
#include <sys/socket.h> 
#include <unistd.h> 

/* Admin Server */

int run_admin_server() {
  /*
  Setup:
  1. Register with multicast tree
  2. Start thread for listening for data server connection 
  3. Start thread for failure recovery  (v2 Todo)
  */

  return 0;
}

/* Data Server */

int data_server_setup() {
  /* 
  Setup:
  1. Leader election (v2 Todo)
  2. Register with admin
  2.1 Get Leader's address from admin
  3. Register with multicast tree
  4. Initiate a on-disk database (a hashtable is enough for v1)
  5. Start listening for multicast message
  */
  return 0;
}

void handle_msg(std::string msg) {
  // capsule::CapsulePDU in_dc;
  // in_dc.ParseFromString(msg);

}

int data_server_handle() {
  /*
  Data Server Handling:
  1. Receive a mcast msg (i.e. a record)
  2. Decrypt (if needed)
  2. Recompute its hash & verify signature
  3. Find its parent using prevHash
  4. Append it to its parent & store on disk
  5. send signed ack to leader
  */
  return 0;
}

int data_server_leader_handle() {
  /*
  Leader Ack Handling:
  1. Listen for acks from followers
  2. Verify ack signature
  3. Store in a on-memory hashtable
  4. When a threshold of acks is reached, send threshold signature back to client
  */
  return 0;
}

int run_data_server() {
  // Data Server Setup
  data_server_setup();

  // Data Server Handle
  data_server_handle();

  // Leader Ack Handle
  data_server_leader_handle();

  return 0;
}

int thread_start_listen_mcast() {
  // Create a socket (IPv4, TCP)
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd == -1) {
    std::cout << "Failed to create socket. errno: " << errno << std::endl;
    exit(EXIT_FAILURE);
  }

  // Listen to port 9999 on any address
  sockaddr_in sockaddr;
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_addr.s_addr = INADDR_ANY;
  sockaddr.sin_port = htons(9999); // htons is necessary to convert a number to
                                   // network byte order
  if (bind(sockfd, (struct sockaddr*)&sockaddr, sizeof(sockaddr)) < 0) {
    std::cout << "Failed to bind to port 9999. errno: " << errno << std::endl;
    exit(EXIT_FAILURE);
  }

  // Start listening. Hold at most 10 connections in the queue
  if (listen(sockfd, 10) < 0) {
    std::cout << "Failed to listen on socket. errno: " << errno << std::endl;
    exit(EXIT_FAILURE);
  }

  // Grab a connection from the queue
  auto addrlen = sizeof(sockaddr);
  int connection = accept(sockfd, (struct sockaddr*)&sockaddr, (socklen_t*)&addrlen);
  if (connection < 0) {
    std::cout << "Failed to grab connection. errno: " << errno << std::endl;
    exit(EXIT_FAILURE);
  }

  // Read from the connection
  char buffer[100];
  auto bytesRead = read(connection, buffer, 100);
  std::cout << "The message was: " << buffer;

  // Send a message to the connection
  std::string response = "Good talking to you\n";
  send(connection, response.c_str(), response.size(), 0);

  // Close the connections
  close(connection);
  close(sockfd);

  return 0;
}

int main(int argc, char *argv[]) {
  /*
  1. start admin server thread
  2. start data server threads
  */

  return 0;
}