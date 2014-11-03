#include <zmq.hpp>
#include <iostream>
#include <string>

int main()
{
  zmq::context_t context(1);
  zmq::socket_t socket(context, ZMQ_PULL);
  socket.bind("tcp://*:5556");
  while (true)
  {
    zmq::message_t request;
    socket.recv(&request);
    std::cout << "Received " << std::string((char*)request.data(), request.size()) << std::endl;    
  }
  return 0;
}
