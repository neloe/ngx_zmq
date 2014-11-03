#include <zmq.hpp>
#include <iostream>
#include <string>

int main()
{
  zmq::context_t context(1);
  zmq::socket_t socket(context, ZMQ_REP);
  socket.bind("tcp://*:5555");
  while (true)
  {
    zmq::message_t request;
    socket.recv(&request);
    std::cout << "Received " << std::string((char*)request.data(), request.size()) << std::endl;
    zmq::message_t reply(5);
    memcpy ((void *) reply.data (), "World", 5);
    socket.send (reply);
    
  }
  return 0;
}
