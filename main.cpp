#include <iostream>
#include "websocketio.h"
#include <thread>

int main()
{
    WebSocketIO ws("wss://echo.websocket.org", "chat",
                   [](const std::string &err){ // Error callback
                       std::cerr << "E -> " << err << std::endl;
                   }, [&](const std::string &data){ // Answer callback
                       std::cerr << "D -> " << data << std::endl;
                   }, false /*no async*/);
    if(ws.start()) {
        ws.write("Hello world!");
        std::this_thread::sleep_for(std::chrono::seconds(2));
        ws.write("Bye world!");
    }
    ws.stop();
    return 0;
}
