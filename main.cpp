#include <iostream>
#include <thread>
#include <wsio.h>

int main()
{
    wscurl::wsio_t ws;
    ws
        // lambda callbacks
        .on_event(
            [](wscurl::event_t ev, const std::string &info)
            {
                switch (ev) {
                case wscurl::event_t::CONNECT_EV:
                    std::cerr << "I -> connected info: " << info << std::endl;
                    break;
                case wscurl::event_t::DISCONNECT_EV:
                    std::cerr << "I -> disconnected reason: " << info << std::endl;
                    break;
                case wscurl::event_t::ERROR_EV:
                    std::cerr << "E -> " << info << std::endl;
                    break;
                }
            }
            )
        .on_message_binary(
            [](const std::vector<uint8_t> &data)
            {
                std::cerr << "D -> " << data.size() << " bytes, chars: " << std::string((const char*)data.data(), data.size()) << std::endl;
            }
            )
        .on_header(
            [](const std::string &hdr_name, const std::string &hdr_val)
            {}
            );

    struct S { // struct with callbacks
        void message_cb(const std::string &msg) {
            std::cerr << "S:message_cb -> " << msg << std::endl;
        }
    } struct_callback;

    ws.on_message_text<S, &S::message_cb>(&struct_callback);

    // sync mode
    if(ws.start("wss://ws.vi-server.org/mirror", "", false)) {
        ws.write("Hello world!");
        ws.read();
        ws.write(std::vector<uint8_t>{'B','y','e',' ','w','o','r','l','d','!'});
        ws.read();
    }
    ws.stop();

    // async mode
    if(ws.start("wss://ws.vi-server.org/mirror")) {
        ws.write("Hello world!");
        std::this_thread::sleep_for(std::chrono::seconds(1));
        ws.write("Bye world!");
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    ws.stop();

    return 0;
}
