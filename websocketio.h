#ifndef WEBSOCKETIO_H
#define WEBSOCKETIO_H
#include <functional>
#include <iomanip>
#include <thread>
#include <curl/curl.h>
#define USER_AGENT "ws-curl-library/0.2"
#define CURL_TIMEOUT 5//000
#define CURL_ASYNC_TIMEOUT_MS 100
#define WS_VERSION 13
#define VERIFYSSL 0
#include "wsocketframes.h"

struct ResponseInfo {
    bool valid = false;
    bool connect_error = false;
    std::string accept_header;
    WSocketFrames resframe;
    std::vector<unsigned char> buf;
};

struct ConnectionInfo {
    CURL *curl;
    ResponseInfo resp;
    bool valid;
    bool ssl;
    std::string host;
    std::string path;
    std::string protocol;
    std::string origin;
    std::string guid;
    unsigned char ws_accept[20];
    ConnectionInfo(const std::string &uri, const std::string &protocol);
    std::string get_key();
    std::string get_uri();
    std::string get_origin();
    std::string get_protocol();
    void print(const std::string &prefix);
};

class WebSocketIO
{
    ConnectionInfo conn;

    bool async;
    std::thread async_thread;

    std::function<void(std::string)> error_cb;
    std::function<void(std::string)> data_cb;

    bool recv_wait();

    const static std::string accept_header;
    const static std::string response_code_header;

    static void default_error_cb(std::string message);
    static void default_data_cb(std::string received);
    void close();
public:
    WebSocketIO(const std::string &uri, const std::string &protocol,
                std::function<void(std::string message)> error = nullptr,
                std::function<void(std::string received)> data = nullptr,
                bool make_async = true);
    ~WebSocketIO();
    bool start();
    void stop();
    bool write(const std::string &data);
};

#endif // WEBSOCKETIO_H
