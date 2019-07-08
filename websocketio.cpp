#include "websocketio.h"
#include <iostream>
#include "cppcodec/base64_rfc4648.hpp"
#include "sha1/sha1.h"

bool WebSocketIO::recv_wait()
{
    CURLcode curl_err;
    constexpr size_t bufsize = 1024;
    conn.resp.buf.clear();
    conn.resp.buf.reserve(bufsize);
    unsigned char buffer[bufsize];
    size_t received;
    bool recv_started = false;
    int recv_try_count = CURL_TIMEOUT * 2; // ms/500
    while(true) {
        if(!recv_started) {
            --recv_try_count;
            if(recv_try_count <= 0) {
                error_cb("error waiting for data");
                conn.resp.buf.clear();
                return false;
            }
        }
        received = 0;
        curl_err = curl_easy_recv(conn.curl, buffer, bufsize, &received);
        if(!recv_started) {
            recv_started = curl_err == CURLcode::CURLE_OK;
        }
        if(recv_started && curl_err) {
            break;
        }
        if(received > 0) {
            for(size_t bi = 0; bi < received; ++bi) {
                conn.resp.buf.push_back(buffer[bi]);
            }
        }
        if(!recv_started) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }
    return true;
}

const std::string WebSocketIO::accept_header("Sec-WebSocket-Accept: ");
const std::string WebSocketIO::response_code_header("HTTP/1.1 ");

void WebSocketIO::default_error_cb(std::string message)
{
    std::cerr << "ERROR: " << message << std::endl;
}

void WebSocketIO::default_data_cb(std::string received)
{
    std::cout << "RECEIVED: " << received << std::endl;
}

void WebSocketIO::close()
{
    if(conn.curl) {
        CURL *del = conn.curl;
        conn.curl = nullptr;
        curl_easy_cleanup(del);
    }
    curl_global_cleanup();
}

WebSocketIO::WebSocketIO(const std::string &uri,
                         const std::string &protocol,
                         std::function<void (std::string)> error,
                         std::function<void (std::string)> data,
                         bool make_async)
    : conn(uri, protocol), async(make_async),
      error_cb(error?error:default_error_cb),
      data_cb(data?data:default_data_cb)
{
    if(!async) return;
    async_thread = std::thread([this](){
        CURLcode curl_err;
        constexpr size_t bufsize = 1024;
        unsigned char buffer[bufsize];
        size_t received;
        static auto to_ms = std::chrono::milliseconds(CURL_ASYNC_TIMEOUT_MS);

        while(async) {
            received = 0;
            if(!conn.curl || !conn.resp.valid || conn.resp.connect_error) {
                std::this_thread::sleep_for(to_ms);
                continue;
            }
            curl_err = curl_easy_recv(conn.curl, buffer, bufsize, &received);
            if(curl_err == CURLE_AGAIN) {
                if(!async) break;
                std::this_thread::sleep_for(to_ms);
                continue;
            }
            if(curl_err) {
                error_cb(curl_easy_strerror(curl_err));
                break;
            }
            if(received > 0) {
                if( (conn.resp.buf.size() + received) < conn.resp.buf.capacity()) {
                    conn.resp.buf.reserve(conn.resp.buf.size()+bufsize);
                }
                for(size_t bi = 0; bi < received; ++bi) {
                    conn.resp.buf.push_back(buffer[bi]);
                }
            }
            if(conn.resp.buf.size() > 0) {
                size_t l;
                while((l = WSocketFrame::frame_fullsize(conn.resp.buf.data(), conn.resp.buf.size())) > 0) {
                    if(l > conn.resp.buf.size()) {
                        break;
                    }
                    if(conn.resp.resframe.add_frame(conn.resp.buf.data(), l)) {
                        if(conn.resp.resframe.is_finished()) {
                            data_cb(conn.resp.resframe.to_string());
                            conn.resp.resframe.clear();
                        }
                    }
                    else {
                        error_cb(conn.resp.resframe.error());
                        conn.resp.resframe.clear();
                    }
                    conn.resp.buf.erase(conn.resp.buf.begin(), conn.resp.buf.begin()+static_cast<long>(l));
                }
            }
        }
    });
}

WebSocketIO::~WebSocketIO()
{
    async = false;
    if(async_thread.joinable())
        async_thread.join();
    close();
}

bool WebSocketIO::start()
{
    //conn.print("");
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdisabled-macro-expansion"
    close();
    curl_global_init(CURL_GLOBAL_ALL);
    conn.curl = curl_easy_init();
    conn.resp.connect_error = true;
    conn.resp.valid = false;
    if(conn.curl) {
        conn.resp.connect_error = false;
        std::string uri = conn.get_uri();
        curl_easy_setopt(conn.curl, CURLOPT_URL, uri.c_str());
        //curl_easy_setopt(curl, CURLOPT_TIMEOUT, CURL_TIMEOUT);
        curl_easy_setopt(conn.curl, CURLOPT_CONNECTTIMEOUT, CURL_TIMEOUT);
        curl_easy_setopt(conn.curl, CURLOPT_SSL_VERIFYPEER, VERIFYSSL);
        curl_easy_setopt(conn.curl, CURLOPT_WRITEDATA, this);
        curl_easy_setopt(conn.curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(conn.curl, CURLOPT_MAXREDIRS, 3L);
        curl_easy_setopt(conn.curl, CURLOPT_HTTPGET, 1);
        curl_easy_setopt(conn.curl, CURLOPT_CONNECT_ONLY, 1);
        auto curl_err = curl_easy_perform(conn.curl);
        if (curl_err != CURLE_OK) {
            this->error_cb(curl_easy_strerror(curl_err));
            conn.resp.connect_error = true;
        }
        else {
            std::string conn_headers("GET ");
            conn_headers += conn.path + " HTTP/1.1\r\n";
            conn_headers += "Host: " + conn.host + "\r\n";
            conn_headers += "Accept: */*\r\n";
            conn_headers += std::string("User-Agent: ") + USER_AGENT + "\r\n";
            conn_headers += "Upgrade: websocket\r\n";
            conn_headers += "Connection: Upgrade\r\n";
            conn_headers += conn.get_key() + "\r\n";
            conn_headers += conn.get_origin() + "\r\n";
            conn_headers += conn.get_protocol() + "\r\n";
            conn_headers += "Sec-WebSocket-Version: " + std::to_string(WS_VERSION) + "\r\n\r\n";

            size_t bytes_sent = 0;
            curl_err = curl_easy_send(conn.curl, conn_headers.c_str(), conn_headers.length(), &bytes_sent);
            if (curl_err != CURLE_OK) {
                this->error_cb(curl_easy_strerror(curl_err));
                conn.resp.connect_error = true;
            }
            else {
                if(recv_wait()) {
                    std::string headers = std::string(reinterpret_cast<char*>(conn.resp.buf.data()), conn.resp.buf.size());
                    //std::cerr << "REQ:" << std::endl << conn_headers << std::endl;
                    //std::cerr << "RES:" << std::endl << headers << std::endl;
                    std::istringstream ifs(headers);
                    std::string hdr;
                    while(std::getline(ifs, hdr, '\n')) {
                        if(hdr.find(accept_header) == 0) {
                            conn.resp.accept_header = hdr.substr(accept_header.length());
                            trimmed(conn.resp.accept_header);
                            try {
                                // check Sec-WebSocket-Accept
                                auto decoded = cppcodec::base64_rfc4648::decode(conn.resp.accept_header.c_str(), conn.resp.accept_header.length());
                                if(decoded.size() != 20) {
                                    this->error_cb("Websocket: Sec-WebSocket-Accept value error");
                                    conn.resp.connect_error = true;
                                }
                                else {
                                    bool same = true;
                                    for(size_t i = 0; i < 20; ++i) {
                                        if(conn.ws_accept[i] != decoded[i]) {
                                            same = false;
                                            break;
                                        }
                                    }
                                    if(!same) {
                                        this->error_cb("Websocket: Sec-WebSocket-Accept not same");
                                        conn.resp.connect_error = true;
                                    }
                                }
                            } catch (...) {
                                this->error_cb("Websocket: Sec-WebSocket-Accept format error");
                                conn.resp.connect_error = true;
                            }
                        }
                        else if(hdr.find(response_code_header) == 0) {
                            conn.resp.valid = hdr.substr(response_code_header.length(), 3) == "101";
                        }
                    }
                }
            }
        }
    }
    conn.resp.buf.clear();
    bool ret = conn.resp.valid && !conn.resp.connect_error;
    if(!ret) {
        close();
    }
#pragma GCC diagnostic pop
    return ret;
}

void WebSocketIO::stop()
{
    close();
}

bool WebSocketIO::write(const std::string &data)
{
    if(conn.curl == nullptr) {
        error_cb("No connection");
        return false;
    }
    size_t bytes_sent = 0;
    CURLcode curl_err;
    WSocketFrames frames(WSocketFrame::FRAME_TYPE::TEXT_FRAME, reinterpret_cast<const unsigned char*>(data.c_str()), data.length());
    for(auto &frame: frames.getdata()) {
        bytes_sent = 0;
        curl_err = curl_easy_send(conn.curl, frame.first, frame.second, &bytes_sent);
        if (curl_err != CURLE_OK) {
            error_cb(curl_easy_strerror(curl_err));
        }
        if(bytes_sent != frame.second) {
            error_cb("Write to socket error (writed "+std::to_string(bytes_sent)+"/"+std::to_string(frame.second)+")");
        }
    }
    if(!async && recv_wait()) {
        size_t l;
        while((l = WSocketFrame::frame_fullsize(conn.resp.buf.data(), conn.resp.buf.size())) > 0) {
            if(l > conn.resp.buf.size()) {
                break;
            }
            if(conn.resp.resframe.add_frame(conn.resp.buf.data(), l)) {
                if(conn.resp.resframe.is_finished()) {
                    data_cb(conn.resp.resframe.to_string());
                    conn.resp.resframe.clear();
                }
            }
            else {
                error_cb(conn.resp.resframe.error());
                conn.resp.resframe.clear();
            }
            conn.resp.buf.erase(conn.resp.buf.begin(), conn.resp.buf.begin()+static_cast<long>(l));
        }
        conn.resp.buf.clear();
    }
    return true;
}

ConnectionInfo::ConnectionInfo(const std::string &uri, const std::string &protocol)
    : curl(nullptr), protocol(protocol)
{
    valid = false;
    size_t pos = uri.find(':');
    if(pos == std::string::npos) return;
    std::string scheme = uri.substr(0, pos);
    if(scheme == "ws") {
        ssl = false;
    }
    else if(scheme == "wss") {
        ssl = true;
    }
    else {
        return;
    }
    pos += 3; // ://
    size_t nextpos = uri.find('/', pos);
    host = uri.substr(pos, nextpos);
    if(nextpos == std::string::npos) {
        path = "/";
    }
    else {
        path = uri.substr(nextpos);
    }
    valid = true;
    std::srand(static_cast<unsigned>(std::time(nullptr)));
    std::stringstream stream;
    std::uppercase(stream);
    int sz2len = sizeof(int)*2;
    for(int i = 0; i < 4; ++i) {
        stream << std::setfill ('0') << std::setw(sz2len) << std::hex << std::rand();
    }
    guid = stream.str();
    pos = 8;
    guid.insert(pos, "-");
    pos += 5;
    guid.insert(pos, "-");
    pos += 5;
    guid.insert(pos, "-");
    pos += 5;
    guid.insert(pos, "-");
    guid = cppcodec::base64_rfc4648::encode(guid.c_str(), guid.length());
    std::string answ = guid+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    sha1::calc(answ.c_str(), static_cast<int>(answ.length()), ws_accept);
}

std::string ConnectionInfo::get_key()
{
    return std::string("Sec-WebSocket-Key: ") + guid;
}

std::string ConnectionInfo::get_uri()
{
    std::string uri(ssl ? "https://" : "http://");
    return uri + host + path;
}

std::string ConnectionInfo::get_origin()
{
    std::string origin("Origin: ");
    return origin + get_uri();
}

std::string ConnectionInfo::get_protocol()
{
    std::string proto("Sec-WebSocket-Protocol: ");
    return proto + protocol;
}

void ConnectionInfo::print(const std::string &prefix)
{
    std::cout << prefix << "VALID: " << (valid ? "true" : "false") << std::endl;
    std::cout << prefix << "SSL: " << (ssl ? "true" : "false") << std::endl;
    std::cout << prefix << "HOST: " << host << std::endl;
    std::cout << prefix << "PATH: " << path << std::endl;
    std::cout << prefix << "PROTOCOL: " << protocol << std::endl;
    std::cout << prefix << "ORIGIN: " << origin << std::endl;
}
