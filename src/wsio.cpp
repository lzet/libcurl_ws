#include "wsio.h"
#include <atomic>
#include <iomanip>
#include <thread>
#include <iostream>
#include <sstream>
#include <curl/curl.h>
#include <base64_rfc4648.hpp>
#include <sha1.h>

#include <wsframe.h>

constexpr const char *USER_AGENT = "ws-curl-library/0.3";
constexpr const char *WS_VERSION = "13";
constexpr int CURL_TIMEOUT = 5;//000
constexpr int CURL_ASYNC_TIMEOUT_MS = 100;
constexpr std::size_t BUFSIZE_DEFAULT = 1024;

using sclock = std::chrono::steady_clock;
using sclocktp = std::chrono::steady_clock::time_point;

struct response_info_t {
    bool valid = false;
    bool connect_error = false;
    std::string accept_header;
    wscurl::wsframepool_t resframe;
    std::vector<uint8_t> buf;
};

struct connection_info_t {
    CURL *curl;
    curl_socket_t sockfd;
    response_info_t resp;
    bool valid;
    bool ssl;
    bool verbose;
    std::string host;
    std::string path;
    std::string protocol;
    std::string origin;
    std::string guid;
    std::array<uint8_t,20> ws_accept;
    bool is_open();
    connection_info_t(const std::string &uri, const std::string &protocol);
    std::string get_uri(bool wsformat = false) const;
    void print(const std::string &prefix);
};

bool connection_info_t::is_open()
{
    return sockfd != CURL_SOCKET_BAD;
}

connection_info_t::connection_info_t(const std::string &uri, const std::string &protocol)
    : curl(nullptr), sockfd(CURL_SOCKET_BAD), valid(false), ssl(false), verbose(false), protocol(protocol)
{
    std::size_t pos = uri.find(':');
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
    std::size_t nextpos = uri.find('/', pos);
    host = uri.substr(pos, nextpos-pos);
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
    sha1::calc(answ.c_str(), static_cast<int>(answ.length()), ws_accept.data());
}

std::string connection_info_t::get_uri(bool wsformat) const
{
    std::string _sch = wsformat ? "ws" : "http";
    std::string _sls = ssl ? "s://" : "://";
    return _sch + _sls + host + path;
}

void connection_info_t::print(const std::string &prefix)
{
    std::cout << prefix << "VALID: " << (valid ? "true" : "false") << std::endl;
    std::cout << prefix << "SSL: " << (ssl ? "true" : "false") << std::endl;
    std::cout << prefix << "HOST: " << host << std::endl;
    std::cout << prefix << "PATH: " << path << std::endl;
    std::cout << prefix << "PROTOCOL: " << protocol << std::endl;
    std::cout << prefix << "ORIGIN: " << origin << std::endl;
}

struct wsio_hdr_t {
    std::string name;
    std::string value;
    bool operator==(const wsio_hdr_t &a) const {
        return a.name == name;
    }
    bool empty() const {
        return name.empty() && value.empty();
    }
    static void insert2vec(std::vector<wsio_hdr_t> &v, const wsio_hdr_t &i, bool override = true) {
        for(auto &vi: v) {
            if(vi == i) {
                if(override) vi.value = i.value;
                return;
            }
        }
        v.push_back(i);
    }
    static wsio_hdr_t fromstr(const std::string &str) {
        auto delim = str.find(':');
        if(delim == std::string::npos)
            return {wscurl::trimmed(str), ""};
        auto name = str.substr(0, delim);
        auto val = str.substr(delim+1);
        return {wscurl::trimmed(name), wscurl::trimmed(val)};
    }
};

struct wsio_internal_t {
    connection_info_t conn;
    std::atomic_bool async;
    bool verifyssl, ismask;
    std::vector<wsio_hdr_t> hdrs, exthdrs;

    std::thread async_thr;

    std::function<void(wscurl::event_t, const std::string&)> event_cb;
    std::function<void(const std::string&)> data_txt_cb;
    std::function<void(const std::vector<uint8_t>&)> data_bin_cb;
    std::function<void(const std::string&, const std::string&)> header_cb;
    std::function<void()> ping_cb;

    bool recv_wait();
    wscurl::wsf_type_t recv_process();
    CURLcode send_wait(const uint8_t *request, std::size_t request_len);
    std::string connection_request() const;

    const static std::string accept_header;
    const static std::string response_code_header;

    static void default_event_cb(wscurl::event_t ev, const std::string &info);
    static void default_data_txt_cb(const std::string &data);
    static void default_data_bin_cb(const std::vector<uint8_t> &data);
    static void default_header_cb(const std::string &name, const std::string &value);
    static void default_ping_cb();
    void start_async_thread();
    void close();
    bool start(const std::string &uri, const std::string &protocol, bool make_async = true);
    bool write(wscurl::wsf_type_t type, const uint8_t *data, std::size_t datalen);
    bool read();

    static wsio_internal_t* instance_from(const std::shared_ptr<void> &inptr);
    static void instance_deleter(void *in);

    wsio_internal_t(bool sslverify, bool ismasked)
        : conn("", ""), async(false), verifyssl(sslverify), ismask(ismasked)
        , event_cb(default_event_cb)
        , data_txt_cb(default_data_txt_cb)
        , data_bin_cb(default_data_bin_cb)
        , header_cb(default_header_cb)
        , ping_cb(default_ping_cb)
    {}
    ~wsio_internal_t();
};

const std::string wsio_internal_t::accept_header("Sec-WebSocket-Accept");
const std::string wsio_internal_t::response_code_header("HTTP/1.1 ");

bool wsio_internal_t::recv_wait()
{
    if(!conn.is_open()) return false;
    CURLcode curl_err;
    conn.resp.buf.clear();
    conn.resp.buf.reserve(BUFSIZE_DEFAULT);
    std::array<uint8_t, BUFSIZE_DEFAULT> buffer;
    std::size_t received;
    bool recv_started = false;
    int recv_try_count = CURL_TIMEOUT;
    sclocktp starttime = sclock::now();
    std::chrono::seconds timeout(2);
    while(true) {
        if(!recv_started) {
            --recv_try_count;
            if(recv_try_count <= 0) {
                if(async) event_cb(wscurl::event_t::ERROR_EV, "error waiting for data");
                conn.resp.buf.clear();
                return false;
            }
        }
        received = 0;
        curl_err = curl_easy_recv(conn.curl, buffer.data(), buffer.size(), &received);
        if(!recv_started) {
            recv_started = curl_err == CURLcode::CURLE_OK;
        }
        if(recv_started && curl_err) {
            break;
        }
        if(received > 0) {
            for(std::size_t bi = 0; bi < received; ++bi) {
                conn.resp.buf.push_back(buffer[bi]);
            }
        }
        else {
            auto durtime = std::chrono::duration_cast<std::chrono::seconds>(sclock::now()-starttime);
            if(durtime >= timeout) {
                if(async) event_cb(wscurl::event_t::ERROR_EV, "error waiting for data (timeout)");
                conn.resp.buf.clear();
                return false;
            }
        }
        if(!recv_started) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }
    return true;
}

wscurl::wsf_type_t wsio_internal_t::recv_process()
{
    std::size_t l;
    wscurl::wsf_type_t r = (wscurl::wsf_type_t)0xff;
    while((l = wscurl::wsframe_t::frame_fullsize(conn.resp.buf.data(), conn.resp.buf.size())) > 0) {
        if(l > conn.resp.buf.size()) {
            break;
        }
        if(conn.resp.resframe.add_frame(conn.resp.buf.data(), l)) {
            if(conn.resp.resframe.is_finished()) {
                r = conn.resp.resframe.type();
                switch (r) {
                case wscurl::wsf_type_t::BINARY_FRAME:
                    data_bin_cb(conn.resp.resframe.to_binary());
                    break;
                case wscurl::wsf_type_t::TEXT_FRAME:
                    data_txt_cb(conn.resp.resframe.to_string());
                    break;
                case wscurl::wsf_type_t::PING_FRAME:
                    ping_cb();
                    break;
                case wscurl::wsf_type_t::CONNECTION_CLOSE_FRAME:
                    event_cb(wscurl::event_t::DISCONNECT_EV, "closed by server");
                    close();
                    break;
                case wscurl::wsf_type_t::CONTTINUATION_FRAME:
                case wscurl::wsf_type_t::PONG_FRAME:
                    break;
                }
                conn.resp.resframe.clear();
            }
        }
        else {
            event_cb(wscurl::event_t::ERROR_EV, conn.resp.resframe.error());
            conn.resp.resframe.clear();
        }
        conn.resp.buf.erase(conn.resp.buf.begin(), conn.resp.buf.begin()+static_cast<long>(l));
    }
    conn.resp.buf.clear();
    return r;
}

int wait_on_socket(curl_socket_t sockfd, int for_recv, long timeout_ms)
{
    timeval tv;
    fd_set infd, outfd, errfd;
    int res;

#if defined(MSDOS) || defined(__AMIGA__)
    tv.tv_sec = (time_t)(timeout_ms / 1000);
    tv.tv_usec = (time_t)(timeout_ms % 1000) * 1000;
#else
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (int)(timeout_ms % 1000) * 1000;
#endif

    FD_ZERO(&infd);
    FD_ZERO(&outfd);
    FD_ZERO(&errfd);

/* Avoid this warning with pre-2020 Cygwin/MSYS releases:
 * warning: conversion to 'long unsigned int' from 'curl_socket_t' {aka 'int'}
 * may change the sign of the result [-Wsign-conversion]
 */
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#if defined(__DJGPP__)
#pragma GCC diagnostic ignored "-Warith-conversion"
#endif
#elif defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable:4127)  /* conditional expression is constant */
#endif
    FD_SET(sockfd, &errfd); /* always check for error */

    if(for_recv) {
        FD_SET(sockfd, &infd);
    }
    else {
        FD_SET(sockfd, &outfd);
    }
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#elif defined(_MSC_VER)
#pragma warning(pop)
#endif

    /* select() returns the number of signalled sockets or -1 */
    res = select((int)sockfd + 1, &infd, &outfd, &errfd, &tv);
    return res;
}

CURLcode wsio_internal_t::send_wait(const uint8_t *request, std::size_t request_len)
{
    if(!conn.is_open()) return CURLE_COULDNT_CONNECT;
    std::size_t nsent_total = 0;
    CURLcode res;
    do {
        std::size_t nsent;
        do {
            nsent = 0;
            res = curl_easy_send(conn.curl, request+nsent_total, request_len-nsent_total, &nsent);
            nsent_total += nsent;

            if(res == CURLE_AGAIN && !wait_on_socket(conn.sockfd, 0, CURL_TIMEOUT*1000))
                return CURLE_COULDNT_CONNECT;
        } while(res == CURLE_AGAIN);

        if(res != CURLE_OK)
            return res;

    } while(nsent_total < request_len);
    return CURLE_OK;
}

std::string wsio_internal_t::connection_request() const
{
    std::ostringstream ost(std::ios::out);
    ost << "GET " << conn.path << " HTTP/1.1\n";
    auto hdrs_copy = hdrs;
    for(const auto &h: exthdrs)
        wsio_hdr_t::insert2vec(hdrs_copy, h);
    for(const auto &h: hdrs_copy)
        ost << h.name << ": " << h.value << "\n";
    ost << "\n";
    return ost.str();
}

void wsio_internal_t::default_event_cb(wscurl::event_t ev, const std::string &info)
{
    std::cerr << "EVENT " << event_info_str(ev) << ": " << info << std::endl;
}

void wsio_internal_t::default_data_txt_cb(const std::string &data)
{
    std::cerr << "RECEIVED text: " << data << std::endl;
}

void wsio_internal_t::default_data_bin_cb(const std::vector<uint8_t> &data)
{
    std::cerr << "RECEIVED binary data: size=" << data.size() << " bytes" << std::endl;
}

void wsio_internal_t::default_header_cb(const std::string &name, const std::string &value)
{
    std::cerr << "RECEIVED header data: name=" << name << " value=" << value << std::endl;
}

void wsio_internal_t::default_ping_cb()
{
}

void wsio_internal_t::start_async_thread()
{
    if(!async) return;
    if(async_thr.joinable()) return;
    async_thr = std::thread([this](){
        CURLcode curl_err;
        std::array<uint8_t, BUFSIZE_DEFAULT> buffer;
        std::size_t received;
        static auto to_ms = std::chrono::milliseconds(CURL_ASYNC_TIMEOUT_MS);

        while(async) {
            received = 0;
            if(!conn.curl || !conn.resp.valid || conn.resp.connect_error) {
                std::this_thread::sleep_for(to_ms);
                continue;
            }
            curl_err = curl_easy_recv(conn.curl, buffer.data(), buffer.size(), &received);
            if(curl_err == CURLE_AGAIN) {
                if(!async) break;
                std::this_thread::sleep_for(to_ms);
                continue;
            }
            if(curl_err) {
                event_cb(wscurl::event_t::ERROR_EV, curl_easy_strerror(curl_err));
                break;
            }
            if(received > 0) {
                if((conn.resp.buf.size() + received) < conn.resp.buf.capacity()) {
                    conn.resp.buf.reserve(conn.resp.buf.size()+BUFSIZE_DEFAULT);
                }
                for(std::size_t bi = 0; bi < received; ++bi) {
                    conn.resp.buf.push_back(buffer[bi]);
                }
            }
            if(conn.resp.buf.size() > 0)
                recv_process();
        }
    });
}

void wsio_internal_t::close()
{
    async = false;
    if(async_thr.joinable())
        async_thr.join();
    if(conn.curl) {
        CURL *del = conn.curl;
        conn.curl = nullptr;
        curl_easy_cleanup(del);
    }
    curl_global_cleanup();
}

int closesocket(void *clientp, curl_socket_t item) {
    wsio_internal_t *ctx = static_cast<wsio_internal_t*>(clientp);
    if(ctx->conn.sockfd != CURL_SOCKET_BAD) {
        ctx->conn.sockfd = CURL_SOCKET_BAD;
        ctx->event_cb(wscurl::event_t::DISCONNECT_EV, "socket " + std::to_string(item) + " closed");
    }
    return 0;
}

int debug_callback(CURL *handle, curl_infotype type, char *data, std::size_t size, void *clientp) {
    if(type == CURLINFO_TEXT) std::cerr << std::string(data, size) << std::endl;
    else std::cerr << "type: " << type << std::endl;
    return 0;
}

bool wsio_internal_t::start(const std::string &uri, const std::string &protocol, bool make_async)
{
    if(conn.curl) {
        event_cb(wscurl::event_t::ERROR_EV, "already started");
        return false;
    }

    conn = connection_info_t(uri, protocol);

    wsio_hdr_t::insert2vec(hdrs, {"Host", conn.host});
    wsio_hdr_t::insert2vec(hdrs, {"User-Agent", USER_AGENT});
    wsio_hdr_t::insert2vec(hdrs, {"Accept", "*/*"});
    wsio_hdr_t::insert2vec(hdrs, {"Sec-WebSocket-Version", WS_VERSION});
    wsio_hdr_t::insert2vec(hdrs, {"Sec-WebSocket-Extensions", "permessage-deflate"});
    wsio_hdr_t::insert2vec(hdrs, {"Sec-WebSocket-Key", conn.guid});
    if(!conn.protocol.empty()) {
        wsio_hdr_t::insert2vec(hdrs, {"Sec-WebSocket-Protocol", conn.protocol});
    }
    wsio_hdr_t::insert2vec(hdrs, {"Accept-Encoding", "gzip, deflate"});
    wsio_hdr_t::insert2vec(hdrs, {"Connection", "keep-alive, Upgrade"});
    wsio_hdr_t::insert2vec(hdrs, {"Pragma", "no-cache"});
    wsio_hdr_t::insert2vec(hdrs, {"Cache-Control", "no-cache"});
    wsio_hdr_t::insert2vec(hdrs, {"Origin", conn.get_uri()});
    wsio_hdr_t::insert2vec(hdrs, {"Upgrade", "websocket"});

    async = make_async;
    start_async_thread();
    //conn.print("");
#pragma GCC diagnostic push

#if defined(__has_warning)
#if __has_warning("-Wdisabled-macro-expansion")
#pragma GCC diagnostic ignored "-Wdisabled-macro-expansion"
#endif
#endif
    curl_global_init(CURL_GLOBAL_ALL);
    conn.curl = curl_easy_init();
    conn.resp.connect_error = true;
    conn.resp.valid = false;
    if(conn.curl) {
        conn.resp.connect_error = false;
        std::string _uri = conn.get_uri();

        if(conn.verbose) {
            curl_easy_setopt(conn.curl, CURLOPT_DEBUGFUNCTION, debug_callback);
            curl_easy_setopt(conn.curl, CURLOPT_DEBUGDATA,  this);
            curl_easy_setopt(conn.curl, CURLOPT_VERBOSE, 1L);
        }

        curl_easy_setopt(conn.curl, CURLOPT_URL, _uri.c_str());
        // curl_easy_setopt(conn.curl, CURLOPT_TIMEOUT, CURL_TIMEOUT);
        curl_easy_setopt(conn.curl, CURLOPT_CONNECTTIMEOUT, CURL_TIMEOUT);
        curl_easy_setopt(conn.curl, CURLOPT_SSL_VERIFYPEER, verifyssl);
        curl_easy_setopt(conn.curl, CURLOPT_WRITEDATA, this);
        curl_easy_setopt(conn.curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(conn.curl, CURLOPT_MAXREDIRS, 3L);
        curl_easy_setopt(conn.curl, CURLOPT_HTTPGET, 1L);
        curl_easy_setopt(conn.curl, CURLOPT_CONNECT_ONLY, 1L);
        curl_easy_setopt(conn.curl, CURLOPT_CLOSESOCKETFUNCTION, closesocket);
        curl_easy_setopt(conn.curl, CURLOPT_CLOSESOCKETDATA, this);

        auto curl_err = curl_easy_perform(conn.curl);
        if (curl_err != CURLE_OK) {
            event_cb(wscurl::event_t::ERROR_EV, curl_easy_strerror(curl_err));
            conn.resp.connect_error = true;
        }
        else {
            curl_err = curl_easy_getinfo(conn.curl, CURLINFO_ACTIVESOCKET, &conn.sockfd);
            if (curl_err != CURLE_OK) {
                event_cb(wscurl::event_t::ERROR_EV, curl_easy_strerror(curl_err));
                conn.resp.connect_error = true;
            }
            else {
                std::string conn_headers = connection_request();
                curl_err = send_wait(reinterpret_cast<const uint8_t*>(conn_headers.c_str()), conn_headers.size());
                if (curl_err != CURLE_OK) {
                    event_cb(wscurl::event_t::ERROR_EV, curl_easy_strerror(curl_err));
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
                            wsio_hdr_t h = wsio_hdr_t::fromstr(hdr);
                            if(h.empty())
                                continue;
                            header_cb(h.name, h.value);
                            if(h.name == accept_header) {
                                conn.resp.accept_header = h.value;
                                try {
                                    // check Sec-WebSocket-Accept
                                    auto decoded = cppcodec::base64_rfc4648::decode(conn.resp.accept_header.c_str(), conn.resp.accept_header.length());
                                    if(decoded.size() != 20) {
                                        event_cb(wscurl::event_t::ERROR_EV, "Websocket: Sec-WebSocket-Accept value error");
                                        conn.resp.connect_error = true;
                                    }
                                    else {
                                        if(!std::equal(conn.ws_accept.begin(), conn.ws_accept.end(), decoded.begin())) {
                                            event_cb(wscurl::event_t::ERROR_EV, "Websocket: Sec-WebSocket-Accept not same");
                                            conn.resp.connect_error = true;
                                        }
                                    }
                                } catch (...) {
                                    event_cb(wscurl::event_t::ERROR_EV, "Websocket: Sec-WebSocket-Accept format error");
                                    conn.resp.connect_error = true;
                                }
                            }
                            else if(hdr.find(response_code_header) != std::string::npos) {
                                conn.resp.valid = hdr.substr(response_code_header.length(), 3) == "101";
                            }
                        }
                    }
                }
            }
        }
    }
    conn.resp.buf.clear();
    bool ret = conn.resp.valid && !conn.resp.connect_error;
    if(!ret) close();
#pragma GCC diagnostic pop
    if(ret) {
        event_cb(wscurl::event_t::CONNECT_EV, conn.get_uri(true));
        ping_cb = [this]() -> void {
            static std::vector<uint8_t> frame = wscurl::wsframe_t(wscurl::wsf_type_t::PONG_FRAME, true).frame();
            CURLcode curl_err = send_wait(frame.data(), frame.size());
            if (curl_err != CURLE_OK)
                event_cb(wscurl::event_t::ERROR_EV, curl_easy_strerror(curl_err));
        };
    }
    else
        event_cb(wscurl::event_t::DISCONNECT_EV, "connect error");
    return ret;
}

bool wsio_internal_t::write(wscurl::wsf_type_t type, const uint8_t *data, std::size_t datalen)
{
    if(conn.curl == nullptr) {
        event_cb(wscurl::event_t::ERROR_EV, "write error: no connection");
        return false;
    }
    if(datalen < 1)
        return true;
    CURLcode curl_err;
    wscurl::wsframepool_t frames(type, ismask, data, datalen);
    for(const auto &frame: frames.getdata()) {
        curl_err = send_wait(frame.first, frame.second);
        if (curl_err != CURLE_OK) {
            event_cb(wscurl::event_t::ERROR_EV, curl_easy_strerror(curl_err));
            return false;
        }
    }
    return true;
}

bool wsio_internal_t::read()
{
    if(conn.curl == nullptr) {
        event_cb(wscurl::event_t::ERROR_EV, "read error: no connection");
        return false;
    }
    if(!async) {
        if(!recv_wait()) return false;
        recv_process();
    }
    return true;
}

wsio_internal_t *wsio_internal_t::instance_from(const std::shared_ptr<void> &inptr)
{
    if(inptr) return static_cast<wsio_internal_t*>(inptr.get());
    return nullptr;
}

void wsio_internal_t::instance_deleter(void *in)
{
    if(in)
        delete static_cast<wsio_internal_t*>(in);
}

wsio_internal_t::~wsio_internal_t()
{
    close();
}

std::string wscurl::event_info_str(event_t ev)
{
    switch (ev) {
    case event_t::CONNECT_EV: return "connect";
    case event_t::DISCONNECT_EV: return "disconnect";
    case event_t::ERROR_EV: return "error";
    }
    return "unknown";
}


wscurl::wsio_t::wsio_t(bool verifyssl, bool maskframe)
    : _context(
          (void*)(new wsio_internal_t(verifyssl, maskframe)),
          wsio_internal_t::instance_deleter
          )
{

}

wscurl::wsio_t::~wsio_t()
{

}

wscurl::wsio_t &wscurl::wsio_t::on_event(std::function<void (event_t, const std::string &)> &&event_cb)
{
    wsio_internal_t::instance_from(_context)->event_cb = std::move(event_cb);
    return *this;
}

wscurl::wsio_t &wscurl::wsio_t::on_header(std::function<void (const std::string &, const std::string &)> &&header_cb)
{
    wsio_internal_t::instance_from(_context)->header_cb = std::move(header_cb);
    return *this;
}

wscurl::wsio_t &wscurl::wsio_t::on_message_text(std::function<void (const std::string &)> &&message_txt_cb)
{
    wsio_internal_t::instance_from(_context)->data_txt_cb = std::move(message_txt_cb);
    return *this;
}

wscurl::wsio_t &wscurl::wsio_t::on_message_binary(std::function<void (const std::vector<uint8_t>&)> &&message_bin_cb)
{
    wsio_internal_t::instance_from(_context)->data_bin_cb = std::move(message_bin_cb);
    return *this;
}

void wscurl::wsio_t::add_header(const std::string &name, const std::string &value)
{
    wsio_internal_t::instance_from(_context)->exthdrs.push_back({name, value});
}

bool wscurl::wsio_t::start(const std::string &uri, const std::string &protocol, bool make_async)
{
    return wsio_internal_t::instance_from(_context)->start(uri, protocol, make_async);
}

void wscurl::wsio_t::stop()
{
    wsio_internal_t::instance_from(_context)->close();
}

bool wscurl::wsio_t::write(const std::string &data)
{
    return wsio_internal_t::instance_from(_context)->write(wsf_type_t::TEXT_FRAME, reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

bool wscurl::wsio_t::write(const std::vector<uint8_t> &data)
{
    return wsio_internal_t::instance_from(_context)->write(wsf_type_t::BINARY_FRAME, data.data(), data.size());
}

bool wscurl::wsio_t::read()
{
    return wsio_internal_t::instance_from(_context)->read();
}
