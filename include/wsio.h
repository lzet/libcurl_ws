#ifndef WSIO_H
#define WSIO_H
#include <functional>
#include <string>
#include <memory>

namespace wscurl {

enum class event_t {
    ERROR_EV = 0,
    CONNECT_EV,
    DISCONNECT_EV
};
std::string event_info_str(event_t ev);

class wsio_t
{
    std::shared_ptr<void> _context;
public:
    wsio_t(bool verifyssl = false, bool maskframe = true);
    ~wsio_t();

    /**
     * @brief on_event
     * @param event_cb void(event type, message)
     * @return
     */
    wsio_t& on_event(std::function<void(event_t, const std::string&)> &&event_cb);
    /**
     * @brief on_header
     * @param header_cb void(header name, header value)
     * @return
     */
    wsio_t& on_header(std::function<void(const std::string&, const std::string&)> &&header_cb);
    wsio_t& on_message_text(std::function<void(const std::string&)> &&message_txt_cb);
    wsio_t& on_message_binary(std::function<void(const std::vector<uint8_t>&)> &&message_bin_cb);

    template<class S, auto CALLBK>
    wsio_t& on_event(void *s) {
        return on_event([s](event_t t, const std::string &m) {
            (static_cast<S*>(s)->CALLBK)(t, m);
        });
    }
    template<class S, auto CALLBK>
    wsio_t& on_header(void *s) {
        return on_header([s](const std::string &n, const std::string &v) {
            (static_cast<S*>(s)->*CALLBK)(n, v);
        });
    }
    template<class S, auto CALLBK>
    wsio_t& on_message_text(void *s) {
        return on_message_text([s](const std::string &m) {
            (static_cast<S*>(s)->*CALLBK)(m);
        });
    }
    template<class S, auto CALLBK>
    wsio_t& on_message_binary(void *s) {
        return on_message_binary([s](const std::vector<uint8_t> &d) {
            (static_cast<S*>(s)->*CALLBK)(d);
        });
    }
    void add_header(const std::string &name, const std::string &value);

    bool start(const std::string &uri, const std::string &protocol = "", bool make_async = true);
    void stop();
    bool write(const std::string &data);
    bool write(const std::vector<uint8_t> &data);
    bool read();
};

}

#endif // WSIO_H
