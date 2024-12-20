#ifndef WSFRAME_H
#define WSFRAME_H

#include <string>
#include <vector>
namespace wscurl {
// The WebSocket Protocol
// https://datatracker.ietf.org/doc/html/rfc6455

std::string& trimmed(std::string &str);
std::string trimmed(const std::string &str);

enum class wsf_hdr1b_t: uint8_t {
    HDR1_FIN                     = 0x80,
    HDR1_RSV1                    = 0x40,
    HDR1_RSV2                    = 0x20,
    HDR1_RSV3                    = 0x10,

    HDR1_CONTTINUATION_FRAME     = 0x00, // %x0 denotes a continuation frame
    HDR1_TEXT_FRAME              = 0x01, // %x1 denotes a text frame
    HDR1_BINARY_FRAME            = 0x02, // %x2 denotes a binary frame
    // 0x30 - 0x70 are reserved for further non-control frames
    HDR1_CONNECTION_CLOSE_FRAME  = 0x08, // %x8 denotes a connection close
    HDR1_PING_FRAME              = 0x09, // %x9 denotes a ping
    HDR1_PONG_FRAME              = 0x0a, // %xA denotes a pong
    // 0xB0 - 0xF0 are reserved for further control frames
};
enum class wsf_hdr2b_t: uint8_t {
    HDR2_MASK_FRAME              = 0x80,
    HDR2_RMASK2B_LEN             = 0x7e, // the following 2 bytes interpreted as a 16-bit unsigned integer
    HDR2_RMASK8B_LEN             = 0x7f  // the following 8 bytes interpreted as a 64-bit unsigned integer (the most significant bit MUST be 0)
};

enum class wsf_type_t: uint8_t {
    UNKNOWN_FRAME         = 0,
    CONTTINUATION_FRAME,
    TEXT_FRAME,
    BINARY_FRAME,
    CONNECTION_CLOSE_FRAME,
    PING_FRAME,
    PONG_FRAME,
};

using wsdata_t = std::vector<uint8_t>;

class wsframe_t
{
    wsdata_t _data;
    wsf_type_t _type;
    bool _isfinal, _ismask;
public:
    static std::size_t frame_fullsize(const uint8_t *indata, std::size_t indata_len);
    static std::pair<std::size_t, std::size_t> frame_startposition_size(const uint8_t *indata, std::size_t indata_len);
    wsframe_t(wsf_type_t type, bool final = true, bool ismask = true, const uint8_t *indata = nullptr, std::size_t indata_len = 0);
    wsframe_t(const uint8_t *indata, std::size_t indata_len, bool &ok, std::string &err);
    bool is_final();
    bool is_masked();
    wsf_type_t get_type();
    wsdata_t frame();
    static wsdata_t getframe(wsf_type_t type, bool final = true, bool ismask = true, const uint8_t *indata = nullptr, std::size_t indata_len = 0);
};

class wsframepool_t {
    std::vector<wsdata_t> _pool;
    bool _fin;
    std::string _err;
    wsf_type_t _type;
public:
    wsframepool_t(wsf_type_t type=wsf_type_t::CONNECTION_CLOSE_FRAME, bool ismask = true, const uint8_t *data=nullptr, std::size_t len=0);
    std::vector<std::pair<const uint8_t*, std::size_t> > getdata() const;
    std::string to_string() const;
    wsdata_t to_binary() const;
    bool add_frame(const uint8_t *data, std::size_t len);
    bool is_finished() const;
    void clear();
    std::string error() const;
    wsf_type_t type() const;
};

}

#endif // WSFRAME_H
