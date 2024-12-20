#include "wsframe.h"
#include <ctime>
#include <sstream>

std::string& wscurl::trimmed(std::string &str) {
    constexpr const char *SPACESYMBOLS = " \t\n\r\x0B";
    auto pos1 = str.find_first_not_of(SPACESYMBOLS);
    if(pos1 == std::string::npos) pos1 = 0;
    auto pos2 = str.find_last_not_of(SPACESYMBOLS);
    str = str.substr(pos1, pos2-pos1+1);
    return str;
}

std::string wscurl::trimmed(const std::string &str) {
    auto str2 = str;
    trimmed(str2);
    return str2;
}


template <typename T>
T swaporder(T in) {
    T out;
    uint8_t *inbuf = reinterpret_cast<uint8_t*>(&in);
    uint8_t *oubuf = reinterpret_cast<uint8_t*>(&out);
    std::size_t ousize = sizeof (T);
    std::size_t oui = ousize-1;
    for(std::size_t ini = 0; ini < ousize; ++ini) {
        oubuf[oui--] = inbuf[ini];
    }
    return out;
}

wscurl::wsf_type_t frametype(uint8_t opcode) {
    wscurl::wsf_hdr1b_t tt = static_cast<wscurl::wsf_hdr1b_t>(0xf & opcode);
    switch (tt) {
    case wscurl::wsf_hdr1b_t::HDR1_CONTTINUATION_FRAME:
        return wscurl::wsf_type_t::CONTTINUATION_FRAME;
    case wscurl::wsf_hdr1b_t::HDR1_CONNECTION_CLOSE_FRAME:
        return wscurl::wsf_type_t::CONNECTION_CLOSE_FRAME;
    case wscurl::wsf_hdr1b_t::HDR1_PING_FRAME:
        return wscurl::wsf_type_t::PING_FRAME;
    case wscurl::wsf_hdr1b_t::HDR1_PONG_FRAME:
        return wscurl::wsf_type_t::PONG_FRAME;
    case wscurl::wsf_hdr1b_t::HDR1_TEXT_FRAME:
        return wscurl::wsf_type_t::TEXT_FRAME;
    case wscurl::wsf_hdr1b_t::HDR1_BINARY_FRAME:
        return wscurl::wsf_type_t::BINARY_FRAME;
    case wscurl::wsf_hdr1b_t::HDR1_RSV1:
    case wscurl::wsf_hdr1b_t::HDR1_RSV2:
    case wscurl::wsf_hdr1b_t::HDR1_RSV3:
    case wscurl::wsf_hdr1b_t::HDR1_FIN:
        break;
    }
    return wscurl::wsf_type_t::UNKNOWN_FRAME;
}

std::size_t wscurl::wsframe_t::frame_fullsize(const uint8_t *indata, std::size_t indata_len)
{
    auto fssp = frame_startposition_size(indata, indata_len);
    return fssp.first+fssp.second;
}

std::pair<std::size_t, std::size_t> wscurl::wsframe_t::frame_startposition_size(const uint8_t *indata, std::size_t indata_len)
{
    if(indata_len < 2) {
        return {0,0};
    }
    std::pair<std::size_t, std::size_t> ret{0,0};
    uint8_t standart_len = indata[1];
    std::size_t startpos = 2;
    standart_len &= static_cast<uint8_t>(wsf_hdr2b_t::HDR2_RMASK8B_LEN);
    if(standart_len <= 125) {
        ret.first = startpos;
        ret.second = standart_len;
    }
    else if(standart_len == 126) {
        const uint16_t *data16 = reinterpret_cast<const uint16_t*>(indata+startpos);
        startpos += 2;
        ret.first = startpos;
        ret.second = swaporder<uint16_t>(data16[0]);
    }
    else {
        const uint64_t *data64 = reinterpret_cast<const uint64_t*>(indata+startpos);
        startpos += 8;
        ret.first = startpos;
        ret.second = swaporder<uint64_t>(data64[0]);
    }
    if(ret.second > indata_len)
        return {0,0};
    return ret;
}

bool srinit() {
    std::srand(static_cast<unsigned>(std::time(nullptr)));
    return true;
}

wscurl::wsframe_t::wsframe_t(wsf_type_t type, bool final, bool ismask, const uint8_t *indata, std::size_t indata_len)
    : _type(type), _isfinal(final), _ismask(ismask)
{
    static bool srandinit = srinit(); // one time
    std::size_t data_len = 2;
    uint8_t frrr_opcode = final ? static_cast<uint8_t>(wsf_hdr1b_t::HDR1_FIN) : 0;
    std::size_t ext_len = 0;
    std::size_t masklen = ismask ? 4 : 0;
    if((indata_len + masklen) > 125) {
        if((indata_len + masklen + 2/*extlen*/) > 0x7fffff) ext_len = 8;
        else ext_len = 2;
    }
    switch (type) {
    case wsf_type_t::UNKNOWN_FRAME:
        break;
    case wsf_type_t::CONTTINUATION_FRAME:
        frrr_opcode |= static_cast<uint8_t>(wsf_hdr1b_t::HDR1_CONTTINUATION_FRAME);
        break;
    case wsf_type_t::CONNECTION_CLOSE_FRAME:
        frrr_opcode |= static_cast<uint8_t>(wsf_hdr1b_t::HDR1_CONNECTION_CLOSE_FRAME);
        break;
    case wsf_type_t::PING_FRAME:
        frrr_opcode |= static_cast<uint8_t>(wsf_hdr1b_t::HDR1_PING_FRAME);
        break;
    case wsf_type_t::PONG_FRAME:
        frrr_opcode |= static_cast<uint8_t>(wsf_hdr1b_t::HDR1_PONG_FRAME);
        break;
    case wsf_type_t::TEXT_FRAME:
        frrr_opcode |= static_cast<uint8_t>(wsf_hdr1b_t::HDR1_TEXT_FRAME);
        data_len += ext_len + masklen + indata_len;
        break;
    case wsf_type_t::BINARY_FRAME:
        frrr_opcode |= static_cast<uint8_t>(wsf_hdr1b_t::HDR1_BINARY_FRAME);
        data_len += ext_len + masklen + indata_len;
        break;
    }
    _data.resize(data_len);
    _data.data()[0] = frrr_opcode;

    if(type == wsf_type_t::CONNECTION_CLOSE_FRAME ||
       type == wsf_type_t::PING_FRAME || type == wsf_type_t::PONG_FRAME ||
       type == wsf_type_t::UNKNOWN_FRAME || indata_len == 0) {
        _data.data()[1] = 0;
        return; // no data
    }
    std::size_t difpos = 2;
    if(ext_len == 0) {
        _data.data()[1] = static_cast<uint8_t>(indata_len);
    }
    if(ext_len == 2) {
        _data.data()[1] = 0x7e;
        uint16_t *data16 = reinterpret_cast<uint16_t*>(_data.data()+difpos);
        data16[0] = swaporder<uint16_t>(static_cast<uint16_t>(indata_len));
    }
    else if(ext_len == 8) {
        _data.data()[1] = 0x7f;
        uint64_t *data64 = reinterpret_cast<uint64_t*>(_data.data()+difpos);
        data64[0] = swaporder<uint64_t>(static_cast<uint64_t>(indata_len));
    }
    if(ismask) {
        _data.data()[1] |= static_cast<uint8_t>(wsf_hdr2b_t::HDR2_MASK_FRAME); // masked data
    }
    difpos += ext_len;

    if(ismask) {
        uint32_t mask = static_cast<uint32_t>(std::rand());
        uint32_t *data32 = reinterpret_cast<uint32_t*>(_data.data()+difpos);
        data32[0] = mask;
        difpos += masklen;
    }
    uint8_t *data8 = _data.data() + difpos;
    std::copy(indata, indata+indata_len, data8);
    if(ismask) {
        uint8_t *mask8 = _data.data() + difpos - masklen;
        for(std::size_t i = 0; i < indata_len; ++i) {
            std::size_t j = i % 4;
            data8[i] = data8[i] ^ mask8[j]; // mask data
        }
    }
}

wscurl::wsframe_t::wsframe_t(const uint8_t *indata, std::size_t indata_len, bool &ok, std::string &err)
{
    ok = true;
    auto fssp = frame_startposition_size(indata, indata_len);
    if(fssp.second < 2) {
        ok = false;
        err = "Length data error ("+std::to_string(fssp.second)+")";
        return;
    }
    _ismask = (indata[1] & static_cast<uint8_t>(wsf_hdr2b_t::HDR2_MASK_FRAME)) != 0;
    _isfinal = (indata[0] & static_cast<uint8_t>(wsf_hdr1b_t::HDR1_FIN)) != 0;
    _type = frametype(indata[0]);
    switch (_type) {
    case wsf_type_t::PING_FRAME:
    case wsf_type_t::PONG_FRAME:
    case wsf_type_t::CONNECTION_CLOSE_FRAME:
    case wsf_type_t::UNKNOWN_FRAME:
        return;
    default:
        break;
    }
    if(_ismask && fssp.second < 4) {
        ok = false;
        err = "Length data+mask error ("+std::to_string(fssp.second)+")";
        return;
    }
    std::size_t datalen = fssp.second;
    if(datalen == 0) return;
    _data.resize(datalen);
    const uint8_t *in = indata + fssp.first + (_ismask ? 4 : 0);
    std::copy(in, in+datalen, _data.data());
    if(_ismask) {
        const uint8_t *mask8 = indata + fssp.first;
        for(std::size_t i = 0; i < datalen; ++i) {
            std::size_t j = i % 4;
            _data.data()[i] = _data.data()[i] ^ mask8[j]; // mask data
        }
    }
}

bool wscurl::wsframe_t::is_final()
{
    return _isfinal;
}

bool wscurl::wsframe_t::is_masked()
{
    return _ismask;
}

wscurl::wsf_type_t wscurl::wsframe_t::get_type()
{
    return _type;
}

wscurl::wsdata_t wscurl::wsframe_t::frame()
{
    return std::move(_data);
}

wscurl::wsdata_t wscurl::wsframe_t::getframe(wsf_type_t type, bool final, bool ismask, const uint8_t *indata, std::size_t indata_len)
{
    return wsframe_t(type, final, ismask, indata, indata_len).frame();
}

wscurl::wsframepool_t::wsframepool_t(wsf_type_t type, bool ismask, const uint8_t *data, std::size_t len)
    : _fin(data != nullptr), _type(type)
{
    _fin = true;
    if(len > 0x400000) {
        size_t cur_pos = 0;
        size_t cur_len = 0x400000;
        while(true) {
            _fin = (cur_pos+cur_len) == len;
            _pool.push_back(wsframe_t::getframe(cur_pos == 0 ? type : wsf_type_t::CONTTINUATION_FRAME, _fin, ismask, data+cur_pos, cur_len));
            cur_pos += cur_len;
            if(cur_pos >= len) break;
            if((len - cur_pos) > cur_len) {
                cur_len = len - cur_pos;
            }
        }
        return;
    }
    if(data && len > 0) _pool.push_back(wsframe_t::getframe(type, _fin, ismask, data, len));
}

std::vector<std::pair<const uint8_t*, std::size_t> > wscurl::wsframepool_t::getdata() const
{
    std::vector<std::pair<const uint8_t*, std::size_t>> ret;
    for(const auto &v: _pool)
        ret.push_back({v.data(), v.size()});
    return ret;
}

std::string wscurl::wsframepool_t::to_string() const
{
    std::ostringstream ost(std::ios::out);
    for(const auto &v: _pool)
        ost << std::string(reinterpret_cast<const char*>(v.data()), v.size());
    return ost.str();
}

wscurl::wsdata_t wscurl::wsframepool_t::to_binary() const
{
    wscurl::wsdata_t rdata;
    std::size_t fulllen = 0;
    for(const auto &v: _pool) fulllen += v.size();
    if(fulllen < 1)
        return rdata;
    rdata.resize(fulllen);
    fulllen = 0;
    for(const auto &v: _pool) {
        std::copy(v.begin(), v.end(), rdata.data() + fulllen);
        fulllen += v.size();
    }
    return rdata;
}

bool wscurl::wsframepool_t::add_frame(const uint8_t *data, std::size_t len)
{
    bool ok = false;
    wsframe_t frame(data, len, ok, _err);
    if(_pool.empty()) {
        _type = frame.get_type();
        _fin = frame.is_final();
        _pool.push_back(frame.frame());
        return ok;
    }
    if(!_fin) {
        if(_type == frame.get_type() || frame.get_type() == wsf_type_t::CONTTINUATION_FRAME) {
            _fin = frame.is_final();
            _pool.push_back(frame.frame());
            return ok;
        }
    }
    return false;
}

bool wscurl::wsframepool_t::is_finished() const
{
    return _fin;
}

void wscurl::wsframepool_t::clear()
{
    _pool.clear();
    _type = wsf_type_t::CONNECTION_CLOSE_FRAME;
    _fin = false;
}

std::string wscurl::wsframepool_t::error() const
{
    return _err;
}

wscurl::wsf_type_t wscurl::wsframepool_t::type() const
{
    return _type;
}
