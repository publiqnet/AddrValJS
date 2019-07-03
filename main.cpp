#include <cryptopp/config.h>
#ifndef CRYPTOPP_NO_GLOBAL_BYTE
namespace CryptoPP
{
    typedef unsigned char byte;
}
#endif

#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/keccak.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/ripemd.h>

#include <sstream>
#include <iostream>

static CryptoPP::SHA512     _sha512;
static CryptoPP::SHA256     _sha256;
static CryptoPP::RIPEMD160  _rmd160;
static CryptoPP::Keccak_256 _kck256;

using buf64 = unsigned char [64];
using buf32 = unsigned char [32];
using buf20 = unsigned char [20];

static std::vector<unsigned char> from_hex(std::string const &x_str);


static void sha512(buf64 ret, unsigned char *data, uint32_t sz)
{
    _sha512.CalculateDigest(ret, data, sz);
}


static void sha256(buf32 ret, unsigned char *data, uint32_t sz)
{
    _sha256.CalculateDigest(ret, data, sz);
}

static void rmd160(buf20 ret, unsigned char *data, uint32_t sz)
{
    _rmd160.CalculateDigest(ret, data, sz);
}

static void kck256(buf32 ret, unsigned char *data, uint32_t sz)
{
    _kck256.CalculateDigest(ret, data, sz);
}

CryptoPP::Integer _from_base58(std::string const & b58_str)
{
    std::string alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    size_t b = alphabet.length();

    CryptoPP::Integer res = 0, e = 1;
    for(auto it = b58_str.rbegin(); it != b58_str.rend(); ++it)
    {
        auto i = alphabet.find_first_of(*it);
        res += i*e;
        e *= b;
    }

    return res;
}

std::vector<unsigned char> from_base58(std::string const & b58_str)
{
    auto res = _from_base58(b58_str);
    std::vector<unsigned char> buf(res.ByteCount());

    res.Encode(&buf[0], buf.size());
    return buf;
}

template <typename HASH, uint8_t chk_sz = 4>
bool validate_pk(std::string const & addr, HASH _hash)
{
    auto vch = from_base58(addr);

    if ( vch.size() > chk_sz)
    {
        std::string result(vch.begin(), vch.end() - chk_sz);
        std::string chk_str_(vch.end() - chk_sz, vch.end());
        std::string chk_str{};

        CryptoPP::StringSource ss(result, true,
                                  new CryptoPP::HashFilter(_hash, new CryptoPP::StringSink(chk_str)));
        chk_str.resize(chk_sz);

        if(chk_str == chk_str_)
            return true;
    }
    return false;
}

bool validate_CVA(std::string addr)
{
    if (addr.substr(0, 3) != "CVA")
        return false;
    addr = addr.substr(3);

    auto delim = addr.find("_");
    if(delim == std::string::npos)
        return validate_pk(addr, _rmd160);

    auto A = addr.substr(0, delim);
    auto B = addr.substr(delim + 1);

    return validate_pk(A, _rmd160) && validate_pk(B, _rmd160);
}

bool validate_PBQ(std::string addr)
{
    if (addr.substr(0, 3) != "PBQ")
        return false;
    addr = addr.substr(3);

    return validate_pk(addr, _rmd160);
}

bool validate_ETH(std::string addr)
{
    auto delim = addr.find("x");
    if(delim != std::string::npos)
        addr = addr.substr(delim + 1);

    if(addr.length( ) != 2 * 20)
        return false;

    auto addr_ = addr;
    for(auto &&i : addr_)
        i = std::tolower(i);

    buf32 hash;
    kck256(hash, (unsigned char *) addr_.data( ), addr_.length( ));

    for(uint8_t i = 0; i < addr.length( ); ++i)
    {
        uint8_t bit_n  = i % 2 ? 0x08 : 0x80;
        uint8_t byte_n = i >> 1;
        uint8_t chk    = hash[byte_n] & bit_n;
        switch(addr[i])
        {
            case 'A':
            case 'B':
            case 'C':
            case 'D':
            case 'E':
            case 'F':
            {
                if(0 == chk)
                    return false;
                break;
            }
            case 'a':
            case 'b':
            case 'c':
            case 'd':
            case 'e':
            case 'f':
            {
                if(0 != chk)
                    return false;
                break;
            }
        }
    }

    return true;
}

bool validate_BTC(std::string addr)
{
    uint8_t chk_sz = 4;
    auto    vch    = from_base58(addr);

    auto sz = vch.size( );
    if(sz < 1 + 20 + chk_sz)
    {
        vch.resize(1 + 20 + chk_sz);
        std::move(vch.begin( ), vch.begin( ) + sz, vch.begin( ) + vch.size( ) - sz);
        std::fill(vch.begin( ), vch.begin( ) + vch.size( ) - sz, 0);
    }

    switch(vch[0])
    {
        case 0:
        case 5:
        {
            std::string result(vch.begin( ), vch.end( ) - chk_sz);
            std::string chk_str_(vch.end( ) - chk_sz, vch.end( ));

            buf32 chk_str, chk_str__;
            sha256(chk_str__, (unsigned char *) result.data( ), result.size( ));
            sha256(chk_str, chk_str__, sizeof(chk_str__));

            if(0 == memcmp(chk_str, chk_str_.data( ), chk_sz))
                return true;
        }
    }

    return false;
}



static std::vector<unsigned char> from_hex(std::string const &x_str)
{
    CryptoPP::HexDecoder _xdec;
    _xdec.PutMessageEnd((CryptoPP::byte *) x_str.c_str( ), x_str.size( ));

    size_t size = _xdec.MaxRetrievable( );
    if(size)
    {
        std::vector<unsigned char> result(size);
        _xdec.Get(result.data( ), size);
        return result;
    }
    return {};
}

template<typename T, size_t N>
std::string to_hex(T const (&data)[N])
{
    CryptoPP::HexEncoder _xenc(nullptr, false);
    _xenc.PutMessageEnd((CryptoPP::byte *) data, N);

    size_t size = _xenc.MaxRetrievable( );
    if(size)
    {
        std::string result(size, '\0');
        _xenc.Get((CryptoPP::byte *) result.data( ), size);
        return result;
    }
    return {};
}

std::string aes_encrypt(std::string plain_data, buf64 secret, bool add_checksum = false)
{
    std::string encrypted_data;
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption aes;
    aes.SetKeyWithIV(secret, 32, &secret[32]);

    if(add_checksum)
    {
        char ret[32];
        sha256((unsigned char *)ret, (unsigned char *)plain_data.data(), plain_data.size());
        plain_data = std::string(ret, 4) + plain_data;
    }

    CryptoPP::StringSource(plain_data, true, new CryptoPP::StreamTransformationFilter(aes, new CryptoPP::StringSink(encrypted_data)));

    return encrypted_data;
}

std::string aes_decrypt(std::string encrypted_data, buf64 secret, bool check_checksum = false)
{
    std::string plain_data;
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption aes;
    aes.SetKeyWithIV(secret, 32, &secret[32]);
    CryptoPP::StringSource(encrypted_data, true, new CryptoPP::StreamTransformationFilter(aes, new CryptoPP::StringSink(plain_data)));
    if(check_checksum)
    {
        auto check_str = plain_data.substr(0, 4);
        plain_data = plain_data.substr(4);
        char ret[32];
        sha256((unsigned char *)ret, (unsigned char *)plain_data.data(), plain_data.size());
        if(0 == memcmp(plain_data.data(), ret, 4))
            return plain_data;
        return "";
    }

    return plain_data;
}

static uint64_t str_to_u64(std::string str)
{
    uint64_t res = 0, e = 1;
    for( auto it = str.rbegin(); it != str.rend(); ++it)
    {
        char c[1];
        c[0] = *it;
        res += e * std::atoi(c);
        e *= 10;
    }

    return res;
}

#ifndef __EMSCRIPTEN__
int main()
{
    std::cout<<validate_ETH("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")<<std::endl;
    std::cout<<validate_ETH("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359")<<std::endl;
    std::cout<<validate_ETH("0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB")<<std::endl;
    std::cout<<validate_ETH("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")<<std::endl;
    std::cout<<validate_BTC("17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem")<<std::endl;
    std::cout<<validate_BTC("3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX")<<std::endl;
    std::cout<<validate_CVA("CVA6y5UDn3dkNrkzz5NUtbCZFE3ohUS6xrXGJrz8iFrUGb232E6hf")<<std::endl;
    std::cout<<validate_CVA("CVA6SK6R4CP1yKoD2PQNq99y9v4JiVfXoamv3ZM281bZWo9iCZbLc_84ENZXQRFZtA5pP7SvguYe964MBcahB3EA9FoMWor4KyYTrH73")<<std::endl;

    return 0;
}
#else
#include <emscripten/bind.h>

using namespace emscripten;

EMSCRIPTEN_BINDINGS(addrvaljs)
{
    function("validate_CVA", &validate_CVA);
    function("validate_PBQ", &validate_PBQ);
    function("validate_ETH", &validate_ETH);
    function("validate_BTC", &validate_BTC);
};
#endif
