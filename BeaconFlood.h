#include "pch.h"
#include "wlanhdr.h"


/**
 * @brief 샘플용 MAC 주소.
*/
const uint8_t SAMPLE_MAC_ADDR[6] = {
    0x00, 0x15, 0x5d, 0xb4, 0x82, 0xa0
};

/**
 * @brief 임의의 SSID, SUPPORTED_RATES, DS_PARAM, BEACON_INTERVAL 값.
*/
const uint8_t TAG_NUMBER_SSID = 0;
const uint8_t TAG_SUPPORTED_RATES[6] = {
    0x01, 0x04, 0x82, 0x84, 0x8b, 0x96
};
const uint8_t TAG_DS_PARAM_SET[6] = {
    0x03, 0x01, 0x01
};
const uint64_t SAMPLE_BEACON_INTERVAL = 0x6400;

/**
 * @brief 랜덤 SSID 생성에 사용될 문자.
*/
const std::string random_ssid_pool("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");

/**
 * @brief class BeaconFlood의 반환 값에 사용될 구조체.
*/
typedef struct WLAN_BEACON_FLOOD_PAKCET {
    u_char* packet;
    uint64_t size;
    std::string ssid;
} beacon_flood_pkt;


/**
 * @brief beacon-flood 패킷 생성용 클래스.
*/
class BeaconFlood
{
private:
    std::random_device rd;
    std::mt19937 gen;
    std::uniform_int_distribution<size_t> dis;

    static const dot11_radiotap_hdr rtap_hdr;
    dot11_beacon_fhdr beacon_fhdr;
    dot11_wlm_hdr wlm_hdr;
    std::string ssid;

    beacon_flood_pkt* make_flood_packet();

    /**
     * @ref https://stackoverflow.com/questions/47977829/generate-a-random-string-in-c11
    */
    std::string get_random_ssid(size_t length);

public:
    BeaconFlood();
    BeaconFlood(const uint8_t ap_mac_addr[6]);
    ~BeaconFlood();

    void init_flood_pkt();
    beacon_flood_pkt* get_random_flood_pkt();
    beacon_flood_pkt* get_flood_pkt(const std::string& ssid);
};
