#include "wlanhdr.h"
#include <random>
#include <string>
#include <algorithm>


const uint8_t SAMPLE_MAC_ADDR[6] = {
    0x00, 0x15, 0x5d, 0xb4, 0x82, 0xa0
};

const uint8_t TAG_NUMBER_SSID = 0;
const uint8_t TAG_SUPPORTED_RATES[6] = {
    0x01, 0x04, 0x82, 0x84, 0x8b, 0x96
};
const uint8_t TAG_DS_PARAM_SET[6] = {
    0x03, 0x01, 0x01
};
const uint64_t SAMPLE_BEACON_INTERVAL = 0x6400;

const std::string random_ssid_pool("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");

typedef struct WLAN_BEACON_FLOOD_PAKCET {
    u_char* packet;
    uint64_t size;
    std::string ssid;
} __attribute__((__packed__)) beacon_flood_pkt;

class BeaconFlood
{
private:
    static const dot11_radiotap_hdr rtap_hdr;
    dot11_beacon_fhdr beacon_fhdr;
    dot11_wlm_hdr wlm_hdr;
    std::string ssid;

    /**
     * @ref https://stackoverflow.com/questions/47977829/generate-a-random-string-in-c11
    */
    std::string get_random_ssid(size_t length);
public:
    BeaconFlood();
    BeaconFlood(const uint8_t ap_mac_addr[6]);
    ~BeaconFlood();

    void set_ap_mac_addr(const uint8_t ap_mac_addr[6]);
    void set_cap_info(const uint16_t cap_info);
    void set_ssid(const std::string ssid);
    beacon_flood_pkt* get_flood_pkt();
};
