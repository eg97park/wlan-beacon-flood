#include "BeaconFlood.h"
#include "tools.h"


const dot11_radiotap_hdr BeaconFlood::rtap_hdr = {
    .it_version = 0,
    .it_pad = 0,
    .it_len = 8,
    .it_present = 0
};

std::string BeaconFlood::get_random_ssid(size_t length)
{
    std::string ssid_cand = std::string(random_ssid_pool);
    std::random_device rd;
    std::mt19937_64 generator(rd());
    std::shuffle(ssid_cand.begin(), ssid_cand.end(), generator);
    return ssid_cand.substr(0, length);
}

BeaconFlood::BeaconFlood()
{
    this->beacon_fhdr.base.fctl_field = 0x0080;
    this->beacon_fhdr.base.duration = 0;
    this->beacon_fhdr.frag_seq_num = 0;

    for (size_t i = 0; i < 6; i++)
    {
        this->beacon_fhdr.rcv_addr[i] = 0xff;
    }

    for (size_t i = 0; i < 6; i++)
    {
        this->beacon_fhdr.src_addr[i] = SAMPLE_MAC_ADDR[i];
        this->beacon_fhdr.bssid[i] = SAMPLE_MAC_ADDR[i];
    }

    this->wlm_hdr.timestamp = 0;
    this->wlm_hdr.binterval = SAMPLE_BEACON_INTERVAL;
    this->wlm_hdr.cap_info = 0;
    this->ssid = this->get_random_ssid(14);
}

BeaconFlood::BeaconFlood(const uint8_t ap_mac_addr[6])
{
    this->beacon_fhdr.base.fctl_field = 0x0080;
    this->beacon_fhdr.base.duration = 0;
    this->beacon_fhdr.frag_seq_num = 0;

    for (size_t i = 0; i < 6; i++)
    {
        this->beacon_fhdr.rcv_addr[i] = 0xff;
    }

    for (size_t i = 0; i < 6; i++)
    {
        this->beacon_fhdr.src_addr[i] = ap_mac_addr[i];
        this->beacon_fhdr.bssid[i] = ap_mac_addr[i];
    }

    this->wlm_hdr.binterval = SAMPLE_BEACON_INTERVAL;
    this->wlm_hdr.timestamp = 0;
    this->wlm_hdr.cap_info = 0;
}

BeaconFlood::~BeaconFlood()
{
}

void BeaconFlood::set_ap_mac_addr(const uint8_t ap_mac_addr[6])
{
    for (size_t i = 0; i < 6; i++)
    {
        this->beacon_fhdr.src_addr[i] = ap_mac_addr[i];
        this->beacon_fhdr.bssid[i] = ap_mac_addr[i];
    }
}

void BeaconFlood::set_cap_info(const uint16_t cap_info)
{
    this->wlm_hdr.cap_info = cap_info;
}

beacon_flood_pkt* BeaconFlood::get_flood_pkt()
{
    this->ssid = std::string("GILGIL_TEST_") + this->get_random_ssid(12);
    uint8_t ssid_length = this->ssid.length();
    printf("SSID: %s was generated.\n", this->ssid.c_str());

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
    flood_pkt->packet = (u_char*)calloc(flood_pkt_size, sizeof(uint8_t));
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
    return flood_pkt;
}
