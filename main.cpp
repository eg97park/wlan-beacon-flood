#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <memory.h>

#include <unistd.h>

#include <string>

#include "wlanhdr.h"
#include "tools.h"



int main(int argc, char* argv[]) {
    Param param = {
        .dev_ = NULL
    };

    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }
    
    const char* SLASH_LINE = "------------------------------------------------";
    const int TAGGED_PARAMS_RAW[] = {
        0x00,
        0x00
    };

    fake_dot11_bpkt* fpkt = (fake_dot11_bpkt*)calloc(sizeof(fake_dot11_bpkt) + 100, sizeof(uint8_t));

    fpkt->radiotap_hdr.it_version = 0;
    fpkt->radiotap_hdr.it_pad = 0;
    fpkt->radiotap_hdr.it_len = 8;
    fpkt->radiotap_hdr.it_present = 0;


    fpkt->beacon_hdr.base.fctl_field = 0x0080;
    fpkt->beacon_hdr.base.flags = 0;

    uint8_t RANDOM_MAC_ADDR[6] = {
        0xa,
        0xa,
        0xa,
        0xa,
        0xa,
        0xa
    };

    std::memcpy(fpkt->beacon_hdr.rcv_addr, BROADCAST_MAC_ADDR, sizeof(BROADCAST_MAC_ADDR));
    std::memcpy(fpkt->beacon_hdr.src_addr, RANDOM_MAC_ADDR, sizeof(RANDOM_MAC_ADDR));
    std::memcpy(fpkt->beacon_hdr.bssid, RANDOM_MAC_ADDR, sizeof(RANDOM_MAC_ADDR));
    fpkt->beacon_hdr.frag_seq_num = 0;

    fpkt->wlm_hdr.timestamp = 0;

    /**
     * @ref https://www.oreilly.com/library/view/80211-wireless-networks/0596100523/ch04.html
    */
    fpkt->wlm_hdr.binterval = 0x1431;
    fpkt->wlm_hdr.cap_info = 0;


    uint8_t* tag_addr = (uint8_t*)(&(fpkt->wlm_hdr.timestamp)) + sizeof(fpkt->wlm_hdr);

    const char* SSID_STRING = "GILGIL_HW_TEST";
    uint8_t TAG_NUMBER_SSID = 0;
    std::memcpy(
        tag_addr,
        &TAG_NUMBER_SSID,
        sizeof(TAG_NUMBER_SSID)
    );
    uint8_t TAG_LENGTH_SSID = sizeof(char) * strlen(SSID_STRING);
    std::memcpy(
        tag_addr + sizeof(TAG_NUMBER_SSID),
        &TAG_LENGTH_SSID,
        sizeof(TAG_LENGTH_SSID)
    );
    std::memcpy(
        tag_addr + sizeof(TAG_NUMBER_SSID) + sizeof(TAG_LENGTH_SSID),
        SSID_STRING,
        sizeof(char) * TAG_LENGTH_SSID
    );

    uint8_t TAG_NUMBER_SUPPORTED_RATES = 1;
    std::memcpy(
        tag_addr + sizeof(TAG_NUMBER_SSID) + sizeof(TAG_LENGTH_SSID) + sizeof(char) * TAG_LENGTH_SSID,
        &TAG_NUMBER_SUPPORTED_RATES,
        sizeof(TAG_NUMBER_SUPPORTED_RATES)
    );
    uint8_t TAG_SUPPORTED_RATES[] = { 0x82, 0x84, 0x8b, 0x96 };
    uint8_t TAG_LENGTH_SUPPORTED_RATES = sizeof(TAG_SUPPORTED_RATES);
    std::memcpy(
        tag_addr + sizeof(TAG_NUMBER_SSID) + sizeof(TAG_LENGTH_SSID) + sizeof(char) * TAG_LENGTH_SSID
         + sizeof(TAG_NUMBER_SUPPORTED_RATES),
        &TAG_LENGTH_SUPPORTED_RATES,
        sizeof(TAG_LENGTH_SUPPORTED_RATES)
    );
    std::memcpy(
        tag_addr + sizeof(TAG_NUMBER_SSID) + sizeof(TAG_LENGTH_SSID) + sizeof(char) * TAG_LENGTH_SSID
         + sizeof(TAG_NUMBER_SUPPORTED_RATES) + sizeof(TAG_LENGTH_SUPPORTED_RATES),
        TAG_SUPPORTED_RATES,
        sizeof(TAG_SUPPORTED_RATES)
    );

    while (true)
    {
        sleep(0);
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(fpkt),
            sizeof(fpkt->radiotap_hdr) +
            sizeof(fpkt->beacon_hdr) +
            sizeof(fpkt->wlm_hdr) +
            sizeof(TAG_NUMBER_SSID) + 
            sizeof(TAG_LENGTH_SSID) + 
            sizeof(char) * TAG_LENGTH_SSID +
            sizeof(TAG_NUMBER_SUPPORTED_RATES) +
            sizeof(TAG_LENGTH_SUPPORTED_RATES) +
            sizeof(TAG_SUPPORTED_RATES)
        );
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket error=%s\n", pcap_geterr(handle));
            pcap_close(handle);
            return -1;
        }

        dump(fpkt,
            sizeof(fpkt->radiotap_hdr) +
            sizeof(fpkt->beacon_hdr) +
            sizeof(fpkt->wlm_hdr) +
            sizeof(TAG_NUMBER_SSID) + 
            sizeof(TAG_LENGTH_SSID) + 
            sizeof(char) * TAG_LENGTH_SSID +
            sizeof(TAG_NUMBER_SUPPORTED_RATES) +
            sizeof(TAG_LENGTH_SUPPORTED_RATES) +
            sizeof(TAG_SUPPORTED_RATES)
        );
        printf("%s\n", SLASH_LINE);
    }
    
    pcap_close(handle);
	return 0;
}
