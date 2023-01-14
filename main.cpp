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

    fpkt->wlm_hdr.timestamp = 1090326527994;
    fpkt->wlm_hdr.binterval = 0;
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

    uint8_t TAG_NUMBER_DS_PARAM[3] = { 0x03, 0x01, 0x01 };
    std::memcpy(
        tag_addr + sizeof(TAG_NUMBER_SSID) + sizeof(TAG_LENGTH_SSID) + sizeof(char) * TAG_LENGTH_SSID
         + sizeof(TAG_NUMBER_SUPPORTED_RATES) + sizeof(TAG_LENGTH_SUPPORTED_RATES) + sizeof(TAG_SUPPORTED_RATES),
        &TAG_NUMBER_DS_PARAM,
        sizeof(TAG_NUMBER_DS_PARAM)
    );

    const uint8_t vendor_spec[] = {
        0xdd, 0x0b, 0x8c, 0xfd, 0xf0, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01,
        0xdd, 0x05, 0x00, 0x16, 0x32, 0x80, 0x00,
        0xdd, 0x08, 0x00, 0x50, 0xf2, 0x11, 0x02, 0x00, 0x00, 0x00
    };
    std::memcpy(
        tag_addr + sizeof(TAG_NUMBER_SSID) + sizeof(TAG_LENGTH_SSID) + sizeof(char) * TAG_LENGTH_SSID
         + sizeof(TAG_NUMBER_SUPPORTED_RATES) + sizeof(TAG_LENGTH_SUPPORTED_RATES) + sizeof(TAG_SUPPORTED_RATES)
         + sizeof(TAG_NUMBER_DS_PARAM),
        vendor_spec,
        sizeof(vendor_spec)
    );

    // const char* sample_pkt = "\x00\x00\x38\x00\x2f\x40\x40\xa0\x20\x08\x00\xa0\x20\x08\x00\x00\x4d\x41\x30\x18\x00\x00\x00\x00\x10\x02\x6c\x09\xa0\x00\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x2d\x6f\x31\x18\x00\x00\x00\x00\x16\x00\x11\x03\xc6\x00\xc8\x01\x80\x00\x00\x00\xff\xff\xff\xff\xff\xff\x8e\x19\x05\xec\x05\x2e\x8e\x19\x05\xec\x05\x2e\x20\xc0\xfa\x7f\x86\xdc\xfd\x00\x00\x00\x64\x00\x31\x14\x00\x0d\x41\x42\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x01\x04\x82\x84\x8b\x96\x03\x01\x01\x05\x04\x00\x02\x00\x00\x07\x06\x4b\x52\x04\x01\x0d\x17\x3b\x06\x51\x53\x54\x7d\x80\x81\x2a\x01\x00\x32\x08\x0c\x12\x18\x24\x30\x48\x60\x6c\x30\x14\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x0c\x00\x2d\x1a\xad\x09\x13\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x3d\x16\x01\x00\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xdd\x18\x00\x50\xf2\x02\x01\x01\x81\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00\xbf\x0c\x92\x79\x81\x33\xfa\xff\x62\x03\xfa\xff\x62\x03\xc0\x05\x00\x00\x00\xfa\xff\xc3\x02\x00\x17\x7f\x08\x04\x00\x00\x00\x00\x00\x00\x40\xdd\x0b\x8c\xfd\xf0\x01\x01\x02\x01\x00\x02\x01\x01\xdd\x05\x00\x16\x32\x80\x00\xdd\x08\x00\x50\xf2\x11\x02\x00\x00\x00\x13\x07\xb7\xca";

    while (true)
    {
        sleep(0);
        /*
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(sample_pkt),
            320
        );
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket error=%s\n", pcap_geterr(handle));
            pcap_close(handle);
            return -1;
        }
        */
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(fpkt),
            sizeof(fpkt->radiotap_hdr) +
            sizeof(fpkt->beacon_hdr) +
            sizeof(fpkt->wlm_hdr) +
            sizeof(TAG_NUMBER_SSID) + 
            sizeof(TAG_LENGTH_SSID) + 
            sizeof(char) * TAG_LENGTH_SSID +
            sizeof(TAG_NUMBER_SUPPORTED_RATES) +
            sizeof(TAG_LENGTH_SUPPORTED_RATES) +
            sizeof(TAG_SUPPORTED_RATES) + 
            sizeof(TAG_NUMBER_DS_PARAM) + 
            sizeof(vendor_spec)
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
            sizeof(TAG_SUPPORTED_RATES) + 
            sizeof(TAG_NUMBER_DS_PARAM) + 
            sizeof(vendor_spec)
        );
        printf("%s\n", SLASH_LINE);
    }
    
    pcap_close(handle);
	return 0;
}
