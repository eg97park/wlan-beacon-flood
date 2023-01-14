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

    fake_dot11_bpkt* fpkt = (fake_dot11_bpkt*)malloc(sizeof(fake_dot11_bpkt) + 12);

    fpkt->radiotap_hdr.it_version = 0;
    fpkt->radiotap_hdr.it_pad = 0;
    fpkt->radiotap_hdr.it_len = 12;
    fpkt->radiotap_hdr.it_present = 0;

    fpkt->beacon_hdr.base.fctl_field = 0x0080;
    fpkt->beacon_hdr.base.flags = 0;

    uint8_t RANDOM_MAC_ADDR[6] = {
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06
    };

    std::memcpy(fpkt->beacon_hdr.rcv_addr, BROADCAST_MAC_ADDR, sizeof(BROADCAST_MAC_ADDR));
    std::memcpy(fpkt->beacon_hdr.src_addr, RANDOM_MAC_ADDR, sizeof(RANDOM_MAC_ADDR));
    std::memcpy(fpkt->beacon_hdr.bssid, RANDOM_MAC_ADDR, sizeof(RANDOM_MAC_ADDR));
    dump(&(fpkt->radiotap_hdr), sizeof(fpkt->radiotap_hdr) + sizeof(fpkt->beacon_hdr));
    fpkt->beacon_hdr.frag_seq_num = 0;

    fpkt->wlm_hdr.timestamp = 0;
    fpkt->wlm_hdr.binterval = 0;
    fpkt->wlm_hdr.cap_info = 0;
    std::memcpy(fpkt->wlm_hdr.tag_addr(), "\x00\x08\x41\x42\x41\x42\x41\x42\x41\x00", sizeof("\x00\x08\x41\x42\x41\x42\x41\x42\x41\x00"));
    dump(&(fpkt->radiotap_hdr), sizeof(fpkt->radiotap_hdr) + sizeof(fpkt->beacon_hdr) + sizeof(fpkt->wlm_hdr) + sizeof(RANDOM_MAC_ADDR));

    while (true)
    {
        sleep(0);
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&handle), sizeof(fpkt->radiotap_hdr) + sizeof(fpkt->beacon_hdr) + sizeof(RANDOM_MAC_ADDR));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket error=%s\n", pcap_geterr(handle));
            pcap_close(handle);
            return -1;
        }
        dump(&(fpkt->radiotap_hdr), sizeof(fpkt->radiotap_hdr) + sizeof(fpkt->beacon_hdr) + sizeof(fpkt->wlm_hdr) + sizeof(RANDOM_MAC_ADDR));
        printf("%s\n", SLASH_LINE);
    }
    
    pcap_close(handle);
	return 0;
}
