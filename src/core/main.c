#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vigil/capture.h"

/* ── Printing helpers ──────────────────────────────────────────────── */

void print_hex(const u_char* packet, int caplen) {
    for (int i = 0; i < caplen; i++) {
        if (i % 16 == 0) printf("%04x: ", i & ~0xF);
        printf("%02x ", packet[i]);
        if (i % 16 == 15) printf("\n");
    }
    printf("\n");
}

void print_mac(const char* label, const uint8_t* mac) {
    printf("%s", label);
    for (int i = 0; i < 6; i++) {
        printf("%02x", mac[i]);
        if (i < 5) printf(":");
    }
}

int main(int argc, char* argv[]) {
    char* interface_name = NULL;
    int should_free = 0;
    int verbose = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0)
            verbose = 1;
        else
            interface_name = argv[i];
    }

    if (!interface_name) {
        pcap_if_t* devs;
        char errbuf[PCAP_ERRBUF_SIZE];
        if (pcap_findalldevs(&devs, errbuf) == -1 || !devs) {
            fprintf(stderr, "No interfaces found: %s\n", errbuf);
            return 1;
        }
        interface_name = strdup(devs->name);
        should_free = 1;
        pcap_freealldevs(devs);
        printf("Auto-selected interface: %s\n", interface_name);
    }

    CaptureConfig config = {
        .interface_name = interface_name,
        .snapshot_length = 262144,
        .promiscuous = 1,
        .capture_timeout = 1000,
        .verbose = verbose,
    };

    CaptureHandle* handle = capture_open(&config);
    if (!handle) {
        fprintf(stderr, "capture_open failed: %s\n", config.errbuf);
        return 1;
    }

    capture_start(handle);
    capture_close(handle);
    if (should_free) free(interface_name);
    return 0;
}