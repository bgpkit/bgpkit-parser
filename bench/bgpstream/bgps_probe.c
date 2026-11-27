// Parse a single MRT file with CAIDA BGPStream and run one application workload, without
// formatting anything.
//
//   records : iterate records only
//   elems   : iterate records and drain each record's elems
//   prefix  : iterate elems and hash each prefix (version, address bytes, mask length)
//   aspath  : iterate elems and sum the AS path lengths
#include <bgpstream.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint64_t fnv(uint64_t hash, const uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        hash ^= bytes[i];
        hash *= 0x00000100000001b3ULL;
    }
    return hash;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <rib|upd> <file> <records|elems|prefix|aspath>\n", argv[0]);
        return 2;
    }
    const char *kind = argv[1];
    const char *path = argv[2];
    const char *mode = argv[3];

    bgpstream_t *bs = bgpstream_create();
    if (bs == NULL) {
        fprintf(stderr, "bgpstream_create failed\n");
        return 1;
    }
    bgpstream_set_data_interface(bs, BGPSTREAM_DATA_INTERFACE_SINGLEFILE);
    bgpstream_data_interface_id_t di = BGPSTREAM_DATA_INTERFACE_SINGLEFILE;
    const char *opt_name = strcmp(kind, "rib") == 0 ? "rib-file" : "upd-file";
    bgpstream_data_interface_option_t *opt =
        bgpstream_get_data_interface_option_by_name(bs, di, opt_name);
    if (opt == NULL) {
        fprintf(stderr, "option %s not found\n", opt_name);
        return 1;
    }
    bgpstream_set_data_interface_option(bs, opt, path);
    if (bgpstream_start(bs) < 0) {
        fprintf(stderr, "bgpstream_start failed\n");
        return 1;
    }

    bgpstream_record_t *record = NULL;
    bgpstream_elem_t *elem = NULL;
    long long records = 0;
    long long elems = 0;
    uint64_t prefix_hash = 0xcbf29ce484222325ULL;
    long long asn_sum = 0;

    int elems_mode = strcmp(mode, "elems") == 0 || strcmp(mode, "prefix") == 0 ||
                     strcmp(mode, "aspath") == 0;

    int rv;
    while ((rv = bgpstream_get_next_record(bs, &record)) > 0) {
        records++;
        if (!elems_mode) {
            continue;
        }
        while (bgpstream_record_get_next_elem(record, &elem) > 0) {
            elems++;
            if (strcmp(mode, "prefix") == 0) {
                if (elem->prefix.address.version == BGPSTREAM_ADDR_VERSION_IPV4) {
                    uint32_t address = elem->prefix.address.bs_ipv4.addr.s_addr;
                    prefix_hash = fnv(prefix_hash, (const uint8_t *)&address, 4);
                } else {
                    prefix_hash =
                        fnv(prefix_hash, elem->prefix.address.bs_ipv6.addr.s6_addr, 16);
                }
                prefix_hash = fnv(prefix_hash, &elem->prefix.mask_len, 1);
            } else if (strcmp(mode, "aspath") == 0 && elem->as_path != NULL) {
                asn_sum += bgpstream_as_path_get_len(elem->as_path);
            }
        }
    }

    if (strcmp(mode, "prefix") == 0) {
        printf("records=%lld elems=%lld prefix_hash=%llu\n", records, elems,
               (unsigned long long)prefix_hash);
    } else if (strcmp(mode, "aspath") == 0) {
        printf("records=%lld elems=%lld asn_sum=%lld\n", records, elems, asn_sum);
    } else {
        printf("records=%lld elems=%lld\n", records, elems);
    }
    bgpstream_destroy(bs);
    return 0;
}
