// Parse a single MRT file with CAIDA BGPStream and count what was produced, without formatting.
// Two modes:
//   records : iterate bgpstream records only
//   elems   : iterate records and drain each record's elems (this is what forces attribute parsing)
#include <bgpstream.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <rib|upd> <file> <records|elems>\n", argv[0]);
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
    int elems_mode = strcmp(mode, "elems") == 0;

    int rv;
    while ((rv = bgpstream_get_next_record(bs, &record)) > 0) {
        records++;
        if (elems_mode) {
            while (bgpstream_record_get_next_elem(record, &elem) > 0) {
                elems++;
            }
        }
    }

    printf("records=%lld elems=%lld\n", records, elems);
    bgpstream_destroy(bs);
    return 0;
}
