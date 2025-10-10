#include "torrent.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: ./torque [torrent file]\n");
        exit(1);
    }

    const char* torrent_path = argv[1];
    torrent_file* tf = parse_torrent_file(torrent_path);
    if (!tf) {
        fprintf(stderr, "Error: could not parse torrent file: %s\n", torrent_path);
        exit(1);
    }

    const char* my_peer_id = "-TQ0001-ABCDEFGHIJKL";
    u16 my_port = 6881;
    time_t last_announce = 0;

    torrent_download* dwn = torrent_download_init(tf, my_peer_id, my_port);
    if (!dwn) {
        fprintf(stderr, "Error: could not init torrent download\n");
        free_torrent_file(tf);
        exit(1);
    }

    printf("Announcing to tracker...\n");
    if (!torrent_download_update_via_announce(dwn)) {
        fprintf(stderr, "Error: announce failed\n");
        torrent_download_free(dwn);
        free_torrent_file(tf);
        exit(1);
    }

    printf("Tracker returned %zu peers\n", dwn->num_peers);

    while (dwn->left > 0) {
        printf("Progress: downloaded=%zu / %zu bytes, left=%zu\n",
               dwn->downloaded, tf->length, dwn->left);

        sleep(5);


        time_t now = time(NULL);
        if (now - last_announce >= dwn->reannounce_interval) {
            torrent_download_update_via_announce(dwn);
            last_announce = now;
        }
    }

    printf("Download complete!\n");

    torrent_download_free(dwn);
    free_torrent_file(tf);
    return 0;
}
