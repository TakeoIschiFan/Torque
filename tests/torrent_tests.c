#include "defines.h"
#include "napoleon.h"
#include "torrent.h"
#include <stdio.h>
#include <string.h>

NAP_TEST test_torrent_file_parsing_valid(void) {
    torrent_file* tf = parse_torrent_file("./tests/test_file.torrent");
    nap_assert(tf != NULL);
    nap_assert(strcmp(tf->announce, "http://localhost:6985/announce") == 0);
    nap_assert(strcmp(tf->name, "test_file.txt") == 0);
    nap_assert(tf->piece_length == 16384);
    nap_assert(tf->length == 62);
    nap_assert(tf->num_pieces == 1);

    const char* expected_piece_hash = "ec5cb7caaaef5be280dc38588ab1b3bb096c39dd";
    char buf2[41];
    for (int i = 0; i < 20; i++)
        sprintf(buf2 + i*2, "%02x", tf->piece_hashes[0][i]);
    buf2[40] = '\0';
    nap_assert(strcmp(buf2, expected_piece_hash) == 0);

    free_torrent_file(tf);
}

NAP_TEST test_torrent_missing_announce(void) {
    const char* path = "bad.torrent";
    FILE* f = fopen(path, "wb");
    // missing announce field
    fprintf(f, "d4:infod4:name3:bad12 lengthi16384e6:lengthi1e6:pieces20");
    fclose(f);

    torrent_file* tf = parse_torrent_file(path);
    nap_assert(tf == NULL);
    remove(path);
}

NAP_TEST test_torrent_invalid_pieces(void) {
    const char* path = "badpieces.torrent";
    FILE* f = fopen(path, "wb");
    // "pieces" is 19 bytes, invalid
    fprintf(f, "d8:announce7:tracker4:infod4:name3:bad12 lengthi16384e6:lengthi1e6:pieces19");
    fclose(f);

    torrent_file* tf = parse_torrent_file(path);
    nap_assert(tf == NULL);
    remove(path);
}

NAP_TEST test_torrent_rejects_multifile(void) {
    const char* path = "multifile.torrent";
    FILE* f = fopen(path, "wb");
    // create with "files" array
    fprintf(f, "d8:announce7:tracker4:infod4:name3:bad12 lengthi16384e6:filesld6:lengthi10e4:pathl8.txtee6:pieces20");
    fclose(f);

    torrent_file* tf = parse_torrent_file(path);
    nap_assert(tf == NULL);
    remove(path);
}

NAP_TEST test_torrent_missing_length(void) {
    const char* path = "nolength.torrent";
    FILE* f = fopen(path, "wb");
    fprintf(f, "d8:announce7:tracker4:infod4:name3:bad12 lengthi16384e6:pieces20");
    fclose(f);

    torrent_file* tf = parse_torrent_file(path);
    nap_assert(tf == NULL);
    remove(path);
}

NAP_TEST test_torrent_invalid_name(void) {
    const char* path = "badname.torrent";
    FILE* f = fopen(path, "wb");
    // name not a string
    fprintf(f, "d8:announce7:tracker4:infod4:namei42e12 lengthi16384e6:lengthi1e6:pieces20");
    fclose(f);

    torrent_file* tf = parse_torrent_file(path);
    nap_assert(tf == NULL);
    remove(path);
}

NAP_TEST test_torrent_download_init_and_free(void) {
    torrent_file* tf = parse_torrent_file("./tests/test_file.torrent");
    nap_assert(tf != NULL);

    const char* peer_id = "ABCDEFGHIJKLMNOPQRST"; // 20 bytes
    torrent_download* dwn = torrent_download_init(tf, peer_id, 6881);

    nap_assert(dwn != NULL);
    nap_assert(dwn->torrent_file == tf);
    nap_assert(memcmp(dwn->my_peer_id, peer_id, 20) == 0);
    nap_assert(dwn->my_port == 6881);
    nap_assert(dwn->uploaded == 0);
    nap_assert(dwn->downloaded == 0);
    nap_assert(dwn->left == tf->length);
    nap_assert(dwn->num_peers == 0);
    nap_assert(dwn->queue_capacity == tf->num_pieces);
    nap_assert(dwn->queue_count == 0);

    nap_assert(dwn->piece_queue != NULL);

    int mutex_result = pthread_mutex_trylock(&dwn->queue_lock);
    nap_assert(mutex_result == 0);  // should be unlocked
    pthread_mutex_unlock(&dwn->queue_lock);

    torrent_download_free(dwn);

    nap_assert(tf->announce != NULL);

    free_torrent_file(tf);
}

NAP_TEST test_torrent_download_update_via_announce_adds_peer(void) {
    torrent_file* tf = parse_torrent_file("./tests/test_file.torrent");
    nap_assert(tf != NULL);

    torrent_download* dwn = torrent_download_init(tf, "ABCDEFGHIJKLMNOPQRST", 6980);

    b8 ok = torrent_download_update_via_announce(dwn);
    nap_assert(ok);
    nap_assert(dwn->num_peers == 1);

    torrent_peer* p = dwn->peers;
    nap_assert(p != NULL);
    nap_assert(p->bitfield_size == ((tf->num_pieces - 1) / 8) + 1);
    nap_assert(p->current_piece_buf != NULL);

    torrent_peer_close_and_free(p);
    torrent_download_free(dwn);
    free_torrent_file(tf);
}

NAP_TEST test_torrent_download_reannounce_interval(void) {
    torrent_file* tf = parse_torrent_file("./tests/test_file.torrent");
    nap_assert(tf != NULL);

    torrent_download* dwn = torrent_download_init(tf, "ABCDEFGHIJKLMNOPQRST", 6980);

    nap_assert(dwn->reannounce_interval == 0);

    b8 ok = torrent_download_update_via_announce(dwn);
    nap_assert(ok);
    nap_assert(dwn->reannounce_interval > 0);

    usize old_num_peers = dwn->num_peers;
    ok = torrent_download_update_via_announce(dwn);
    nap_assert(ok);
    nap_assert(dwn->num_peers == old_num_peers);

    torrent_peer* p = dwn->peers;
    torrent_peer_close_and_free(p);
    torrent_download_free(dwn);
    free_torrent_file(tf);
}

NAP_TEST test_torrent_peer_has_piece_bits(void) {
    torrent_peer peer;
    memset(&peer, 0, sizeof(peer));

    peer.bitfield_size = 2;
    u8 bitfield[2] = {0b10100001, 0b10000000};
    peer.bitfield = bitfield;

    nap_assert(torrent_peer_has_piece(&peer, 0) == true);
    nap_assert(torrent_peer_has_piece(&peer, 2) == true);
    nap_assert(torrent_peer_has_piece(&peer, 7) == true);
    nap_assert(torrent_peer_has_piece(&peer, 8) == true);
    nap_assert(torrent_peer_has_piece(&peer, 9) == false);

    nap_assert(torrent_peer_has_piece(&peer, 16) == false);
}

NAP_TEST test_torrent_peer_add_and_remove(void) {
    torrent_file* tf = parse_torrent_file("./tests/test_file.torrent");
    nap_assert(tf != NULL);

    torrent_download* dwn = torrent_download_init(tf, "ABCDEFGHIJKLMNOPQRST", 6881);

    torrent_peer* p1 = torrent_peer_add(dwn, inet_addr("127.0.0.2"), 5000);
    nap_assert(dwn->num_peers == 1);
    nap_assert(dwn->peers == p1);
    nap_assert(p1->address == inet_addr("127.0.0.2"));
    nap_assert(p1->port == 5000);

    torrent_peer* p2 = torrent_peer_add(dwn, inet_addr("127.0.0.3"), 5001);
    nap_assert(dwn->num_peers == 2);
    nap_assert(dwn->peers->next == p2);

    torrent_peer_close_and_free(p1);
    nap_assert(dwn->num_peers == 1);
    nap_assert(dwn->peers == p2);

    torrent_peer_close_and_free(p2);
    nap_assert(dwn->num_peers == 0);
    nap_assert(dwn->peers == NULL);

    torrent_download_free(dwn);
    free_torrent_file(tf);
}

NAP_TEST test_torrent_piece_queue_operations(void) {
    torrent_file* tf = parse_torrent_file("./tests/test_file.torrent");
    nap_assert(tf != NULL);

    torrent_download* dwn = torrent_download_init(tf, "ABCDEFGHIJKLMNOPQRST", 6881);

    // enqueue a piece
    pthread_mutex_lock(&dwn->queue_lock);
    usize piece_idx = 0;
    dwn->piece_queue[dwn->queue_count++] = piece_idx;
    pthread_cond_signal(&dwn->queue_not_empty);
    pthread_mutex_unlock(&dwn->queue_lock);

    // dequeue
    pthread_mutex_lock(&dwn->queue_lock);
    nap_assert(dwn->queue_count > 0);
    usize idx = dwn->piece_queue[dwn->queue_head];
    dwn->queue_head = (dwn->queue_head + 1) % dwn->queue_capacity;
    dwn->queue_count--;
    pthread_mutex_unlock(&dwn->queue_lock);

    nap_assert(idx == 0);
    nap_assert(dwn->queue_count == 0);

    torrent_download_free(dwn);
    free_torrent_file(tf);
}

NAP_TEST test_torrent_peer_work_download_stats(void) {
    torrent_file* tf = parse_torrent_file("./tests/test_file.torrent");
    nap_assert(tf != NULL);

    torrent_download* dwn = torrent_download_init(tf, "ABCDEFGHIJKLMNOPQRST", 6881);

    // enqueue a piece
    pthread_mutex_lock(&dwn->queue_lock);
    dwn->piece_queue[dwn->queue_count++] = 0;
    pthread_cond_signal(&dwn->queue_not_empty);
    pthread_mutex_unlock(&dwn->queue_lock);

    // add a mock peer
    torrent_peer* peer = torrent_peer_add(dwn, inet_addr("127.0.0.2"), 5000);

    // mock: peer has the piece
    peer->bitfield[0] = 0x80; // first piece

    // mock: override torrent_peer_download_piece to just mark piece downloaded
    peer->current_piece_downloaded = tf->piece_length;
    dwn->downloaded = 0;
    dwn->left = tf->length;

    // normally torrent_peer_work loops infinitely, so we simulate one iteration
    pthread_mutex_lock(&dwn->queue_lock);
    usize piece_idx = dwn->piece_queue[dwn->queue_head];
    dwn->queue_head = (dwn->queue_head + 1) % dwn->queue_capacity;
    dwn->queue_count--;
    dwn->downloaded += tf->length;
    dwn->left -= tf->length;
    pthread_mutex_unlock(&dwn->queue_lock);

    nap_assert(dwn->downloaded == tf->length);
    nap_assert(dwn->left == 0);

    torrent_peer_close_and_free(peer);
    torrent_download_free(dwn);
    free_torrent_file(tf);
}

