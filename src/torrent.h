#pragma once

#include "defines.h"
#include "network.h"
#include "bencode.h"
#include <arpa/inet.h>
#include <pthread.h>

typedef struct torrent_peer torrent_peer;

typedef struct {
    bencode_item* raw;
    char* announce;
    char* name;

    usize piece_length;
    usize num_pieces;
    usize length;
    u8** piece_hashes; // array of 20-byte hashes
    u8 info_hash[20];
} torrent_file;

typedef struct {
    torrent_file* torrent_file;
    u32 reannounce_interval;
    u8 my_peer_id[20];
    u16 my_port;

    usize uploaded;
    usize downloaded;
    usize left; // can be larger than torrent_file->length - downloaded, as pieces might fail integrity checks and need to be re-downloaded

    torrent_peer* peers; // linked list
    usize num_peers;

    usize* piece_queue;
    usize queue_capacity;
    usize queue_head;
    usize queue_count;
    pthread_mutex_t queue_lock;
    pthread_cond_t queue_not_empty;
    b8 shutdown;
} torrent_download;

#define PEER_MAX_BACKLOG 5
#define PEER_BLOCK_SIZE 16384

struct torrent_peer {
    struct torrent_peer* next;

    pthread_t thread;
    connection_context* ctx;
    in_addr_t address;
    u16 port;
    torrent_download* dwn;
    u8 their_peer_id[20];

    b8 choked;
    b8 interested;
    usize bitfield_size;
    u8* bitfield;

    u8* current_piece_buf;
    usize current_piece_length;
    usize current_piece_downloaded;
    usize current_piece_requested;
    usize current_backlog;
};

typedef enum {
    DOWNLOADING,
    STALLED
} torrent_peer_status;

typedef enum {
    INVALID = -2,
    KEEP_ALIVE = -1,
    CHOKE = 0,
    UNCHOKE = 1,
    INTERESTED = 2,
    NOT_INTERESTED = 3,
    HAVE = 4,
    BITFIELD = 5,
    REQUEST = 6,
    PIECE = 7,
    CANCEL = 8
} torrent_peer_message_type;

torrent_file* parse_torrent_file(const char* file_path);
void free_torrent_file(torrent_file* torrent);

torrent_download* torrent_download_init(torrent_file* torrent_file, const char* my_peer_id, u16 my_port);
void torrent_download_free(torrent_download* dwn);


torrent_peer* torrent_peer_add(torrent_download* dwn, in_addr_t address, u16 port);
void torrent_peer_close_and_free(torrent_peer* peer);

void torrent_peer_work(torrent_peer* peer);

b8 torrent_peer_connect_perform_handshake_and_get_bitfield(torrent_peer* peer);

void torrent_peer_download_piece(torrent_peer* peer, usize piece_idx, u8* piece_buf);

torrent_peer_message_type torrent_peer_receive(torrent_peer* peer);
void torrent_peer_send_keepalive(torrent_peer* peer);
void torrent_peer_send_unchoke(torrent_peer* peer);
void torrent_peer_send_choke(torrent_peer* peer);
void torrent_peer_send_interested(torrent_peer* peer);
void torrent_peer_send_not_interested(torrent_peer* peer);
void torrent_peer_send_have(torrent_peer* peer, usize piece_idx);
void torrent_peer_send_bitfield(torrent_peer* peer);
void torrent_peer_send_request(torrent_peer* peer, usize piece_idx, usize offset, usize length);
void torrent_peer_send_piece(torrent_peer* peer);
void torrent_peer_send_cancel(torrent_peer* peer);

b8 torrent_peer_has_piece(torrent_peer* peer, usize piece_idx);
b8 torrent_peer_check_integrity(torrent_peer* peer, usize piece_idx);

// returns true if succesful
b8 torrent_download_update_via_announce(torrent_download* dwn);
