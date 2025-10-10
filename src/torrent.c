#include "defines.h"
#include "torrent.h"
#include "bencode.h"
#include "network.h"
#include "sha1.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

torrent_file* parse_torrent_file(const char* file_path) {
    torrent_file* out = calloc(1, sizeof(torrent_file));

    FILE* file = fopen(file_path, "rb");
    if (!file) {
        fprintf(stderr, "Error: Could not open torrent file at %s\n", file_path);
        free(out);
        return null;
    }

    // get file size
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    rewind(file);

    // read the entire file into memory
    char* contents = malloc(size);
    fread(contents, size, 1, file);
    bencode_context* context = bencode_context_get((void*)contents, size);


    bencode_item* item = decode_bencode_item(context);
    if (item->type == BENCODE_INVALID) {
        fprintf(stderr, "Error: Could not decode torrent file at %s\n", file_path);
        free(contents);
        free(context);
        bencode_free(item);
        free(out);
        fclose(file);
        return null;
    }
    out->raw = item;

    // announce
    bencode_item* announce = bencode_search(item, "announce");
    if (!announce || announce->type != BENCODE_BYTE_STRING) {
        fprintf(stderr, "Error: announce field missing or invalid\n");
        free(contents);
        free(context);
        free_torrent_file(out);
        fclose(file);
        return null;
    }

    out->announce = malloc(announce->byte_string_data->size + 1);
    memcpy(out->announce, announce->byte_string_data->data,
           announce->byte_string_data->size);
    out->announce[announce->byte_string_data->size] = '\0';

    // info dict
    bencode_item* info = bencode_search(item, "info");
    if (!info) {
        fprintf(stderr, "Error: missing info dictionary\n");
        free(contents);
        free(context);
        free_torrent_file(out);
        fclose(file);
        return null;
    }

    // reject multi-file torrents
    bencode_item* files = bencode_search(info, "files");
    if (files) {
        fprintf(stderr, "Error: multi-file torrents unsupported\n");
        free(contents);
        free(context);
        free_torrent_file(out);
        fclose(file);
        return null;
    }

    // warn on private tracker
    bencode_item* private = bencode_search(info, "private");
    if (private && private->int_data == 1) {
        fprintf(stderr,
                "Warning: torrent file requested private tracker, unsupported.\n");
    }

    // compute info_hash
    SHA1_CTX sha;
    SHA1Init(&sha);
    SHA1Update(&sha, context->_info_start_ptr, context->_info_length);
    SHA1Final(out->info_hash, &sha);

    // extract name
    bencode_item* name_item = bencode_search(info, "name");
    if (name_item->type != BENCODE_BYTE_STRING) {
        fprintf(stderr, "Error: Missing or invalid 'name' in torrent file\n");
        free(contents);
        free(context);
        free_torrent_file(out);
        fclose(file);
        return null;
    }
    out->name = malloc(name_item->byte_string_data->size + 1);
    memcpy(out->name, name_item->byte_string_data->data, name_item->byte_string_data->size);
    out->name[name_item->byte_string_data->size] = '\0';

    // piece length
    bencode_item* piece_length_item = bencode_search(info, "piece length");
    if (piece_length_item->type != BENCODE_INT) {
        fprintf(stderr, "Error: Missing or invalid 'piece length' in torrent file\n");
        free(contents);
        free(context);
        free_torrent_file(out);
        fclose(file);
        return null;
    }
    out->piece_length = (u64) piece_length_item->int_data;

    // total length
    bencode_item* length_item = bencode_search(info, "length");
    if (!length_item || length_item->type != BENCODE_INT) {
        fprintf(stderr, "Error: Missing or invalid 'length' in torrent file\n");
        free(contents);
        free(context);
        free_torrent_file(out);
        fclose(file);
        return NULL;
    }
    out->length = (usize) length_item->int_data;

    // pieces
    bencode_item* pieces_item = bencode_search(info, "pieces");
    if (pieces_item->type != BENCODE_BYTE_STRING) {
        fprintf(stderr, "Error: Missing or invalid 'pieces' in torrent file\n");
        free(contents);
        free(context);
        free_torrent_file(out);
        fclose(file);
        return NULL;
    }
    usize pieces_size = pieces_item->byte_string_data->size;
    if (pieces_size % 20 != 0) {
        fprintf(stderr, "Error: 'pieces' field is not a multiple of 20 bytes\n");
        free(contents);
        free(context);
        free_torrent_file(out);
        fclose(file);
        return NULL;
    }
    out->num_pieces = pieces_size / 20;
    out->piece_hashes = malloc(out->num_pieces * sizeof(u8*));
    for (usize i = 0; i < out->num_pieces; i++) {
        out->piece_hashes[i] = malloc(20);
        memcpy(out->piece_hashes[i],
               pieces_item->byte_string_data->data + (i * 20),
               20);
    }

    // cleanup
    free(contents);
    free(context);
    fclose(file);

    return out;
}

void free_torrent_file(torrent_file* torrent) {
    free(torrent->announce);
    free(torrent->name);
    for (usize i = 0; i < torrent->num_pieces; i++) {
        free(torrent->piece_hashes[i]);
    }
    free(torrent->piece_hashes);
    bencode_free(torrent->raw);
    free(torrent);
}

torrent_download* torrent_download_init(torrent_file* torrent_file, const char* my_peer_id, u16 my_port){
    torrent_download* dwn = malloc(sizeof(torrent_download));

    dwn->torrent_file = torrent_file;
    if(strlen(my_peer_id) != 20){
        fprintf(stderr, "Warning: peer id %s should be 20 bytes...\n", my_peer_id);
    }
    memcpy(dwn->my_peer_id, my_peer_id, 20);
    dwn->my_port = my_port;
    dwn->uploaded = 0;
    dwn->downloaded = 0;
    dwn->left = torrent_file->length;
    dwn->peers = null;
    dwn->num_peers = 0;
    dwn->queue_capacity = dwn->torrent_file->num_pieces;
    dwn->piece_queue = malloc(sizeof(usize) * dwn->queue_capacity);
    dwn->queue_head = 0;
    dwn->queue_count = 0;
    pthread_mutex_init(&dwn->queue_lock, null);
    pthread_cond_init(&dwn->queue_not_empty, null);
    dwn->shutdown = false;

    for (usize i = 0; i < dwn->torrent_file->num_pieces; i++) {
        dwn->piece_queue[dwn->queue_count++] = i;
    }

    return dwn;
}
void torrent_download_free(torrent_download* dwn) {
    // tell all threads to stop
    dwn->shutdown = true;

    // wake up any threads waiting on queue
    pthread_mutex_lock(&dwn->queue_lock);
    pthread_cond_broadcast(&dwn->queue_not_empty);
    pthread_mutex_unlock(&dwn->queue_lock);

    // join peer threads
    torrent_peer* cur = dwn->peers;
    while (cur) {
        pthread_join(cur->thread, NULL);
        cur = cur->next;
    }

    // free peers
    cur = dwn->peers;
    while (cur) {
        torrent_peer* nxt = cur->next;
        torrent_peer_close_and_free(cur);
        cur = nxt;
    }

    free(dwn->piece_queue);
    pthread_mutex_destroy(&dwn->queue_lock);
    pthread_cond_destroy(&dwn->queue_not_empty);

    free(dwn);
}

b8 torrent_download_update_via_announce(torrent_download* dwn) {
    url* tracker_url = url_parse(dwn->torrent_file->announce);
    if (!tracker_url) {
        fprintf(stderr, "Error: Could not parse tracker url\n");
        return false;
    }

    if (strcmp(tracker_url->scheme, "http") != 0) {
        fprintf(stderr, "Error: Announce url scheme is not http (only http supported)\n");
        free(tracker_url);
        return false;
    }

    connection_context* conn = connection_init_from_url(tracker_url);
    if (!conn) {
        fprintf(stderr, "Error: Could not initialize connection to tracker\n");
        free(tracker_url);
        return false;
    }

    char* info_hash_encoded = url_encode_bytes(dwn->torrent_file->info_hash, 20);
    char* my_peer_id = url_encode_bytes(dwn->my_peer_id, 20);
    char my_port[16];
    snprintf(my_port, sizeof(my_port), "%hu", dwn->my_port);

    char downloaded[32], uploaded[32], left[32];
    snprintf(downloaded, sizeof(downloaded), "%zu", dwn->downloaded);
    snprintf(uploaded, sizeof(uploaded), "%zu", dwn->uploaded);
    snprintf(left, sizeof(left), "%zu", dwn->left);

    http_url_param info_hash_param  = { "info_hash",  info_hash_encoded, NULL };
    http_url_param peer_id_param    = { "peer_id",    my_peer_id, &info_hash_param };
    http_url_param port_param       = { "port",       my_port, &peer_id_param };
    http_url_param uploaded_param   = { "uploaded",   uploaded, &port_param };
    http_url_param downloaded_param = { "downloaded", downloaded, &uploaded_param };
    http_url_param left_param       = { "left",       left, &downloaded_param };
    http_url_param compact_param    = { "compact",    "1", &left_param };

    connection_send_http_get(conn, tracker_url, &compact_param);

    u8 response[8192];
    usize bytes_read = connection_receive(conn, response, sizeof(response));
    if (bytes_read == 0) {
        fprintf(stderr, "Error: No response from tracker\n");
        free(info_hash_encoded);
        free(my_peer_id);
        free(tracker_url);
        connection_close_and_free(conn);
        return false;
    }

    int major, minor, code;
    char reason[64] = {0};
    if (sscanf((char*)response, "HTTP/%d.%d %d %63[^\r\n]", &major, &minor, &code, reason) != 4) {
        fprintf(stderr, "Error: Failed to parse HTTP status line\n");
        free(info_hash_encoded);
        free(my_peer_id);
        free(tracker_url);
        connection_close_and_free(conn);
        return false;
    }
    if (code != 200) {
        fprintf(stderr, "Error: HTTP error %d %s\n", code, reason);
        free(info_hash_encoded);
        free(my_peer_id);
        free(tracker_url);
        connection_close_and_free(conn);
        return false;
    }

    u8* body = (u8*)strstr((char*)response, "\r\n\r\n");
    if (!body) {
        fprintf(stderr, "Error: No HTTP body found\n");
        free(info_hash_encoded);
        free(my_peer_id);
        free(tracker_url);
        connection_close_and_free(conn);
        return false;
    }
    body += 4;
    usize body_size = bytes_read - (body - response);

    bencode_context* tracker_response_ctx = bencode_context_get(body, body_size);
    bencode_item* tracker_data = decode_bencode_item(tracker_response_ctx);
    if (tracker_data->type == BENCODE_INVALID) {
        fprintf(stderr, "Error: Failed to decode tracker response\n");
        free(tracker_response_ctx);
        free(info_hash_encoded);
        free(my_peer_id);
        free(tracker_url);
        connection_close_and_free(conn);
        return false;
    }

    bencode_item* interval = bencode_search(tracker_data, "interval");
    if (!interval){
        if (dwn->reannounce_interval == 0){
            fprintf(stderr, "Error: Tracker response did not include interval\n");
            free(tracker_response_ctx);
            free(info_hash_encoded);
            free(my_peer_id);
            free(tracker_url);
            connection_close_and_free(conn);
            return false;
        }
        fprintf(stderr, "Warning: Tracker response did not include interval, assuming previous\n");
    }else{
        dwn->reannounce_interval = (u32) interval->int_data;
    }


    bencode_item* peers = bencode_search(tracker_data, "peers");
    if (peers->type != BENCODE_BYTE_STRING || peers->byte_string_data->size % 6 != 0) {
        fprintf(stderr, "Error: Tracker returned invalid peer list\n");
        bencode_free(tracker_data);
        free(tracker_response_ctx);
        free(info_hash_encoded);
        free(my_peer_id);
        free(tracker_url);
        connection_close_and_free(conn);
        return false;
    }

    usize peers_size = peers->byte_string_data->size;
    for (usize i = 0; i < peers_size; i += 6) {
        u8* offset = peers->byte_string_data->data + i;

        struct in_addr peer_addr;
        memcpy(&peer_addr.s_addr, offset, 4);

        u16 port_net;
        memcpy(&port_net, offset + 4, 2);
        u16 peer_port = ntohs(port_net);

        char ipbuf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &peer_addr, ipbuf, sizeof(ipbuf));
        printf("Peer: %s:%u\n", ipbuf, peer_port);

        if (peer_addr.s_addr == inet_addr("127.0.0.1") && peer_port == dwn->my_port)
            continue;

        torrent_peer* cur = dwn->peers;
        b8 exists = false;
        while (cur) {
            if ((cur->address == peer_addr.s_addr) && (peer_port == cur->port)) {
                exists = true;
                break;
            }
            cur = cur->next;
        }
        if (exists) continue;

        torrent_peer_add(dwn, peer_addr.s_addr, peer_port);
    }

    bencode_free(tracker_data);
    free(tracker_response_ctx);
    free(info_hash_encoded);
    free(my_peer_id);
    free(tracker_url);
    connection_close_and_free(conn);
    return true;
}

torrent_peer* torrent_peer_add(torrent_download* dwn, in_addr_t address, u16 port) {
    torrent_peer* peer = calloc(1, sizeof(torrent_peer));

    peer->dwn = dwn;
    peer->address = address;
    peer->port = port;
    peer->choked = true;
    peer->interested = false;
    peer->next = NULL;
    // bitfield is one bit per piece
    peer->bitfield_size = ((dwn->torrent_file->num_pieces - 1) / 8) + 1;
    peer->bitfield = calloc(1, peer->bitfield_size);

    peer->current_piece_buf = calloc(1, dwn->torrent_file->piece_length);

    // append to linked list
    if (!dwn->peers) {
        dwn->peers = peer;
    } else {
        torrent_peer* cur = dwn->peers;
        while (cur->next) cur = cur->next;
        cur->next = peer;
    }
    dwn->num_peers++;

    if (pthread_create(&peer->thread, null, (void*(*)(void*))torrent_peer_work, peer) != 0) {
        fprintf(stderr, "Error: failed to create thread for peer\n");
        torrent_peer_close_and_free(peer);
        return null;
    }

    return peer;
}

void torrent_peer_close_and_free(torrent_peer* peer) {
    if (peer->ctx) {
        connection_close_and_free(peer->ctx);
        peer->ctx = NULL;
    }

    torrent_download* dwn = peer->dwn;
    if (dwn && dwn->peers) {
        torrent_peer* cur = dwn->peers;
        torrent_peer* prev = NULL;
        while (cur) {
            if (cur == peer) {
                if (prev) prev->next = cur->next;
                else dwn->peers = cur->next;
                dwn->num_peers--;
                break;
            }
            prev = cur;
            cur = cur->next;
        }
    }
    free(peer->bitfield);
    free(peer->current_piece_buf);
    free(peer);
}
void put_piece_in_queue(torrent_download* dwn, usize piece_idx);


void torrent_peer_work(torrent_peer* peer){
    b8 ok = torrent_peer_connect_perform_handshake_and_get_bitfield(peer);
    if (!ok){
        fprintf(stderr, "[Thread #%lu] Error: Wrong handshake response from peer\n", peer->thread);
        return;
    }

    while(!peer->dwn->shutdown){
        // grap a piece from the queue
        pthread_mutex_lock(&peer->dwn->queue_lock);

        while (peer->dwn->queue_count == 0) {
            pthread_cond_wait(&peer->dwn->queue_not_empty, &peer->dwn->queue_lock);
        }

        if (peer->dwn->shutdown) {
            pthread_mutex_unlock(&peer->dwn->queue_lock);
            return;
        }

        usize out_piece = peer->dwn->piece_queue[peer->dwn->queue_head];
        usize global_piece_len = peer->dwn->torrent_file->piece_length;
        usize out_piece_len;

        if (out_piece == peer->dwn->torrent_file->num_pieces - 1){
            out_piece_len = peer->dwn->torrent_file->length % global_piece_len;
            // on the off chance that the last piece is exactly divisible by the piece length
            if (out_piece_len == 0){
                out_piece_len = global_piece_len;
            }
            printf("[Thread #%lu] Last piece detected, using piece length %zu\n", peer->thread, out_piece_len);
        }else{
            out_piece_len = global_piece_len;
        }

        peer->current_piece_length = out_piece_len;
        peer->current_piece_downloaded = 0;
        peer->current_piece_requested  = 0;
        peer->current_backlog = 0;
        memset(peer->current_piece_buf, 0, peer->current_piece_length);

        // if peer does not have the piece, bail
        if (!torrent_peer_has_piece(peer, out_piece)){
            if(peer->dwn->queue_count < 10 || peer->dwn->left < peer->dwn->torrent_file->length / 10){ // if this is the last few pieces, just kill the thread, this is a very crude "endgame mode";
                printf("[Thread #%lu] We don't have the last pieces, exiting %zu\n", peer->thread, out_piece_len);
                return;
            }
            pthread_mutex_unlock(&peer->dwn->queue_lock);
            continue;
        }

        peer->dwn->queue_head = (peer->dwn->queue_head + 1) % peer->dwn->queue_capacity;
        peer->dwn->queue_count--;

        pthread_mutex_unlock(&peer->dwn->queue_lock);

        torrent_peer_download_piece(peer, out_piece, peer->current_piece_buf);

        // Check integrity
        b8 ok_piece = torrent_peer_check_integrity(peer, out_piece);


        pthread_mutex_lock(&peer->dwn->queue_lock);
        if (!ok_piece) {
            fprintf(stderr, "[Thread #%lu] Piece %zu failed hash check, requeueing\n", peer->thread, out_piece);
            usize tail = (peer->dwn->queue_head + peer->dwn->queue_count) % peer->dwn->queue_capacity;
            peer->dwn->piece_queue[tail] = out_piece;
            peer->dwn->queue_count++;
            pthread_cond_signal(&peer->dwn->queue_not_empty);
        } else {
            peer->dwn->downloaded += peer->current_piece_length;
            peer->dwn->left -= peer->current_piece_length;
        }
        pthread_mutex_unlock(&peer->dwn->queue_lock);

        if (ok_piece) {
            // Send HAVE message
            torrent_peer_send_have(peer, out_piece);
        }

    }
}

void torrent_peer_download_piece(torrent_peer* peer, usize piece_idx, u8* piece_buf){

    while(peer->current_piece_downloaded < peer->current_piece_length){
        if(!peer->choked){
            while(peer->current_backlog < PEER_MAX_BACKLOG && peer->current_piece_requested < peer->current_piece_length){

            usize remaining = peer->current_piece_length - peer->current_piece_requested;
            usize block_size;
            if (remaining < PEER_BLOCK_SIZE){
                block_size = remaining;
            }else {
                block_size = PEER_BLOCK_SIZE;
            }

            //fprintf(stdout, "[Thread #%lu] Sending REQUEST piece=%zu offset=%zu len=%zu //(backlog=%zu)\n",
            //        peer->thread, piece_idx, peer->current_piece_requested, block_size, ///peer->current_backlog);


            torrent_peer_send_request(peer, piece_idx, peer->current_piece_requested, block_size);
            peer->current_backlog++;
            peer->current_piece_requested += block_size;
        }
    }
        torrent_peer_message_type msg = torrent_peer_receive(peer);
        if (msg == INVALID) {
            fprintf(stdout, "[Thread #%lu] Disconnecting peer\n", peer->thread);
            return;
        }

    }
}

b8 torrent_peer_connect_perform_handshake_and_get_bitfield(torrent_peer* peer){
    peer->ctx = connection_init_addr(peer->address, peer->port);
    if (!peer->ctx) {
        fprintf(stderr, "Error: failed to init connection for peer\n");
        return false;
    }

    u8 handshake[68] = {0};

    handshake[0] = '\x13';
    memcpy(handshake+1, "BitTorrent protocol", 19);
    memset(handshake+20, 0, 8);
    memcpy(handshake+28, peer->dwn->torrent_file->info_hash, 20);
    memcpy(handshake+48, peer->dwn->my_peer_id, 20);

    connection_send(peer->ctx, handshake, 68);
    u8 handshake_response[68] = {0};
    usize read = connection_receive(peer->ctx, handshake_response, 68);
    printf("bytes read: %zu\n", read);
    if (read != 68){
        fprintf(stderr, "[Thread #%lu] Error: Wrong handshake response from peer\n", peer->thread);
        return false;
    }

    u8 response_hash[20];
    memcpy(response_hash, handshake_response + 28, 20);

    if(!(memcmp(response_hash, peer->dwn->torrent_file->info_hash, 20) == 0)){
        fprintf(stderr, "[Thread #%lu] Error: Info hashes do not match with peer\n", peer->thread);
        return false;
    }

    memcpy(peer->their_peer_id, handshake_response + 48, 20);

    // TODO eventually we want to send our bitfield first too

    // Wait for the peer's next message (usually BITFIELD)
    torrent_peer_message_type type = torrent_peer_receive(peer);

    if (type != BITFIELD){
        fprintf(stderr, "[Thread #%lu] Warning: First message from peer is not bitfield (type %d)\n", peer->thread, type);
        // TODO: fix this
    } else {
        torrent_peer_send_interested(peer);
        peer->interested = true;
        fprintf(stdout, "[Thread #%lu] Sent INTERESTED after bitfield\n", peer->thread);
    }

    return true;
}

torrent_peer_message_type torrent_peer_receive(torrent_peer* peer) {
    u32 length_prefix_net;
    usize read = connection_receive(peer->ctx, (u8*)&length_prefix_net, 4);
    if (read == 0) {
        fprintf(stdout, "[Thread #%lu] Peer closed connection\n", peer->thread);
        return INVALID; // signal disconnect
    }
    if (read != 4) {
        fprintf(stderr, "[Thread #%lu] Error: Failed to read length prefix (got %zu, errno=%d)\n",
                peer->thread, read, errno);
        return INVALID;
    }

    u32 message_length = ntohl(length_prefix_net);

    if (message_length == 0) {
        fprintf(stdout, "[Thread #%lu] Received keep-alive\n", peer->thread);
        return KEEP_ALIVE;
    }

    u8 message_payload[message_length];
    read = connection_receive(peer->ctx, message_payload, message_length);
    if (read != message_length) {
        fprintf(stderr, "[Thread #%lu] Error: Payload length mismatch (%zu/%u)\n",
                peer->thread, read, message_length);
        return INVALID;
    }

    u8 message_type = message_payload[0];
    //fprintf(stdout, "[Thread #%lu] Received message type %d\n", peer->thread, message_type);

    switch (message_type) {
        case CHOKE:
            fprintf(stdout, "[Thread #%lu] Received choke\n", peer->thread);
            peer->choked = true;
            return CHOKE;

        case UNCHOKE:
            fprintf(stdout, "[Thread #%lu] Received unchoke\n", peer->thread);
            peer->choked = false;
            return UNCHOKE;

        case INTERESTED:
            fprintf(stdout, "[Thread #%lu] Received interested\n", peer->thread);
            peer->interested = true;
            return INTERESTED;

        case NOT_INTERESTED:
            fprintf(stdout, "[Thread #%lu] Received not interested\n", peer->thread);
            peer->interested = false;
            return NOT_INTERESTED;

        case HAVE: {
            if (message_length < 5) {
                fprintf(stderr, "[Thread #%lu] Error: Malformed HAVE message\n", peer->thread);
                return INVALID;
            }
            u32 have_index_net;
            memcpy(&have_index_net, message_payload + 1, 4);
            u32 have_index = ntohl(have_index_net);
            fprintf(stdout, "[Thread #%lu] Peer reports HAVE piece %u\n", peer->thread, have_index);

            // mark bitfield
            if (have_index < peer->dwn->torrent_file->num_pieces) {
                peer->bitfield[have_index / 8] |= (0x80 >> (have_index % 8));
            }
            return HAVE;
        }

        case BITFIELD: {
            usize bitfield_size = message_length - 1;
            fprintf(stdout, "[Thread #%lu] Received bitfield (%zu bytes)\n", peer->thread, bitfield_size);

            if (peer->bitfield_size == bitfield_size) {
                memcpy(peer->bitfield, message_payload + 1, bitfield_size);
            } else {
                fprintf(stderr, "[Thread #%lu] Warning: bitfield size mismatch\n", peer->thread);
            }
            return BITFIELD;
        }

        case REQUEST: {
            if (message_length < 13) {
                fprintf(stderr, "[Thread #%lu] Error: Malformed REQUEST message\n", peer->thread);
                return INVALID;
            }
            u32 idx_net, begin_net, len_net;
            memcpy(&idx_net,   message_payload + 1, 4);
            memcpy(&begin_net, message_payload + 5, 4);
            memcpy(&len_net,   message_payload + 9, 4);

            u32 piece_idx = ntohl(idx_net);
            u32 begin     = ntohl(begin_net);
            u32 length    = ntohl(len_net);

            fprintf(stdout, "[Thread #%lu] Peer REQUEST: piece=%u begin=%u length=%u\n",
                    peer->thread, piece_idx, begin, length);
            // TODO: implement upload path
            return REQUEST;
        }

        case PIECE: {
            if (message_length < 9) {
                fprintf(stderr, "[Thread #%lu] Error: Malformed PIECE message\n", peer->thread);
                return INVALID;
            }
            u32 idx_net, begin_net;
            memcpy(&idx_net, message_payload + 1, 4);
            memcpy(&begin_net, message_payload + 5, 4);

            u32 piece_idx = ntohl(idx_net);
            u32 begin = ntohl(begin_net);

            usize block_len = message_length - 9;
            //fprintf(stdout, "[Thread #%lu] Received PIECE: piece=%u begin=%u length=%zu\n",
            //        peer->thread, piece_idx, begin, block_len);

            if (piece_idx < peer->dwn->torrent_file->num_pieces && begin + block_len <= peer->current_piece_length) {
                memcpy(peer->current_piece_buf + begin, message_payload + 9, block_len);
                peer->current_piece_downloaded += block_len;
                peer->current_backlog--;
            } else {
                fprintf(stderr, "[Thread #%lu] Error: PIECE out of bounds\n", peer->thread);
            }
            return PIECE;
        }

        case CANCEL: {
            if (message_length < 13) {
                fprintf(stderr, "[Thread #%lu] Error: Malformed CANCEL message\n", peer->thread);
                return INVALID;
            }
            u32 idx_net, begin_net, len_net;
            memcpy(&idx_net,   message_payload + 1, 4);
            memcpy(&begin_net, message_payload + 5, 4);
            memcpy(&len_net,   message_payload + 9, 4);

            u32 piece_idx = ntohl(idx_net);
            u32 begin     = ntohl(begin_net);
            u32 length    = ntohl(len_net);

            fprintf(stdout, "[Thread #%lu] Peer CANCEL: piece=%u begin=%u length=%u\n",
                    peer->thread, piece_idx, begin, length);
            return CANCEL;
        }

        default:
            fprintf(stderr, "[Thread #%lu] Unknown message type %u\n", peer->thread, message_type);
            return INVALID;
    }
}

void torrent_peer_send_keepalive(torrent_peer* peer) {
    u32 len_be = htonl(0);
    connection_send(peer->ctx, (u8*)&len_be, 4);
}

void torrent_peer_send_choke(torrent_peer* peer) {
    u32 length = 1;
    u32 len_be = htonl(length);
    u8 buf[5];
    memcpy(buf, &len_be, 4);
    buf[4] = (u8)CHOKE;

    connection_send(peer->ctx, buf, sizeof(buf));
}

void torrent_peer_send_unchoke(torrent_peer* peer) {
    u32 length = 1;
    u32 len_be = htonl(length);
    u8 buf[5];
    memcpy(buf, &len_be, 4);
    buf[4] = (u8)UNCHOKE;

    connection_send(peer->ctx, buf, sizeof(buf));
}

void torrent_peer_send_interested(torrent_peer* peer) {
    u32 length = 1;
    u32 len_be = htonl(length);
    u8 buf[5];
    memcpy(buf, &len_be, 4);
    buf[4] = (u8)INTERESTED;

    connection_send(peer->ctx, buf, sizeof(buf));
}

void torrent_peer_send_not_interested(torrent_peer* peer) {
    u32 length = 1;
    u32 len_be = htonl(length);
    u8 buf[5];
    memcpy(buf, &len_be, 4);
    buf[4] = (u8)NOT_INTERESTED;

    connection_send(peer->ctx, buf, sizeof(buf));
}

void torrent_peer_send_have(torrent_peer* peer, usize piece_idx) {
    // payload: 1 byte id + 4 bytes piece index
    u32 length = 1 + 4;
    u32 len_be = htonl(length);
    u8 buf[4 + 1 + 4];

    memcpy(buf, &len_be, 4);
    buf[4] = (u8)HAVE;

    u32 piece_index_be = htonl(piece_idx);
    memcpy(buf + 5, &piece_index_be, 4);

    connection_send(peer->ctx, buf, sizeof(buf));
}

void torrent_peer_send_bitfield(torrent_peer* peer) {
    // TODO: unused
    fprintf(stdout, "[Thread #%lu] TODO: torrent_peer_send_bitfield not implemented\n", peer->thread);
}

void torrent_peer_send_request(torrent_peer* peer, usize piece_idx, usize offset, usize length) {
    // payload:
    // 4 bytes: length prefix (1 + 4 + 4 + 4 = 13)
    // 1 byte: id (6)
    // 4 bytes: index
    // 4 bytes: begin (offset)
    // 4 bytes: length (requested block size)

    u32 msg_payload_len = 13;
    u32 len_be = htonl(msg_payload_len);

    u8 buf[4 + 13];
    u8* p = buf;

    memcpy(p, &len_be, 4);
    p += 4;

    *p++ = (u8)REQUEST;

    u32 idx_be = htonl((u32)piece_idx);
    memcpy(p, &idx_be, 4);
    p += 4;

    u32 off_be = htonl((u32)offset);
    memcpy(p, &off_be, 4);
    p += 4;

    u32 len_field_be = htonl((u32)length);
    memcpy(p, &len_field_be, 4);
    p += 4;

    connection_send(peer->ctx, buf, sizeof(buf));
}

void torrent_peer_send_piece(torrent_peer* peer) {
    // TODO: unused
    fprintf(stdout, "[Thread #%lu] TODO: torrent_peer_send_piece not implemented\n", peer ? peer->thread : 0);
}

void torrent_peer_send_cancel(torrent_peer* peer) {
    // TODO: unused
    fprintf(stdout, "[Thread #%lu] TODO: torrent_peer_send_cancel not implemented\n", peer ? peer->thread : 0);
}

b8 torrent_peer_has_piece(torrent_peer* peer, usize piece_idx) {
    usize byte_index = piece_idx / 8;
    usize bit_index = piece_idx % 8;

    if (byte_index >= peer->bitfield_size) {
        return false;
    }

    u8 byte = peer->bitfield[byte_index];
    return (byte & (0x80 >> bit_index)) != 0; // 0x80 = 10000000, msb bitmask
}

b8 torrent_peer_check_integrity(torrent_peer* peer, usize piece_idx){
    u8* expected_hash = peer->dwn->torrent_file->piece_hashes[piece_idx];
    u8 computed_hash[20];

    SHA1_CTX sha;
    SHA1Init(&sha);
    SHA1Update(&sha, peer->current_piece_buf, peer->current_piece_length);
    SHA1Final(computed_hash, &sha);

    if(memcmp(expected_hash, computed_hash, 20) == 0){
        return true;
    } else {
        fprintf(stderr, "[Thread #%lu] Piece %zu failed hash check\n", peer->thread, piece_idx);
        fprintf(stderr, "Expected: ");
        for(int i = 0; i < 20; i++) fprintf(stderr, "%02x", expected_hash[i]);
        fprintf(stderr, "\nComputed: ");
        for(int i = 0; i < 20; i++) fprintf(stderr, "%02x", computed_hash[i]);
        fprintf(stderr, "\n");
        return false;
    }
}

