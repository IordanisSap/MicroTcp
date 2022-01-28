/*
 * microtcp, a lightweight implementation of TCP for teaching,
 * and academic purposes.
 *
 * Copyright (C) 2015-2017  Manolis Surligas <surligas@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "microtcp.h"
#include "../utils/crc32.h"
#include "sys/socket.h"
#include "stdlib.h"
#include "stdio.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "time.h"

#define MAX_TRIES 30
struct timeval tv;



microtcp_header_t* header;
void set_SeqAck();
void decodeHeader(microtcp_header_t* microtcpHeader);
void encodeHeader(microtcp_header_t* microtcpHeader);
void sockError(microtcp_sock_t* sock, char* str);

microtcp_sock_t microtcp_socket (int domain, int type, int protocol) {
    /* Your code here */
    srand(time(NULL));
    microtcp_sock_t sock;
    if ((sock.sd = socket(domain,SOCK_DGRAM,protocol)) == -1){
        sock.state = INVALID;
        return sock;
    }
    sock.ssthresh = MICROTCP_INIT_SSTHRESH;
    sock.cwnd = MICROTCP_INIT_CWND;
    sock.init_win_size = MICROTCP_WIN_SIZE;
    sock.curr_win_size = MICROTCP_WIN_SIZE;
    sock.state = UNKNOWN;

    /* Set socket timeout */
    tv.tv_sec = 0;
    tv.tv_usec = 100000;
    if (setsockopt(sock.sd, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0) {
        sockError(&sock, "Error");
        return sock;
    }
    header = malloc(sizeof (microtcp_header_t));
    header->future_use0 = 0;
    header->future_use1 = 0;
    header->future_use2 = 0;
    header->window = 0;
    return sock;
}

int microtcp_bind (microtcp_sock_t *socket, const struct sockaddr *address,
               socklen_t address_len) {
    /* Your code here */
    int flag;
    flag = bind(socket->sd, address, address_len);
    if (flag == -1) socket->state = INVALID;
    return flag;
}

int microtcp_connect (microtcp_sock_t *socket, const struct sockaddr *address,
                  socklen_t address_len) {
    /* Your code here */
    int flag=0;
    socket->CLIENT_INIT_SEQ = (rand()%100)+1;
    ssize_t recved;
    ssize_t sent;

    if (socket->sd<0 || socket->state == INVALID){
        socket->state = INVALID;
        return -1;
    }

    socket->addr = address;



    while (header->control != SYN_ACK && flag<MAX_TRIES) {
        header->seq_number = htonl(socket->CLIENT_INIT_SEQ);
        header->control = htons(SYN);
        sent = sendto(socket->sd, header, sizeof(microtcp_header_t), 0, address, address_len);
        if (sent == -1) {
            sockError(socket,"Send error");
            return -1;
        }
        recved = recvfrom(socket->sd, (microtcp_header_t *) header, sizeof(microtcp_header_t), 0, (struct sockaddr *) address,
                 &address_len);
        if (recved) {
            decodeHeader(header);
        }
        flag++;
    }

    if (flag == MAX_TRIES) {
        sockError(socket,"Timeout");
        return -1;
    }
    socket->SERVER_INIT_SEQ = header->seq_number;

    set_SeqAck();
    header->control = ACK;
    encodeHeader(header);
    sent = sendto(socket->sd, header, sizeof(microtcp_header_t), 0,address,address_len);
    if (sent == -1) {
        sockError(socket,"Send error");
        return -1;
    }
    socket->state = ESTABLISHED;
    return flag;
}

int microtcp_accept (microtcp_sock_t *socket, struct sockaddr *address,
                 socklen_t address_len) {

    /* Your code here */
    int flag=0;
    ssize_t recved;
    ssize_t sent;
    socket->SERVER_INIT_SEQ = (rand()%100)+1;

    if (socket->sd < 0 || socket->state == INVALID){
        return -1;
    }

    socket->addr = address;

    while (header->control != SYN) {
        recvfrom(socket->sd, (microtcp_header_t *) header, sizeof(microtcp_header_t), 0, address, &address_len);
        decodeHeader(header);
    }


    socket->CLIENT_INIT_SEQ = header->seq_number;
    set_SeqAck();
    header->ack_number = header->ack_number + 1;
    header->seq_number = socket->SERVER_INIT_SEQ;
    header->control = SYN_ACK;

    while (header->control != ACK && flag<MAX_TRIES) {
        encodeHeader(header);
        sent = sendto(socket->sd, header, sizeof(microtcp_header_t), 0, address, address_len);
        if (sent == -1) {
            sockError(socket,"Send error");
            return -1;
        }

        recved = recvfrom(socket->sd, (microtcp_header_t *) header, sizeof(microtcp_header_t), 0, address, &address_len);
        if (recved) decodeHeader(header);
        flag++;
    }
    
    if (flag == MAX_TRIES) {
        sockError(socket,"Timeout");
        return -1;
    }

    socket->state = ESTABLISHED;
    set_SeqAck();
    return flag;
}

int microtcp_shutdown (microtcp_sock_t *socket, int how) {
    /* Your code here */
    int flag=0;
    socklen_t size;
    ssize_t recved;
    ssize_t sent;
    size = sizeof(struct sockaddr);
    if (socket->sd<0 || socket->state == INVALID){
        return -1;
    }
    fflush(stdout);
    if (socket->state==ESTABLISHED) {
        socket->state = CLOSING_BY_PEER;
        header->control = FIN_ACK;
        while (header->control != ACK && flag<20) {
            encodeHeader(header);
            sent = sendto(socket->sd, header, sizeof(microtcp_header_t), 0, socket->addr, sizeof(struct sockaddr));
            if (sent == -1) {
                sockError(socket,"Send error");
                return -1;
            }
            fflush(stdout);
            recved = recvfrom(socket->sd, (microtcp_header_t *) header, sizeof(microtcp_header_t), 0,
                              (struct sockaddr *) socket->addr, &size);

            if (recved > 0) decodeHeader(header);
            flag++;
        }

        if (flag == MAX_TRIES){
            sockError(socket,"Timeout");
            return -1;
        }

        socket->state = CLOSING_BY_HOST;
        flag = 0;
        while (header->control != FIN_ACK && flag<MAX_TRIES) {
            recved = recvfrom(socket->sd, (microtcp_header_t *) header, sizeof(microtcp_header_t), 0,
                              (struct sockaddr *) socket->addr, &size);
            if (recved > 0) decodeHeader(header);
            fflush(stdout);
            flag++;
        }

        if (flag == MAX_TRIES){
            sockError(socket,"Timeout");
            return -1;
        }

        header->control = ACK;
        encodeHeader(header);
        sendto(socket->sd, header, sizeof(microtcp_header_t), 0, socket->addr, sizeof(struct sockaddr));
        if (sent == -1) {
            sockError(socket,"Send error");
            return -1;
        }

    }

    else if (socket->state==CLOSING_BY_PEER){
        while (header->control != FIN_ACK && flag<MAX_TRIES) {
            recved = recvfrom(socket->sd, (microtcp_header_t *) header, sizeof(microtcp_header_t), 0,
                     (struct sockaddr *) socket->addr, &size);
            if (recved>0) decodeHeader(header);
            flag++;
        }

        if (flag == MAX_TRIES){
            sockError(socket,"Timeout");
            return -1;
        }

        fflush(stdout);
        header->control = ACK;
        header->ack_number = header->seq_number+1;
        encodeHeader(header);
        sent = sendto(socket->sd, header, sizeof(microtcp_header_t),0,socket->addr, sizeof(struct sockaddr));
        if (sent == -1) {
            sockError(socket,"Send error");
            return -1;
        }
        socket->state=CLOSING_BY_HOST;
        header->control = FIN_ACK;
        encodeHeader(header);
        sent = sendto(socket->sd, header, sizeof(microtcp_header_t),0,socket->addr, sizeof(struct sockaddr));
        if (sent == -1) {
            sockError(socket,"Send error");
            return -1;
        }
        while (header->control != ACK) {
            recved = recvfrom(socket->sd, (microtcp_header_t *) header, sizeof(microtcp_header_t), 0,
                     (struct sockaddr *) socket->addr, &size);
            if (recved>0) decodeHeader(header);
        }

    }

    socket->state = CLOSED;
    free(header);
    return 0;
}

ssize_t microtcp_send (microtcp_sock_t *socket, const void *buffer, size_t length,
               int flags){
  /* Your code here */

    return 0;
}

ssize_t microtcp_recv (microtcp_sock_t *socket, void *buffer, size_t length, int flags) {
    /* Your code here */
    recv(socket->sd, buffer, length, flags);
    header = (microtcp_header_t*) buffer;
    decodeHeader(header);
    if (header->control == FIN_ACK) {
        socket->state = CLOSING_BY_PEER;
        microtcp_shutdown(socket, 0);
    }
    return 0;
}


void set_SeqAck(){
    mircotcp_state_t temp = header->seq_number;
    header->seq_number = header->ack_number;
    header->ack_number = temp;
}

void decodeHeader(microtcp_header_t* microtcpHeader){
    microtcpHeader->seq_number = ntohl(microtcpHeader->seq_number);
    microtcpHeader->ack_number = ntohl(microtcpHeader->ack_number);
    microtcpHeader->control = ntohs(microtcpHeader->control);
}

void encodeHeader(microtcp_header_t* microtcpHeader){
    microtcpHeader->seq_number = htonl(microtcpHeader->seq_number);
    microtcpHeader->ack_number = htonl(microtcpHeader->ack_number);
    microtcpHeader->control = htons(microtcpHeader->control);
}

void sockError(microtcp_sock_t* sock, char* str){
    perror(str);
    sock->state = INVALID;
}