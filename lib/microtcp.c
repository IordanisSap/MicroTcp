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
#include <string.h>
#include "time.h"
#include <unistd.h>

struct timeval tv;



microtcp_header_t* header;
void set_SeqAck();
void decodeHeader(microtcp_header_t* microtcpHeader);
void encodeHeader(microtcp_header_t* microtcpHeader);
int sockError(microtcp_sock_t* sock, char* str);
uint32_t crcCheck(void* buf, unsigned int len);
int isSendSuccessful(ssize_t sent, size_t amountToSend);
int waitZeroWindow(microtcp_sock_t *socket);
size_t minAmount(size_t val1, size_t val2, size_t val3);
uint8_t* initBuf(uint8_t buf[], size_t len);
void bufDecodeHeader(void *buf);

microtcp_sock_t microtcp_socket (int domain, int type, int protocol) {
    /* Your code here */
    srand(time(NULL));
    microtcp_sock_t sock;
    if ((sock.sd = socket(domain,SOCK_DGRAM,IPPROTO_UDP)) == -1){
        sock.state = INVALID;
        return sock;
    }
    sock.ssthresh = MICROTCP_INIT_SSTHRESH;
    sock.cwnd = MICROTCP_INIT_CWND;
    sock.init_win_size = MICROTCP_WIN_SIZE;
    sock.curr_win_size = MICROTCP_WIN_SIZE;
    sock.state = UNKNOWN;
    sock.recvbuf = malloc(MICROTCP_MSS);

    /* Set socket timeout */
    tv.tv_sec = 2;
    tv.tv_usec = MICROTCP_ACK_TIMEOUT_US;

    if (setsockopt(sock.sd, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0) {
        sockError(&sock, "Error");
        return sock;
    }
    header = malloc(sizeof (microtcp_header_t));
    header->window = 0;
    header->data_len = 0;
    header->future_use0 = 0;
    header->future_use1 = 0;
    header->future_use2 = 0;

    return sock;
}

int microtcp_bind (microtcp_sock_t *socket, const struct sockaddr *address,
               socklen_t address_len) {
    int flag;
    flag = bind(socket->sd, address, address_len);
    if (flag == -1) socket->state = INVALID;
    return flag;
}

int microtcp_connect (microtcp_sock_t *socket, const struct sockaddr *address,
                  socklen_t address_len) {
    socket->CLIENT_INIT_SEQ = (rand()%100)+1;
    ssize_t recved;
    ssize_t sent;

    if (socket->sd<0 || socket->state == INVALID){
        socket->state = INVALID;
        return -1;
    }
    socket->addr = (struct sockaddr*) address;
    socket->address_len = address_len;

    /* Send 1st packet (SYN) */
    header->seq_number = socket->CLIENT_INIT_SEQ;
    header->control = SYN;
    header->window = socket->init_win_size;
    header->checksum = crcCheck(NULL,0);

    encodeHeader(header);
    sent = sendto(socket->sd, header, sizeof(microtcp_header_t), 0, address, address_len);
    if (!isSendSuccessful(sent, sizeof(microtcp_header_t))) return sockError(socket,"Send error during handshake");

    /* Receive 2nd packet (SYN ACK) */
    recved = recvfrom(socket->sd, header, sizeof(microtcp_header_t), 0, socket->addr,
             &address_len);
    /* Checks */
    if (recved>0) decodeHeader(header);
    else return sockError(socket,"Timeout");
    if(header->checksum != crcCheck(NULL,0)) return sockError(socket, "Checksum error");
    if (header->control != SYN_ACK) return sockError(socket,"Wrong packet order");

    socket->SERVER_INIT_SEQ = header->seq_number;
    socket->init_win_size = header->window; /* Initial window size agreed during handshake */
    socket->curr_win_size = socket->init_win_size;
    
    /* Send 3rd packet (ACK) */
    set_SeqAck();
    header->control = ACK;
    header->checksum = crcCheck(NULL,0);

    encodeHeader(header);
    sent = sendto(socket->sd, header, sizeof(microtcp_header_t), 0,address,address_len);
    if (!isSendSuccessful(sent, sizeof(microtcp_header_t))) return sockError(socket,"Send error during handshake");
    decodeHeader(header);
    socket->state = ESTABLISHED;
    socket->seq_number = header->seq_number;
    socket->ack_number = header->ack_number;
    return 0;
}

int microtcp_accept (microtcp_sock_t *socket, struct sockaddr *address,
                 socklen_t address_len) {

    ssize_t recved;
    ssize_t sent;

    socket->SERVER_INIT_SEQ = (rand()%100)+1;

    if (socket->sd < 0 || socket->state == INVALID){
        return -1;
    }

    socket->addr = address;
    socket->address_len = address_len;
    header->control = ACK; /* Initial value, will be changed when client connects */
    /* Receive 1st packet (SYN) */
    while (header->control != SYN) {
        recved = recvfrom(socket->sd, header, sizeof(microtcp_header_t), 0, address,
                          &address_len);
        if (recved > 0) {
            decodeHeader(header);
            if (header->checksum != crcCheck(NULL,0)) header->control = ACK; /* Keep being inside the loop */
        }
    }

    socket->CLIENT_INIT_SEQ = header->seq_number;
    socket->init_win_size = header->window; /* Initial window size agreed during handshake */
    socket->curr_win_size = socket->init_win_size;

    /* Send 2nd packet (SYN ACK) */
    set_SeqAck();
    header->ack_number = header->ack_number + 1;
    header->seq_number = socket->SERVER_INIT_SEQ;
    header->control = SYN_ACK;
    header->checksum = crcCheck(NULL,0);

    encodeHeader(header);
    sent = sendto(socket->sd, header, sizeof(microtcp_header_t), 0, address, address_len);
    if (!isSendSuccessful(sent, sizeof(microtcp_header_t))) return sockError(socket,"Send error during handshake");

    /* Receive 3rd packet (ACK) */
    recved = recvfrom(socket->sd, header, sizeof(microtcp_header_t), 0, address, &address_len);

    /* Checks */
    if (recved>0) decodeHeader(header);
    else return sockError(socket,"Timeout");
    if (header->checksum != crcCheck(NULL,0)) return sockError(socket, "Checksum error");
    if (header->control != ACK) return sockError(socket,"Wrong packet order");

    set_SeqAck();
    socket->state = ESTABLISHED;
    socket->seq_number = header->seq_number;
    socket->ack_number = header->ack_number;

    return 0;
}

int microtcp_shutdown (microtcp_sock_t *socket, int how) {
    /* Your code here */

    free(socket->recvbuf);

    socklen_t size;
    ssize_t recved;
    ssize_t sent;
    size = sizeof(struct sockaddr);
    if (socket->sd<0 || socket->state == INVALID){
        return -1;
    }

    if (socket->state==ESTABLISHED) {
        header->seq_number = socket->seq_number;
        header->ack_number = socket->ack_number;
        header->control = FIN;
        header->checksum = crcCheck(NULL,0);
        encodeHeader(header);
        sent = sendto(socket->sd, header, sizeof(microtcp_header_t), 0, socket->addr, sizeof(microtcp_header_t));
        if (sent == -1) {
            sockError(socket,"Send error");
            return -1;
        }
        socket->seq_number++;
        recved = recvfrom(socket->sd, header, sizeof(microtcp_header_t), 0,
                          socket->addr, &size);

        if (recved > 0) decodeHeader(header);
        if (header->checksum != crcCheck(NULL,0)) return sockError(socket,"Checksum error");
        if (header->control != ACK) return sockError(socket,"Wrong control");

        socket->state = CLOSING_BY_HOST;
        recved = recvfrom(socket->sd, header, sizeof(microtcp_header_t), 0,
                          socket->addr, &size);
        if (recved > 0) decodeHeader(header);
        if (header->checksum != crcCheck(NULL,0)) return sockError(socket,"Checksum error");
        if (header->control != FIN_ACK) return sockError(socket,"Wrong control");

        header->control = ACK;
        header->checksum = crcCheck(NULL,0);
        encodeHeader(header);
        sent = sendto(socket->sd, header, sizeof(microtcp_header_t), 0, socket->addr, sizeof(struct sockaddr));
        if (sent == -1) {
            sockError(socket,"Send error");
            return -1;
        }
    }

    else if (socket->state==CLOSING_BY_PEER){
        header->control = ACK;
        header->ack_number = header->seq_number+1;
        header->seq_number = socket->seq_number;
        header->checksum = crcCheck(NULL,0);
        encodeHeader(header);
        sent = sendto(socket->sd, header, sizeof(microtcp_header_t),0,socket->addr, sizeof(struct sockaddr));
        if (sent == -1) {
            sockError(socket,"Send error");
            return -1;
        }
        socket->state=CLOSING_BY_HOST;
        header->control = FIN_ACK;
        header->checksum = crcCheck(NULL,0);
        encodeHeader(header);
        sent = sendto(socket->sd, header, sizeof(microtcp_header_t),0,socket->addr, sizeof(struct sockaddr));
        if (sent == -1) {
            sockError(socket,"Send error");
            return -1;
        }
        recved = recvfrom(socket->sd, header, sizeof(microtcp_header_t), 0,
                 socket->addr, &size);
        if (recved>0) decodeHeader(header);

    }

    socket->state = CLOSED;
    free(header);
    return 0;
}


ssize_t microtcp_send (microtcp_sock_t *socket, const void *buffer, size_t length,
               int flags){
  /* Your code here */
    size_t remaining = length;
    size_t min, chunks;
    int payloadSize;
    ssize_t sent,recved;
    size_t totalSent=0;
    size_t tempACK,tempACKcounter;
    uint32_t lastACK;
    uint32_t initSeq = socket->seq_number;


    if (socket->state==CLOSED) return 0;
    while (remaining>0){
        min = minAmount(socket->curr_win_size,socket->cwnd, remaining);
        /* Send */
        payloadSize = MICROTCP_MSS - sizeof(microtcp_header_t); /* Payload size is limited by the header size */
        chunks = min/payloadSize;

        /* Init header */
        header->control = 0;
        header->seq_number = socket->seq_number;
        header->ack_number = socket->ack_number;
        header->data_len = payloadSize;
        for (size_t i = 0; i < chunks; ++i) {

            memcpy(socket->recvbuf,header, sizeof(microtcp_header_t));
            memcpy(socket->recvbuf+sizeof(microtcp_header_t),buffer+(totalSent),payloadSize);

            header->checksum = crcCheck(socket->recvbuf,MICROTCP_MSS);
            encodeHeader(header);
            memcpy(socket->recvbuf,header, sizeof(microtcp_header_t));


            sent = sendto(socket->sd, socket->recvbuf, MICROTCP_MSS, 0, socket->addr, socket->address_len);
            decodeHeader(header);
            if (!isSendSuccessful(sent, MICROTCP_MSS)) return sockError(socket, "Error sending chunk");
            header->seq_number += payloadSize;
            totalSent += payloadSize;
        }

        unsigned int remainingBytes = min % payloadSize;
        if (remainingBytes){
            header->data_len = remainingBytes;

            memcpy(socket->recvbuf,header, sizeof(microtcp_header_t));
            memcpy(socket->recvbuf+sizeof(microtcp_header_t),buffer+totalSent,remainingBytes);

            header->checksum = crcCheck(socket->recvbuf,sizeof(microtcp_header_t)+remainingBytes);

            encodeHeader(header);
            memcpy(socket->recvbuf,header, sizeof(microtcp_header_t));

            sent = sendto(socket->sd, socket->recvbuf, sizeof(microtcp_header_t)+remainingBytes, 0, socket->addr, socket->address_len);
            if (!isSendSuccessful(sent, sizeof(microtcp_header_t)+remainingBytes)) return sockError(socket, "Error sending remaining Bytes");
            chunks++;
            decodeHeader(header);
            header->seq_number += remainingBytes;
            totalSent+=remainingBytes;

        }

        remaining -= min;
        socket->seq_number = header->seq_number;

        /*GET ACKS*/

        for (size_t i = 0; i < chunks; ++i) {
            recved = recvfrom(socket->sd, header, sizeof(microtcp_header_t), 0,
                              socket->addr, &socket->address_len);

            if (recved>0){
                decodeHeader(header);
                lastACK = header->ack_number;
                if (header->window==0) {
                    socket->curr_win_size = 0;
                    waitZeroWindow(socket);
                }
                socket->curr_win_size = header->window;
                if (header->ack_number == tempACK){
                    tempACKcounter++;
                    if (tempACKcounter >= 3){   /* 3 dup ACKs */
                        socket->seq_number = lastACK;
                        totalSent = socket->seq_number - initSeq;
                        remaining = length-totalSent;
                        tempACKcounter=0;

                        /* Congestion avoidance */
                        if (socket->ssthresh>1) socket->ssthresh = socket->cwnd /2;
                        socket->cwnd = socket->cwnd /2 + 1;
                        break;
                    }
                } else{ /* Possibly right order */
                    totalSent = header->ack_number - initSeq;
                    remaining = length-totalSent;
                    tempACK = header->ack_number;
                    tempACKcounter=0;
                    /* Congestion control */
                    if (socket->cwnd <= socket->ssthresh){ /* Slow start phase*/
                        socket->cwnd = socket->cwnd+MICROTCP_MSS;
                    } else socket->cwnd +=1;               /*Congestion avoidance phase */

                }
            } else {    /* Recved nothing, timeout */
                socket->seq_number = lastACK;
                totalSent = socket->seq_number - initSeq;
                remaining = length-totalSent;
                tempACKcounter=0;
                if (socket->ssthresh>1) socket->ssthresh = socket->cwnd /2;
                socket->cwnd = minAmount( MICROTCP_MSS , socket->ssthresh, INT32_MAX ); /* Obviously choose between first 2 */
            }
        }

    }

    return totalSent;
}

ssize_t microtcp_recv (microtcp_sock_t *socket, void *buffer, size_t length, int flags) {
    /* Your code here */

    void *tempBuf = malloc(MICROTCP_MSS);
    uint32_t currAck = socket->ack_number;
    ssize_t recved;
    ssize_t sent;
    size_t total = 0;
    buffer = initBuf(buffer,length);

    if (socket->state==CLOSED) return 0;

    while (total<length) {
        recved = recvfrom(socket->sd, tempBuf, MICROTCP_MSS, flags, socket->addr, &socket->address_len);

        if (recved>0){
            bufDecodeHeader(tempBuf);
            if(header->checksum != crcCheck(tempBuf, sizeof(microtcp_header_t)+header->data_len)) {
                perror("Checksum error");
                /* Need Retransmit */
            }
            /* Check for FIN ACK*/
            if (header->control == FIN) {
                socket->state = CLOSING_BY_PEER;
                microtcp_shutdown(socket, 0);
                return total;
            }
            if (header->data_len==0) continue; /* Probably empty header sent because window=0 */
            /* Chunk with data */
            socket->curr_win_size = header->window;
            if (header->seq_number==currAck){
                /* Chunk with right order */
                memcpy(buffer + total, tempBuf + sizeof(microtcp_header_t), header->data_len);
                total += header->data_len;
                currAck += header->data_len;
                header->ack_number = currAck;
                socket->ack_number = currAck;

            } else header->ack_number = socket->ack_number;
            /* Send Ack */
            header->seq_number = socket->seq_number;
            header->control = ACK;
            header->window = length - total;
            header->data_len = 0;
            header->checksum = crcCheck(NULL,0);
            /* Send Ack */
            encodeHeader(header);
            sent = sendto(socket->sd, header, sizeof(microtcp_header_t), 0, socket->addr, socket->address_len);
            if (!isSendSuccessful(sent, sizeof(microtcp_header_t))) return sockError(socket, "Error sending ACK");


        } else{
            /* Recv timeout */
            perror("Recv Timeout");
            return total;
        }
        if (total == length){
            header->window=length;
            header->ack_number = socket->ack_number;
            header->seq_number = socket->seq_number;
            header->data_len=0;
            header->checksum = crcCheck(NULL,0);
            encodeHeader(header);
            sent = sendto(socket->sd, header, sizeof(microtcp_header_t), 0, socket->addr, socket->address_len);
            if (!isSendSuccessful(sent, sizeof(microtcp_header_t))) return sockError(socket, "Error sending packet after 0 window");
            break;
        }
    }

    free(tempBuf);
    return total;
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
    microtcpHeader->checksum = ntohl(microtcpHeader->checksum);
    microtcpHeader->window = ntohs(microtcpHeader->window);
    microtcpHeader->data_len = ntohl(microtcpHeader->data_len);
}

void encodeHeader(microtcp_header_t* microtcpHeader){
    microtcpHeader->seq_number = htonl(microtcpHeader->seq_number);
    microtcpHeader->ack_number = htonl(microtcpHeader->ack_number);
    microtcpHeader->control = htons(microtcpHeader->control);
    microtcpHeader->checksum = htonl(microtcpHeader->checksum);
    microtcpHeader->window = htons(microtcpHeader->window);
    microtcpHeader->data_len = htonl(microtcpHeader->data_len);

}

int sockError(microtcp_sock_t* sock, char* str){
    perror(str);
    free(sock->recvbuf);
    sock->state = INVALID;
    return -1;
}

uint32_t crcCheck(void* buf, unsigned int len){
    if (buf){
        memcpy(header,buf, sizeof(microtcp_header_t));
        header->checksum=0;
        memcpy(buf,header, sizeof(microtcp_header_t));
        return crc32(buf,len);
    }
    header->checksum = 0;
    return crc32((const uint8_t *) header, sizeof(microtcp_header_t));
}

void bufDecodeHeader(void *buf){
    memcpy(header,buf, sizeof(microtcp_header_t));
    decodeHeader(header);
    memcpy(buf,header, sizeof(microtcp_header_t));
}

int isSendSuccessful(ssize_t sent, size_t amountToSend){
    if (sent > 0 && (size_t) sent == amountToSend)
        return 1;
    else{
        return 0;
    }
}

int waitZeroWindow(microtcp_sock_t *socket) {
    int amount = rand() % MICROTCP_MSS;
    ssize_t sent,recved;
    while ( socket->curr_win_size == 0) {
        header->data_len = 0;
        header->control = 0;
        header->seq_number = socket->seq_number;
        header->ack_number = socket->ack_number;
        header->window = 0;
        header->checksum = crcCheck(NULL,0);
        encodeHeader(header);
        sent = sendto(socket->sd, header, sizeof(microtcp_header_t), 0, socket->addr, socket->address_len);
        if (!isSendSuccessful(sent, sizeof(microtcp_header_t))) return sockError(socket, "Error sending empty packet,because of full window");

        recved = recvfrom(socket->sd, header, MICROTCP_MSS, 0, socket->addr, &socket->address_len);
        if (recved>0) {
            decodeHeader(header);
            if(header->checksum != crcCheck(header, sizeof(microtcp_header_t))) perror("Checksum error");
            else if (header->window>0) {
                socket->curr_win_size = header->window;
                socket->ack_number = header->ack_number;
            }
        }
        else usleep(amount);
    }

    return 0;
}


size_t minAmount(size_t val1, size_t val2, size_t val3){
    if (val1 <= val2 && val1 <= val3) return val1;
    if (val2 <= val1 && val2 <= val3) return val2;
    return val3;
}

uint8_t* initBuf(uint8_t buf[], size_t len){
    for (size_t i = 0; i < len; ++i) {
        buf[i] = 0;
    }
    return buf;
}


