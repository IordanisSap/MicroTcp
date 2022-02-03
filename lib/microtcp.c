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
#include <unistd.h>

#define MAX_TRIES 10
struct timeval tv;



microtcp_header_t* header;
void set_SeqAck();
void decodeHeader(microtcp_header_t* microtcpHeader);
void encodeHeader(microtcp_header_t* microtcpHeader);
int sockError(microtcp_sock_t* sock, char* str);
uint32_t crcCheck(void* buf, unsigned int len);
int isSendSuccessful(ssize_t sent, size_t amountToSend);
void waitZeroWindow();
size_t minAmount(size_t curr_win_size, size_t cwnd, size_t remainingBytes);
int sendPacketWithRetransmission(const void *buf, size_t amount, void *outBuf);
uint8_t* initBuf(uint8_t buf[], size_t len);
void bufDecodeHeader(void *buf);

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
    /* Your code here */
    int flag;
    flag = bind(socket->sd, address, address_len);
    if (flag == -1) socket->state = INVALID;
    return flag;
}

int microtcp_connect (microtcp_sock_t *socket, const struct sockaddr *address,
                  socklen_t address_len) {
    /* Your code here */
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
    recved = recvfrom(socket->sd, (microtcp_header_t *) header, sizeof(microtcp_header_t), 0, (struct sockaddr *) address,
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

    /* Your code here */
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
        recved = recvfrom(socket->sd, (microtcp_header_t *) header, sizeof(microtcp_header_t), 0, address,
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
    recved = recvfrom(socket->sd, (microtcp_header_t *) header, sizeof(microtcp_header_t), 0, address, &address_len);

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
        header->data_len = 0;
        header->checksum = crcCheck(NULL,0);
        while (header->control != ACK && flag<20) {
            encodeHeader(header);
            sent = sendto(socket->sd, header, sizeof(microtcp_header_t), 0, socket->addr, sizeof(microtcp_header_t));
            decodeHeader(header);
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
    size_t remaining = length;
    size_t min, chunks;
    int payloadSize;
    ssize_t sent,recved;
    void* buf = malloc(MICROTCP_MSS);
    size_t totalSent=0;
    size_t tempACK,tempACKcounter;
    uint32_t tempSeq;
    uint32_t initSeq = socket->seq_number;


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

            memcpy(buf,header, sizeof(microtcp_header_t));
            memcpy(buf+sizeof(microtcp_header_t),buffer+(totalSent),payloadSize);

            header->checksum = crcCheck(buf,MICROTCP_MSS);
            encodeHeader(header);
            memcpy(buf,header, sizeof(microtcp_header_t));


            if (i!=2) {
                sent = sendto(socket->sd, buf, MICROTCP_MSS, 0, socket->addr, socket->address_len);
            } else chunks--;
            decodeHeader(header);
            if (!isSendSuccessful(sent, MICROTCP_MSS)) return sockError(socket, "Error sending chunk");
            header->seq_number += payloadSize;
            totalSent += payloadSize;
        }

        unsigned int remainingBytes = min % payloadSize;
        if (remainingBytes){
            header->data_len = remainingBytes;

            memcpy(buf,header, sizeof(microtcp_header_t));
            memcpy(buf+sizeof(microtcp_header_t),buffer+totalSent,remainingBytes);

            header->checksum = crcCheck(buf,sizeof(microtcp_header_t)+remainingBytes);

            encodeHeader(header);
            memcpy(buf,header, sizeof(microtcp_header_t));

            sent = sendto(socket->sd, buf, sizeof(microtcp_header_t)+remainingBytes, 0, socket->addr, socket->address_len);
            if (!isSendSuccessful(sent, sizeof(microtcp_header_t)+remainingBytes)) return sockError(socket, "Error sending remaining Bytes");
            chunks++;
            decodeHeader(header);
            header->seq_number += remainingBytes;
            totalSent+=remainingBytes;

        }

        remaining -= min;
        socket->seq_number = header->seq_number;
        printf("\nremaining1 %zu\n",remaining);

        /*GET ACKS*/
        printf("Waiting acks\n");
        printf("CHunks %zu\n", chunks);
        for (size_t i = 0; i < chunks; ++i) {
            recved = recvfrom(socket->sd, header, sizeof(microtcp_header_t), 0,
                              (struct sockaddr *) socket->addr, &socket->address_len);

            if (recved>0){
                decodeHeader(header);
                printf("%d\n",header->ack_number);
                if (header->ack_number == tempACK){
                    tempACKcounter++;
                    if (tempACKcounter >= 3){
                        printf("\nChunk lost, retransmitting\n");
                        socket->seq_number = header->ack_number;
                        totalSent = socket->seq_number - initSeq;
                        remaining = length-totalSent;
                        tempACKcounter=0;
                        break;
                    }
                } else{
                    totalSent = header->ack_number - initSeq;
                    remaining = length-totalSent;
                    tempACK = header->ack_number;
                    tempACKcounter=0;
                }
            } else {
                return sockError(socket,"Timeout waiting for ACKs\n");
            }
        }
        printf("remaining2 %zu\n",remaining);

    }

    free(buf);
    return 0;
}

ssize_t microtcp_recv (microtcp_sock_t *socket, void *buffer, size_t length, int flags) {
    /* Your code here */

    void *tempBuf = malloc(MICROTCP_MSS);
    uint32_t currAck = socket->ack_number;
    unsigned int index1 = 0;
    ssize_t recved=0;
    ssize_t sent;
    size_t total = 0;

    buffer = initBuf(buffer,length);
    while (total<length) {
        recved = recvfrom(socket->sd, tempBuf, MICROTCP_MSS, flags, socket->addr, &socket->address_len);

        if (recved>0){
            bufDecodeHeader(tempBuf);
            if(header->checksum != crcCheck(tempBuf, sizeof(microtcp_header_t)+header->data_len)) {
                perror("Checksum error");
                /* Need Retransmit */
            }
            /* Check for FIN ACK*/
            if (header->control == FIN_ACK) {
                socket->state = CLOSING_BY_PEER;
                microtcp_shutdown(socket, 0);
                break;
            }
            /* Chunk with data */
            if (header->seq_number==currAck){
                /* Chunk with right order */
                memcpy(buffer+index1, tempBuf + sizeof(microtcp_header_t),header->data_len);
                index1 += header->data_len;
                currAck += header->data_len;
                total+=header->data_len;
                socket->ack_number = currAck;
                header->ack_number = currAck;

            } else header->ack_number = socket->ack_number;
            /* Send Ack */
            printf("Sending ack %d\n",header->ack_number);
            header->seq_number = socket->seq_number;
            header->control = ACK;
            header->window = MICROTCP_RECVBUF_LEN - index1;
            header->data_len = 0;
            header->checksum = crcCheck(NULL,0);
            /* Send Ack */
            encodeHeader(header);
            sent = sendto(socket->sd, header, sizeof(microtcp_header_t), 0, socket->addr, socket->address_len);
            if (!isSendSuccessful(sent, sizeof(microtcp_header_t))) return sockError(socket, "Error sending ACK");

        } else{
            /* Recv timeout */
            perror("Timeouttt");
            break;
        }
    }
    free(tempBuf);
    printf("\n%zu %zu\n",length,total);
    return recved;
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

void waitZeroWindow(){
    int amount = rand()%MICROTCP_MSS;
    usleep(amount);
}


size_t minAmount(size_t curr_win_size, size_t cwnd, size_t remainingBytes){
    if (curr_win_size <= cwnd && curr_win_size <= remainingBytes) return curr_win_size;
    if (cwnd <= curr_win_size && cwnd <= remainingBytes) return cwnd;
    return remainingBytes;
}

uint8_t* initBuf(uint8_t buf[], size_t len){
    for (size_t i = 0; i < len; ++i) {
        buf[i] = 0;
    }
    return buf;
}


