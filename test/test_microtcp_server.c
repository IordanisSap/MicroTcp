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

/*
 * You can use this file to write a test microTCP server.
 * This file is already inserted at the build system.
 */

#include "../lib/microtcp.h"
#include <arpa/inet.h>
#include "string.h"
#include "stdlib.h"
#include "stdio.h"

#define randomNum 35000
#define PORT 8080


int main(int argc, char **argv){
    microtcp_sock_t sock;
    struct sockaddr_in servaddr,cliaddr;
    int flag;

    sock = microtcp_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock.state == INVALID) {
        printf("Error initialising socket\n");
        return -1;
    }
    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    servaddr.sin_family    = AF_INET; // IPv4
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PORT);

    flag = microtcp_bind(&sock, (const struct sockaddr *) &servaddr, sizeof(servaddr));
    if (flag == -1){
        printf("Binding error\n");
    }
    microtcp_accept(&sock, ( struct sockaddr *) &cliaddr, sizeof(cliaddr));
    if (sock.state == INVALID){
        printf("Error accepting client\n");
        return -1;
    }
    printf("Successfully accepted client\n");
    sock.recvbuf = malloc(sizeof(int) * randomNum);

    microtcp_recv(&sock,sock.recvbuf,sizeof(uint8_t) * MICROTCP_RECVBUF_LEN,0);
    printf("Received from client\n");
    int *p = (int *) sock.recvbuf;
    for (int i = 0; i < randomNum; ++i) {
        printf("%d", *(p+i));
    }

}
