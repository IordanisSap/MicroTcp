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
 * You can use this file to write a test microTCP client.
 * This file is already inserted at the build system.
 */

#include "../lib/microtcp.h"
#include <arpa/inet.h>
#include "string.h"
#include "stdio.h"

#define randomNum 3000
#define PORT 8080

int main(int argc, char **argv) {
    microtcp_sock_t sock;
    struct sockaddr_in servaddr;
    int flag;
    int buf[randomNum* sizeof(int)];
    sock = microtcp_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock.state == INVALID) {
        printf("Error initialising socket\n");
        return -1;
    }
    memset(&servaddr, 0, sizeof(servaddr));

    // Filling server information
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(PORT);
    servaddr.sin_addr.s_addr = INADDR_ANY;

    flag = microtcp_connect(&sock,(const struct sockaddr *) &servaddr,sizeof(servaddr));
    if (flag == -1){
        printf("Error connecting to server\n");
    }
    printf("Connected to server\n");
    for (int i = 0; i < randomNum; ++i) {
        buf[i] = i;
    }
    int *p = (int *) buf;
    for (int i = 0; i < randomNum; ++i) {
        printf("%d", *(p+i));
    }
    microtcp_send(&sock,buf,randomNum* sizeof(int),0);
    microtcp_shutdown(&sock,5);
    if (sock.state == CLOSED) printf("Shutdown successful\n");
    return 0;
}
