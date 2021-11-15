/*
 *  Author: Abdullah Al Ishtiaq
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <pthread.h>

#define ADAPTER_PORT 60000
#define DEVICE_PORT 58888

int learner_socket;
int device_socket; 

int connectToDevice(int port);
int waitForLearner(int port);

char *trim(char *s);

int main(int argc, char const *argv[])
{   

    device_socket = connectToDevice(DEVICE_PORT);
    if(device_socket < 0 ){
        printf("CONNECTION ERROR WITH DEVICE\n");
        return 1;
    }
    printf("Connected to device...\n");
    
    learner_socket = waitForLearner(ADAPTER_PORT);
    if(learner_socket < 0 ){
        printf("CONNECTION ERROR WITH LEARNER\n");
        return 1;
    }
    printf("Learner connected...\n");
    printf("\n");


    int valread;
	char* cmd = (char *) malloc(1024);
	char* resp = (char *) malloc(1024);
    
    while(1){
        memset(cmd, 0, 1024);
        memset(resp, 0, 1024);

        valread = read(learner_socket , cmd, 1024);
        cmd = trim(cmd);
        // printf("cmd : %s\n", cmd);

        send(device_socket , cmd , strlen(cmd) , 0 );

        valread = read(device_socket , resp, 1024);
        resp = trim(resp);
        strcat(resp, "\n");
        // printf("resp : %s\n", resp);

        send(learner_socket , resp , strlen(resp) , 0);

        // sleep(1);

        printf("%s -> %s\n\n", cmd, resp);

    }





    return 0;
}


int connectToDevice(int port){
    int sock = 0;
	struct sockaddr_in serv_addr;

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		printf("\n Socket creation error \n");
		return -1;
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	
	// Convert IPv4 and IPv6 addresses from text to binary form
	if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0)
	{
		printf("\nInvalid address/ Address not supported \n");
		return -1;
	}

	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
	{
		printf("\nConnection Failed \n");
		return -1;
	}

    return sock;
}

int waitForLearner(int port){
    int server_fd, sock;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
       
    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
       
    // Forcefully attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                                                  &opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons( port );
       
    // Forcefully attaching socket to the port 8080
    if (bind(server_fd, (struct sockaddr *)&address, 
                                 sizeof(address))<0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    if ((sock = accept(server_fd, (struct sockaddr *)&address, 
                       (socklen_t*)&addrlen))<0)
    {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    return sock;
}

int isSpace(char c){
    return (c == ' ' || c == '\n' || c == '\t');
}

char *ltrim(char *s){
    while(isSpace(*s)) s++;
    return s;
}

char *rtrim(char *s){
    char* back = s + strlen(s);
    while(isSpace(*--back));
    *(back+1) = '\0';
    return s;
}

char *trim(char *s){
    return rtrim(ltrim(s)); 
}