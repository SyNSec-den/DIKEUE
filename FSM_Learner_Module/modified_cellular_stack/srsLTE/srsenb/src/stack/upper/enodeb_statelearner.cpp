/*
 *  Authors: Imtiaz Karim, Syed Rafiul Hussain, Abdullah Al Ishtiaq
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

#include "srsenb/hdr/stack/upper/enodeb_statelearner.h"
#include <iostream>
#include <inttypes.h> // for printing uint64_t

namespace srsenb {
enodeb_statelearner *enodeb_statelearner::m_instance = NULL;
pthread_mutex_t enodeb_statelearner_instance_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t enodeb_statelearner_reset_state_mutex = PTHREAD_MUTEX_INITIALIZER;
    enodeb_statelearner::enodeb_statelearner(): thread("ENODEB_STATELEARNER"){
        running = false;
        statelearner_connected       = false;
        return;
    }

    bool
    enodeb_statelearner::init(s1ap_interface_enodeb_statelearner* s1ap_) {
        m_pool = srslte::byte_buffer_pool::get_instance();
        m_s1ap = s1ap_;
        printf("enodeb-statelearner initialized\n");
        running             = false;
        start();
        return true;
    }


    void enodeb_statelearner::run_thread() {

        printf("The enodeb_statelearner thread has been started...\n");

        int sock_fd, err;
        struct sockaddr_in enodeblearnlib_server_addr;


        // socket create and verification
        sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (sock_fd == -1) {
            printf("enodeb-statelearner erver socket creation failed...\n");
            return ;
        }

        bzero(&enodeblearnlib_server_addr, sizeof(enodeblearnlib_server_addr));
        // assign IP, PORT
        enodeblearnlib_server_addr.sin_family = AF_INET;
        enodeblearnlib_server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        inet_pton(AF_INET, "127.0.0.1", &(enodeblearnlib_server_addr.sin_addr));
        enodeblearnlib_server_addr.sin_port = htons(60001);
        err = bind(sock_fd, (struct sockaddr *) &enodeblearnlib_server_addr, sizeof(enodeblearnlib_server_addr));
        if (err != 0) {
            close(sock_fd);
            printf("Error binding TCP socket for s1ap-learnlib server\n");
            return;
        }
        //Listen for connections
        err = listen(sock_fd, SOMAXCONN);
        if (err != 0) {
            close(sock_fd);
            printf("Error in s1ap-learnlib TCP socket listen\n");
            return;
        }

        srslte::byte_buffer_t *pdu = m_pool->allocate("enodeb_statelearner::run_thread");
        if (!pdu) {
            printf("Fatal Error: Couldn't allocate buffer in s1ap::run_thread().\n");
            return;
        }

        uint32_t sz = SRSLTE_MAX_BUFFER_SIZE_BYTES - SRSLTE_BUFFER_HEADER_OFFSET;

        m_enodeb_statelearner_sock = accept(sock_fd, (struct sockaddr *)NULL, (socklen_t *)NULL);
        if(m_enodeb_statelearner_sock<0){
            perror("Client accept failed\n");
            return;
        }
        printf("Statelearner is connected\n");
        running = true;
        int rd_sz;

        bool ret;
        while (running) {
            pdu->clear();
            rd_sz = recv(m_enodeb_statelearner_sock, pdu->msg, sz, 0);

            if(rd_sz == -1)
            {
                //printf("ERROR reading from TCP socket\n");
            }
            if(rd_sz == 0){
                printf("Client Disconnected. Need to run SRSEPC again.\n");
                return;
            }
            else{
                //printf("Received a message\n");
                pdu->N_bytes = rd_sz;
                pdu->msg[pdu->N_bytes] = '\0';
                printf("\nReceived Query from Statelearner = %s\n", pdu->msg);

                if(memcmp(pdu->msg, "Hello\n", pdu->N_bytes) == 0) {
                    printf("### Received the expected HELLO message ###\n");
                    uint8_t response[5] = "ACK\n";
                    uint8_t size = 5;
                    notify_response(response, size);
                }
                else {
                    ret = m_s1ap->execute_command(pdu->msg, pdu->N_bytes);
                    if (ret == false) {
                        uint8_t response[13] = "null_action\n";
                        uint8_t size = 13;
                        notify_response(response, size);
                    }
                }

            }
        }
    }

    void
    enodeb_statelearner::stop() {
        if(running) {
            running = false;
            thread_cancel();
            wait_thread_finish();
        }

        if (m_enodeb_statelearner_sock != -1){
            close(m_enodeb_statelearner_sock);
        }
        return;
    }

    
    enodeb_statelearner*
    enodeb_statelearner::get_instance(void) {
      pthread_mutex_lock(&enodeb_statelearner_instance_mutex);
      if (NULL == m_instance) {
        printf("created a new instance!!\n");
        m_instance = new enodeb_statelearner();
      }
      pthread_mutex_unlock(&enodeb_statelearner_instance_mutex);
      return (m_instance);
    }

bool enodeb_statelearner::notify_response(uint8_t *msg, uint16_t len) {
        printf("Sending response to statelearner\n");
        if ((send(m_enodeb_statelearner_sock, msg, len, 0)) < 0)
        {
            perror("Error in Send to Statelearner");
            exit(0);
        }
        return true;
    }
}