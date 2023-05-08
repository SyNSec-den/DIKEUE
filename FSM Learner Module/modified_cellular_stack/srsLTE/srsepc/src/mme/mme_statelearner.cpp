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

#include "srsepc/hdr/mme/mme_statelearner.h"
#include <iostream>
#include <inttypes.h> // for printing uint64_t
#include "srsepc/hdr/mme/s1ap.h"
#include "srsepc/hdr/spgw/spgw.h"

namespace srsepc {


    mme_statelearner *mme_statelearner::m_instance = NULL;
    pthread_mutex_t mme_statelearner_instance_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t mme_statelearner_reset_state_mutex = PTHREAD_MUTEX_INITIALIZER;


    mme_statelearner::mme_statelearner(): thread("MME_STATELEARNER"){
        running = false;
        statelearner_connected       = false;
        mme_statelearner_reset_state = false;
        return;
    }

    mme_statelearner::~mme_statelearner() {
    }

    mme_statelearner*
    mme_statelearner::get_instance(void) {
        pthread_mutex_lock(&mme_statelearner_instance_mutex);
        if (NULL == m_instance) {
            m_instance = new mme_statelearner();
        }
        pthread_mutex_unlock(&mme_statelearner_instance_mutex);
        return (m_instance);
    }


    bool
    mme_statelearner::init(s1ap_interface_mme_statelearner* s1ap_) {


        m_pool = srslte::byte_buffer_pool::get_instance();
        m_s1ap = s1ap_;
        printf("mme-statelearner initialized\n");
        return true;
    }


    int
    mme_statelearner::statelearner_listen() {
        //This function sets up the TCP socket for MME to connect to StateLearner
        int sock_fd, err;
        struct sockaddr_in mmelearnlib_server_addr;

        printf("mme-statelearner Server Initializing\n");
        // socket create and verification
        sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (sock_fd == -1) {
            printf("S1-statelearner erver socket creation failed...\n");
            return -1;
        }

        bzero(&mmelearnlib_server_addr, sizeof(mmelearnlib_server_addr));
        // assign IP, PORT
        mmelearnlib_server_addr.sin_family = AF_INET;
        mmelearnlib_server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        inet_pton(AF_INET, "127.0.0.1", &(mmelearnlib_server_addr.sin_addr));
        mmelearnlib_server_addr.sin_port = htons(60000);
        err = bind(sock_fd, (struct sockaddr *) &mmelearnlib_server_addr, sizeof(mmelearnlib_server_addr));
        if (err != 0) {
            close(sock_fd);
            printf("Error binding TCP socket for s1ap-learnlib server\n");
            return -1;
        }

        //Listen for connections
        err = listen(sock_fd, SOMAXCONN);
        if (err != 0) {
            close(sock_fd);
            printf("Error in s1ap-learnlib TCP socket listen\n");
            return -1;
        }

        printf("Listen done ....\n");
        return sock_fd;
    }

    void mme_statelearner::run_thread() {

        printf("The mme_statelearner thread has been started...\n");

        int sock_fd, err;
        struct sockaddr_in mmelearnlib_server_addr;


        // socket create and verification
        sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (sock_fd == -1) {
            printf("S1-statelearner erver socket creation failed...\n");
            return ;
        }

        bzero(&mmelearnlib_server_addr, sizeof(mmelearnlib_server_addr));
        // assign IP, PORT
        mmelearnlib_server_addr.sin_family = AF_INET;
        mmelearnlib_server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        inet_pton(AF_INET, "127.0.0.1", &(mmelearnlib_server_addr.sin_addr));
        mmelearnlib_server_addr.sin_port = htons(60000);
        err = bind(sock_fd, (struct sockaddr *) &mmelearnlib_server_addr, sizeof(mmelearnlib_server_addr));
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

        srslte::byte_buffer_t *pdu = m_pool->allocate("mme_statelearner::run_thread");
        if (!pdu) {
            printf("Fatal Error: Couldn't allocate buffer in s1ap::run_thread().\n");
            return;
        }

        uint32_t sz = SRSLTE_MAX_BUFFER_SIZE_BYTES - SRSLTE_BUFFER_HEADER_OFFSET;

        m_mme_statelearner_sock = accept(sock_fd, (struct sockaddr *)NULL, (socklen_t *)NULL);
        if(m_mme_statelearner_sock<0){
            perror("Client accept failed\n");
            return;
        }
        printf("Statelearner is connected\n");
        running = true;
        int rd_sz;

        // Connect to MME
        // statelearner rx loop
        bool ret;
        while (running) {
            pdu->clear();
            rd_sz = recv(m_mme_statelearner_sock, pdu->msg, sz, 0);

            if(rd_sz == -1)
            {
            }
            if(rd_sz == 0){
                printf("Client Disconnected. Need to run SRSEPC again.\n");
                return;
            }
            else{
                pdu->N_bytes = rd_sz;
                pdu->msg[pdu->N_bytes] = '\0';

                if(memcmp(pdu->msg, "Hello\n", pdu->N_bytes) == 0) {
                    printf("### Received the expected HELLO message ###\n");
                    if (send(m_mme_statelearner_sock, "ACK\n", 5, 0) < 0)
                    {
                        perror("Error in Send to Statelearner");
                        exit(7);
                    }
                }
                else{
                    ret = m_s1ap->send_query(pdu->msg, pdu->N_bytes);

                    if (ret == false)
                    {
                        printf("Sending NULL_ACTION to statelearner!");
                        uint8_t response[13] = "null_action\n";
                        uint8_t size = 13;
                        notify_response(response, size);
                    }
                }

            }
        }
    }

    void
    mme_statelearner::stop() {

        if (m_mme_statelearner_sock != -1){
            close(m_mme_statelearner_sock);
        }

        return;

    }

    void
    mme_statelearner::cleanup(void) {
        pthread_mutex_lock(&mme_statelearner_instance_mutex);
        if (NULL != m_instance) {
            delete m_instance;
            m_instance = NULL;
        }
        pthread_mutex_unlock(&mme_statelearner_instance_mutex);
    }

    bool mme_statelearner::notify_response(uint8_t *msg, uint16_t len) {
        printf("Sending response to statelearner %s\n",msg);
        if (send(m_mme_statelearner_sock, msg, len, 0) < 0)
        {
            perror("Error in Send to Statelearner");
            exit(7);
        }
        return true;
    }


    void mme_statelearner::set_mme_statelearner_reset_state() {
        pthread_mutex_lock(&mme_statelearner_reset_state_mutex);
        mme_statelearner_reset_state = true;
        pthread_mutex_unlock(&mme_statelearner_reset_state_mutex);
    }

    void mme_statelearner::reset_mme_statelearner_reset_state() {
        pthread_mutex_lock(&mme_statelearner_reset_state_mutex);
        mme_statelearner_reset_state = false;
        pthread_mutex_unlock(&mme_statelearner_reset_state_mutex);
    }

    bool mme_statelearner::get_mme_statelearner_reset_state() {
        return mme_statelearner_reset_state;
    }

}