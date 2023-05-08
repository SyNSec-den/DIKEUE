//
// Created by rafiul on 11/29/18.
//

#ifndef SRSLTE_MME_STATELEARNER_H
#define SRSLTE_MME_STATELEARNER_H

#include "srslte/common/buffer_pool.h"
#include "srslte/common/log.h"
#include "srslte/common/log_filter.h"
#include "srslte/common/buffer_pool.h"
#include "s1ap_common.h"
#include "srslte/common/threads.h"
#include "srslte/interfaces/epc_interfaces.h"
#include "srslte/common/fuzzing.h"

namespace srsepc
{

    class mme_statelearner: public mme_statelearner_interface_s1ap,
                            public thread
    {
    public:

        /*
        typedef struct gtpc_ctx{
          srslte::gtp_fteid_t mme_ctr_fteid;
          srslte::gtp_fteid_t sgw_ctr_fteid;
        }gtpc_ctx_t;
        */
        mme_statelearner();
        static mme_statelearner* get_instance(void);
        static void cleanup(void);

        bool init(s1ap_interface_mme_statelearner *s1ap_);
        void stop();

        // server
        int statelearner_listen();
        int get_mme_statelearner();


        //client
        //bool connect_statelearner();
        bool notify_response(uint8_t *msg, uint16_t len);
        void run_thread();

        void set_mme_statelearner_reset_state();
        void reset_mme_statelearner_reset_state();
        bool get_mme_statelearner_reset_state();


    private:


        srslte::byte_buffer_pool   *m_pool;
        mme_statelearner(const std::string &name_);
        virtual ~mme_statelearner();
        static mme_statelearner *m_instance;


        s1ap_interface_mme_statelearner* m_s1ap;



        in_addr_t m_mme_statelearner_ip;
        int m_mme_statelearner_sock;



        bool running = false;
        bool statelearner_connected       = false;
        bool mme_statelearner_reset_state = false;


        // Not sure if the following are required
        /*
        uint32_t m_next_ctrl_teid;
        std::map<uint32_t,uint64_t> m_mme_ctr_teid_to_imsi;
        std::map<uint64_t,struct gtpc_ctx> m_imsi_to_learnlib_ctx;
        */


    };

}



#endif //SRSLTE_MME_STATELEARNER_H
