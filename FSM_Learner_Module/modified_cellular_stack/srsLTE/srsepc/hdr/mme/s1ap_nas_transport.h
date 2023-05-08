/*
 * Copyright 2013-2019 Software Radio Systems Limited
 *
 * This file is part of srsLTE.
 *
 * srsLTE is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsLTE is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */
#ifndef SRSEPC_S1AP_NAS_TRANSPORT_H
#define SRSEPC_S1AP_NAS_TRANSPORT_H

#include "mme_gtpc.h"
#include "s1ap_common.h"
#include "srsepc/hdr/hss/hss.h"
#include "srslte/asn1/gtpc.h"
#include "srslte/asn1/liblte_s1ap.h"
#include "srslte/common/buffer_pool.h"
#include "srsepc/hdr/mme/mme_statelearner.h" // Fuzzing

namespace srsepc {

class s1ap_nas_transport
{
public:
  static s1ap_nas_transport* m_instance;
  static s1ap_nas_transport* get_instance();
  static void                cleanup();
  void                       init(mme_statelearner_interface_s1ap *mme_statelearner_);

  bool handle_initial_ue_message(LIBLTE_S1AP_MESSAGE_INITIALUEMESSAGE_STRUCT* init_ue,
                                 struct sctp_sndrcvinfo*                      enb_sri,
                                 srslte::byte_buffer_t*                       reply_buffer,
                                 bool*                                        reply_flag);

  bool handle_uplink_nas_transport(LIBLTE_S1AP_MESSAGE_UPLINKNASTRANSPORT_STRUCT* ul_xport,
                                   struct sctp_sndrcvinfo*                        enb_sri,
                                   srslte::byte_buffer_t*                         reply_buffer,
                                   bool*                                          reply_flag);

  bool send_downlink_nas_transport(uint32_t               enb_ue_s1ap_id,
                                   uint32_t               mme_ue_s1ap_id,
                                   srslte::byte_buffer_t* nas_msg,
                                   struct sctp_sndrcvinfo enb_sri);


  bool handle_statelearner_query(uint8_t  msg_type);


private:
  s1ap_nas_transport();
  virtual ~s1ap_nas_transport();

  srslte::log*              m_s1ap_log;
  srslte::byte_buffer_pool* m_pool;

  s1ap*              m_s1ap;
  hss_interface_nas* m_hss;
  mme_gtpc*          m_mme_gtpc;
  mme_statelearner_interface_s1ap *m_mme_statelearner;

  nas_init_t m_nas_init;
  nas_if_t   m_nas_if;


};

} // namespace srsepc
#endif // SRSEPC_S1AP_NAS_TRANSPORT_H
