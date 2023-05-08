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
 * The file has been modified for DIKEUE. 
 * Modified by: Imtiaz Karim, Syed Rafiul Hussain, Abdullah Al Ishtiaq
 */


#include "srsepc/hdr/mme/s1ap.h"
#include "srsepc/hdr/mme/s1ap_nas_transport.h"
#include "srslte/common/liblte_security.h"
#include "srslte/common/security.h"
#include <cmath>
#include <inttypes.h> // for printing uint64_t
#include <srsepc/hdr/mme/nas.h>
#include <srslte/asn1/liblte_mme.h>

namespace srsepc {
uint32 msg_type_global = FUZZING_MSG_TYPE_EOL;
nas::nas(nas_init_t args, nas_if_t itf, srslte::log* nas_log) :
    m_pool(srslte::byte_buffer_pool::get_instance()),
    m_nas_log(nas_log),
    m_gtpc(itf.gtpc),
    m_s1ap(itf.s1ap),
    m_hss(itf.hss),
    m_mme(itf.mme),
    m_mcc(args.mcc),
    m_mnc(args.mnc),
    m_mme_group(args.mme_group),
    m_mme_code(args.mme_code),
    m_tac(args.tac),
    m_apn(args.apn),
    m_dns(args.dns),
    m_t3413(args.paging_timer),
    m_ue_under_test_imsi(args.ue_under_test_imsi),         
    m_enable_ue_state_fuzzing(args.enable_ue_state_fuzzing) 

{
  m_sec_ctx.integ_algo  = args.integ_algo;
  m_sec_ctx.cipher_algo = args.cipher_algo;
  m_nas_log->debug("NAS Context Initialized. MCC: 0x%x, MNC 0x%x\n", m_mcc, m_mnc);
}
srslte::byte_buffer_t* identity_replay_buffer = NULL;
srslte::byte_buffer_t* auth_replay_buffer     = NULL;
srslte::byte_buffer_t* smd_replay_buffer      = NULL;
srslte::byte_buffer_t* smd_ns_replay_buffer      = NULL;
srslte::byte_buffer_t* guti_replay_buffer     = NULL;
srslte::byte_buffer_t* dl_replay_buffer       = NULL;

void nas::reset()
{
  m_emm_ctx = {};
  m_ecm_ctx = {};
  for (int i = 0; i < MAX_ERABS_PER_UE; ++i) {
    m_esm_ctx[i] = {};
  }

  srslte::INTEGRITY_ALGORITHM_ID_ENUM integ_algo  = m_sec_ctx.integ_algo;
  srslte::CIPHERING_ALGORITHM_ID_ENUM cipher_algo = m_sec_ctx.cipher_algo;
  m_sec_ctx                                       = {};
  m_sec_ctx.integ_algo                            = integ_algo;
  m_sec_ctx.cipher_algo                           = cipher_algo;
}
void key_set(uint8_t* key)
{
  printf("setting!!\n");
  uint8_t copy[4] = {0, 0, 0, 0};
  key[0] = 0;
  key[1] = 0;
  key[2] = 0;
  key[3] = 0;
}
/**********************************
 *
 * Handle UE Initiating Messages
 *
 ********************************/
bool nas::handle_attach_request(uint32_t                enb_ue_s1ap_id,
                                struct sctp_sndrcvinfo* enb_sri,
                                srslte::byte_buffer_t*  nas_rx,
                                nas_init_t              args,
                                nas_if_t                itf,
                                srslte::log*            nas_log)
{
  uint32_t                                       m_tmsi = 0;
  uint64_t                                       imsi   = 0;
  LIBLTE_MME_ATTACH_REQUEST_MSG_STRUCT           attach_req;
  LIBLTE_MME_PDN_CONNECTIVITY_REQUEST_MSG_STRUCT pdn_con_req;
    srslte::byte_buffer_pool* pool = srslte::byte_buffer_pool::get_instance();
  pool->deallocate(identity_replay_buffer);
  pool->deallocate(auth_replay_buffer);
  pool->deallocate(smd_replay_buffer);
  pool->deallocate(smd_ns_replay_buffer);
  pool->deallocate(guti_replay_buffer);
  pool->deallocate(dl_replay_buffer);
  identity_replay_buffer = NULL;
  auth_replay_buffer = NULL;
  smd_replay_buffer = NULL;
  smd_ns_replay_buffer           = NULL;
  guti_replay_buffer = NULL;
  dl_replay_buffer = NULL;
  // Interfaces
  s1ap_interface_nas* s1ap = itf.s1ap;
  hss_interface_nas*  hss  = itf.hss;
  gtpc_interface_nas* gtpc = itf.gtpc;

  // Get NAS Attach Request and PDN connectivity request messages
  LIBLTE_ERROR_ENUM err = liblte_mme_unpack_attach_request_msg((LIBLTE_BYTE_MSG_STRUCT*)nas_rx, &attach_req);
  if (err != LIBLTE_SUCCESS) {
    nas_log->error("Error unpacking NAS attach request. Error: %s\n", liblte_error_text[err]);
    return false;
  }
  // Get PDN Connectivity Request*/
  err = liblte_mme_unpack_pdn_connectivity_request_msg(&attach_req.esm_msg, &pdn_con_req);
  if (err != LIBLTE_SUCCESS) {
    nas_log->error("Error unpacking NAS PDN Connectivity Request. Error: %s\n", liblte_error_text[err]);
    return false;
  }

  // Get UE IMSI
  if (attach_req.eps_mobile_id.type_of_id == LIBLTE_MME_EPS_MOBILE_ID_TYPE_IMSI) {
    for (int i = 0; i <= 14; i++) {
      imsi += attach_req.eps_mobile_id.imsi[i] * std::pow(10, 14 - i);
    }
    nas_log->console("Attach request -- IMSI: %015" PRIu64 "\n", imsi);
    nas_log->info("Attach request -- IMSI: %015" PRIu64 "\n", imsi);
    
    if(imsi != args.ue_under_test_imsi){
      nas_log->error("Unhandled IMSI in attach request\n");
      nas_log->console("Unhandled IMSI in attach request\n");
      return false;
    }

  } else if (attach_req.eps_mobile_id.type_of_id == LIBLTE_MME_EPS_MOBILE_ID_TYPE_GUTI) {
    m_tmsi = attach_req.eps_mobile_id.guti.m_tmsi;
    imsi   = s1ap->find_imsi_from_m_tmsi(m_tmsi);
    nas_log->console("Attach request -- M-TMSI: 0x%x\n", m_tmsi);
    nas_log->info("Attach request -- M-TMSI: 0x%x\n", m_tmsi);

  } else {
    nas_log->error("Unhandled Mobile Id type in attach request\n");
    return false;
  }

  

  // Get NAS Context if UE is known
  nas* nas_ctx = s1ap->find_nas_ctx_from_imsi(imsi);

  if (nas_ctx == NULL) {
    // Get attach type from attach request
    if (attach_req.eps_mobile_id.type_of_id == LIBLTE_MME_EPS_MOBILE_ID_TYPE_IMSI) {
      nas::handle_imsi_attach_request_unknown_ue(enb_ue_s1ap_id, enb_sri, attach_req, pdn_con_req, args, itf, nas_log);
      if(s1ap->get_mme_statelearner_reset_state()==false && args.enable_ue_state_fuzzing== true) {
        nas_log->console("Response: attach_request 5\n");
        uint8_t response[16] = "attach_request\n";
        uint8_t size = 16;
        s1ap->notify_response(response, size);
        return true;

      }

    } else if (attach_req.eps_mobile_id.type_of_id == LIBLTE_MME_EPS_MOBILE_ID_TYPE_GUTI) {
      nas::handle_guti_attach_request_unknown_ue(enb_ue_s1ap_id, enb_sri, attach_req, pdn_con_req, args, itf, nas_log);
      
      if(s1ap->get_mme_statelearner_reset_state()==false && args.enable_ue_state_fuzzing== true){

        nas_log->console("Response: attach_request_guti\n");
        uint8_t response[21] = "attach_request_guti\n";
        uint8_t size = 21;
        s1ap->notify_response(response, size);
      } 
      

    } else {
      return false;
    }
  } else {
    nas_log->info("Attach Request -- Found previously attached UE.\n");
    nas_log->console("Attach Request -- Found previously attach UE.\n");
    if (attach_req.eps_mobile_id.type_of_id == LIBLTE_MME_EPS_MOBILE_ID_TYPE_IMSI) {
      nas::handle_imsi_attach_request_known_ue(nas_ctx, enb_ue_s1ap_id, enb_sri, attach_req, pdn_con_req, nas_rx, args,
                                               itf, nas_log);
      
      if(s1ap->get_mme_statelearner_reset_state()==false && args.enable_ue_state_fuzzing== true) {
        nas_log->console("Response: attach_request\n");
        uint8_t response[16] = "attach_request\n";
        uint8_t size = 16;
        key_set(&nas_ctx->m_sec_ctx.k_nas_enc[16]);
        s1ap->notify_response(response, size);
        
      }
      
    } else if (attach_req.eps_mobile_id.type_of_id == LIBLTE_MME_EPS_MOBILE_ID_TYPE_GUTI) {
      nas::handle_guti_attach_request_known_ue(nas_ctx, enb_ue_s1ap_id, enb_sri, attach_req, pdn_con_req, nas_rx, args,
                                               itf, nas_log);
      
      if(s1ap->get_mme_statelearner_reset_state()==false && args.enable_ue_state_fuzzing== true){
        nas_log->console("Response: attach_request_guti\n");
        uint8_t response[21] = "attach_request_guti\n";
        uint8_t size = 21;
        printf("isuueeeeeeeeeeeeeeee is here\n");
        key_set(&nas_ctx->m_sec_ctx.k_nas_enc[16]);
        s1ap->notify_response(response, size);
      } 

    } else {
      return false;
    }
  }
  return true;
}

bool nas::handle_imsi_attach_request_unknown_ue(uint32_t                                              enb_ue_s1ap_id,
                                                struct sctp_sndrcvinfo*                               enb_sri,
                                                const LIBLTE_MME_ATTACH_REQUEST_MSG_STRUCT&           attach_req,
                                                const LIBLTE_MME_PDN_CONNECTIVITY_REQUEST_MSG_STRUCT& pdn_con_req,
                                                nas_init_t                                            args,
                                                nas_if_t                                              itf,
                                                srslte::log*                                          nas_log)
{
  nas*                      nas_ctx;
  srslte::byte_buffer_t*    nas_tx;
  srslte::byte_buffer_pool* pool = srslte::byte_buffer_pool::get_instance();
  pool->deallocate(identity_replay_buffer);
  pool->deallocate(auth_replay_buffer);
  pool->deallocate(smd_replay_buffer);
  pool->deallocate(smd_ns_replay_buffer);
  pool->deallocate(guti_replay_buffer);
  pool->deallocate(dl_replay_buffer);
  
  identity_replay_buffer         = NULL;
  auth_replay_buffer             = NULL;
  smd_replay_buffer              = NULL;
  smd_ns_replay_buffer           = NULL;
  guti_replay_buffer             = NULL;
  dl_replay_buffer               = NULL;
  // Interfaces
  s1ap_interface_nas* s1ap = itf.s1ap;
  hss_interface_nas*  hss  = itf.hss;
  gtpc_interface_nas* gtpc = itf.gtpc;

  // Get IMSI
  uint64_t imsi = 0;
  for (int i = 0; i <= 14; i++) {
    imsi += attach_req.eps_mobile_id.imsi[i] * std::pow(10, 14 - i);
  }

  // Create UE context
  nas_ctx = new nas(args, itf, nas_log);

  // Save IMSI, eNB UE S1AP Id, MME UE S1AP Id and make sure UE is EMM_DEREGISTERED
  nas_ctx->m_emm_ctx.imsi           = imsi;
  nas_ctx->m_emm_ctx.state          = EMM_STATE_DEREGISTERED;
  nas_ctx->m_ecm_ctx.enb_ue_s1ap_id = enb_ue_s1ap_id;
  nas_ctx->m_ecm_ctx.mme_ue_s1ap_id = s1ap->get_next_mme_ue_s1ap_id();

  // Save UE network capabilities
  memcpy(
      &nas_ctx->m_sec_ctx.ue_network_cap, &attach_req.ue_network_cap, sizeof(LIBLTE_MME_UE_NETWORK_CAPABILITY_STRUCT));
  nas_ctx->m_sec_ctx.ms_network_cap_present = attach_req.ms_network_cap_present;
  if (attach_req.ms_network_cap_present) {
    memcpy(&nas_ctx->m_sec_ctx.ms_network_cap,
           &attach_req.ms_network_cap,
           sizeof(LIBLTE_MME_MS_NETWORK_CAPABILITY_STRUCT));
  }

  uint8_t eps_bearer_id                       = pdn_con_req.eps_bearer_id; 
  nas_ctx->m_emm_ctx.procedure_transaction_id = pdn_con_req.proc_transaction_id;

  // Initialize NAS count
  nas_ctx->m_sec_ctx.ul_nas_count = 0;
  nas_ctx->m_sec_ctx.dl_nas_count = 0;

  // Set eNB information
  memcpy(&nas_ctx->m_ecm_ctx.enb_sri, enb_sri, sizeof(struct sctp_sndrcvinfo));

  // Save whether secure ESM information transfer is necessary
  nas_ctx->m_ecm_ctx.eit = pdn_con_req.esm_info_transfer_flag_present;

  // Initialize E-RABs
  for (uint i = 0; i < MAX_ERABS_PER_UE; i++) {
    nas_ctx->m_esm_ctx[i].state   = ERAB_DEACTIVATED;
    nas_ctx->m_esm_ctx[i].erab_id = i;
  }

  // Save attach request type
  nas_ctx->m_emm_ctx.attach_type = attach_req.eps_attach_type;

  if (args.enable_ue_state_fuzzing == false) {
    // Get Authentication Vectors from HSS
    if (!hss->gen_auth_info_answer(nas_ctx->m_emm_ctx.imsi,
                                   nas_ctx->m_sec_ctx.k_asme,
                                   nas_ctx->m_sec_ctx.autn,
                                   nas_ctx->m_sec_ctx.rand,
                                   nas_ctx->m_sec_ctx.xres)) {
      nas_log->console("User not found. IMSI %015" PRIu64 "\n", nas_ctx->m_emm_ctx.imsi);
      nas_log->info("User not found. IMSI %015" PRIu64 "\n", nas_ctx->m_emm_ctx.imsi);
      delete nas_ctx;
      return false;
    }
  }

  // Allocate eKSI for this authentication vector
  // Here we assume a new security context thus a new eKSI
  nas_ctx->m_sec_ctx.eksi = 0;

  // Save the UE context
  s1ap->add_nas_ctx_to_imsi_map(nas_ctx);
  s1ap->add_nas_ctx_to_mme_ue_s1ap_id_map(nas_ctx);
  s1ap->add_ue_to_enb_set(enb_sri->sinfo_assoc_id, nas_ctx->m_ecm_ctx.mme_ue_s1ap_id);

  if (args.enable_ue_state_fuzzing == false) {
    // Pack NAS Authentication Request in Downlink NAS Transport msg
    nas_tx = pool->allocate();
    nas_ctx->pack_authentication_request(nas_tx);

    // Send reply to eNB
    s1ap->send_downlink_nas_transport(
        nas_ctx->m_ecm_ctx.enb_ue_s1ap_id, nas_ctx->m_ecm_ctx.mme_ue_s1ap_id, nas_tx, nas_ctx->m_ecm_ctx.enb_sri);
    pool->deallocate(nas_tx);

    nas_log->info("Downlink NAS: Sending Authentication Request\n");
    nas_log->console("Downlink NAS: Sending Authentication Request\n");
  }
  return true;
}

bool nas::handle_imsi_attach_request_known_ue(nas*                                                  nas_ctx,
                                              uint32_t                                              enb_ue_s1ap_id,
                                              struct sctp_sndrcvinfo*                               enb_sri,
                                              const LIBLTE_MME_ATTACH_REQUEST_MSG_STRUCT&           attach_req,
                                              const LIBLTE_MME_PDN_CONNECTIVITY_REQUEST_MSG_STRUCT& pdn_con_req,
                                              srslte::byte_buffer_t*                                nas_rx,
                                              nas_init_t                                            args,
                                              nas_if_t                                              itf,
                                              srslte::log*                                          nas_log)
{
  bool err;
  srslte::byte_buffer_pool* pool = srslte::byte_buffer_pool::get_instance();
  pool->deallocate(identity_replay_buffer);
  pool->deallocate(auth_replay_buffer);
  pool->deallocate(smd_replay_buffer);
  pool->deallocate(smd_ns_replay_buffer);
  pool->deallocate(guti_replay_buffer);
  pool->deallocate(dl_replay_buffer);
  identity_replay_buffer = NULL;
  auth_replay_buffer     = NULL;
  smd_replay_buffer      = NULL;
  smd_ns_replay_buffer           = NULL;
  guti_replay_buffer     = NULL;
  dl_replay_buffer       = NULL;
  // Interfaces
  s1ap_interface_nas* s1ap = itf.s1ap;
  hss_interface_nas*  hss  = itf.hss;
  gtpc_interface_nas* gtpc = itf.gtpc;

  // Delete previous GTP-U session
  gtpc->send_delete_session_request(nas_ctx->m_emm_ctx.imsi);

  // Release previous context in the eNB, if present
  if (nas_ctx->m_ecm_ctx.mme_ue_s1ap_id != 0) {
    s1ap->send_ue_context_release_command(nas_ctx->m_ecm_ctx.mme_ue_s1ap_id);
  }
  // Delete previous NAS context
  s1ap->delete_ue_ctx(nas_ctx->m_emm_ctx.imsi);

  // Handle new attach
  err =
      nas::handle_imsi_attach_request_unknown_ue(enb_ue_s1ap_id, enb_sri, attach_req, pdn_con_req, args, itf, nas_log);
  return err;
}

bool nas::handle_guti_attach_request_unknown_ue(uint32_t                                              enb_ue_s1ap_id,
                                                struct sctp_sndrcvinfo*                               enb_sri,
                                                const LIBLTE_MME_ATTACH_REQUEST_MSG_STRUCT&           attach_req,
                                                const LIBLTE_MME_PDN_CONNECTIVITY_REQUEST_MSG_STRUCT& pdn_con_req,
                                                nas_init_t                                            args,
                                                nas_if_t                                              itf,
                                                srslte::log*                                          nas_log)

{
    srslte::byte_buffer_pool* pool = srslte::byte_buffer_pool::get_instance();
  pool->deallocate(identity_replay_buffer);
  pool->deallocate(auth_replay_buffer);
  pool->deallocate(smd_replay_buffer);
  pool->deallocate(smd_ns_replay_buffer);
  pool->deallocate(guti_replay_buffer);
  pool->deallocate(dl_replay_buffer);
  identity_replay_buffer = NULL;
  auth_replay_buffer     = NULL;
  smd_replay_buffer      = NULL;
  smd_ns_replay_buffer           = NULL;
  guti_replay_buffer     = NULL;
  dl_replay_buffer       = NULL;
  nas*                      nas_ctx;
  srslte::byte_buffer_t*    nas_tx;

  // Interfaces
  s1ap_interface_nas* s1ap = itf.s1ap;
  hss_interface_nas*  hss  = itf.hss;
  gtpc_interface_nas* gtpc = itf.gtpc;

  nas_log->console("@@@ ATTATCH REQUEST unknown GUTI @@@\n");
  // Create new NAS context.
  nas_ctx = new nas(args, itf, nas_log);

  // Could not find IMSI from M-TMSI, send Id request
  // The IMSI will be set when the identity response is received
  // Set EMM ctx
  nas_ctx->m_emm_ctx.imsi = 0;
  if (args.enable_ue_state_fuzzing == true)
    nas_ctx->m_emm_ctx.imsi = args.ue_under_test_imsi; 

  nas_ctx->m_emm_ctx.state = EMM_STATE_DEREGISTERED;
  // Set ECM context
  nas_ctx->m_ecm_ctx.enb_ue_s1ap_id = enb_ue_s1ap_id;
  nas_ctx->m_ecm_ctx.mme_ue_s1ap_id = s1ap->get_next_mme_ue_s1ap_id();

  // Save UE network capabilities
  memcpy(
      &nas_ctx->m_sec_ctx.ue_network_cap, &attach_req.ue_network_cap, sizeof(LIBLTE_MME_UE_NETWORK_CAPABILITY_STRUCT));
  nas_ctx->m_sec_ctx.ms_network_cap_present = attach_req.ms_network_cap_present;
  if (attach_req.ms_network_cap_present) {
    memcpy(&nas_ctx->m_sec_ctx.ms_network_cap,
           &attach_req.ms_network_cap,
           sizeof(LIBLTE_MME_MS_NETWORK_CAPABILITY_STRUCT));
  }

  uint8_t eps_bearer_id                       = pdn_con_req.eps_bearer_id;
  nas_ctx->m_emm_ctx.procedure_transaction_id = pdn_con_req.proc_transaction_id;

  // Initialize NAS count
  nas_ctx->m_sec_ctx.ul_nas_count = 0;
  nas_ctx->m_sec_ctx.dl_nas_count = 0;

  // Add eNB info to UE ctxt
  memcpy(&nas_ctx->m_ecm_ctx.enb_sri, enb_sri, sizeof(struct sctp_sndrcvinfo));

  // Save whether ESM information transfer is necessary
  nas_ctx->m_ecm_ctx.eit = pdn_con_req.esm_info_transfer_flag_present;

  // Initialize E-RABs
  for (uint i = 0; i < MAX_ERABS_PER_UE; i++) {
    nas_ctx->m_esm_ctx[i].state   = ERAB_DEACTIVATED;
    nas_ctx->m_esm_ctx[i].erab_id = i;
  }

  // Save attach request type
  nas_ctx->m_emm_ctx.attach_type = attach_req.eps_attach_type;

  // Allocate eKSI for this authentication vector
  // Here we assume a new security context thus a new eKSI
  nas_ctx->m_sec_ctx.eksi = 0;

  if (args.enable_ue_state_fuzzing == true) { 
    s1ap->add_nas_ctx_to_imsi_map(nas_ctx);   
  }

  // Store temporary ue context
  s1ap->add_nas_ctx_to_mme_ue_s1ap_id_map(nas_ctx);
  s1ap->add_ue_to_enb_set(enb_sri->sinfo_assoc_id, nas_ctx->m_ecm_ctx.mme_ue_s1ap_id);

  if (args.enable_ue_state_fuzzing == false) {
    // Send Identity Request
    nas_tx = pool->allocate();
    nas_ctx->pack_identity_request(nas_tx);
    s1ap->send_downlink_nas_transport(
        nas_ctx->m_ecm_ctx.enb_ue_s1ap_id, nas_ctx->m_ecm_ctx.mme_ue_s1ap_id, nas_tx, nas_ctx->m_ecm_ctx.enb_sri);
    pool->deallocate(nas_tx);
  }

  return true;
}

bool nas::handle_guti_attach_request_known_ue(nas*                                                  nas_ctx,
                                              uint32_t                                              enb_ue_s1ap_id,
                                              struct sctp_sndrcvinfo*                               enb_sri,
                                              const LIBLTE_MME_ATTACH_REQUEST_MSG_STRUCT&           attach_req,
                                              const LIBLTE_MME_PDN_CONNECTIVITY_REQUEST_MSG_STRUCT& pdn_con_req,
                                              srslte::byte_buffer_t*                                nas_rx,
                                              nas_init_t                                            args,
                                              nas_if_t                                              itf,
                                              srslte::log*                                          nas_log)
{
  bool                      msg_valid = false;
  srslte::byte_buffer_t*    nas_tx;
  srslte::byte_buffer_pool* pool = srslte::byte_buffer_pool::get_instance();
  pool->deallocate(identity_replay_buffer);
  pool->deallocate(auth_replay_buffer);
  pool->deallocate(smd_replay_buffer);
  pool->deallocate(smd_ns_replay_buffer);
  pool->deallocate(guti_replay_buffer);
  pool->deallocate(dl_replay_buffer);
  identity_replay_buffer         = NULL;
  auth_replay_buffer             = NULL;
  smd_replay_buffer              = NULL;
  smd_ns_replay_buffer           = NULL;
  guti_replay_buffer             = NULL;
  dl_replay_buffer               = NULL;
  emm_ctx_t* emm_ctx             = &nas_ctx->m_emm_ctx;
  ecm_ctx_t* ecm_ctx             = &nas_ctx->m_ecm_ctx;
  sec_ctx_t* sec_ctx             = &nas_ctx->m_sec_ctx;

  // Interfaces
  s1ap_interface_nas* s1ap = itf.s1ap;
  hss_interface_nas*  hss  = itf.hss;
  gtpc_interface_nas* gtpc = itf.gtpc;

  // Check NAS integrity
  msg_valid = nas_ctx->integrity_check(nas_rx);


  if (emm_ctx->state == EMM_STATE_DEREGISTERED) { 
    nas_log->console(
        "GUTI Attach -- NAS Integrity OK. UL count %d, DL count %d\n", sec_ctx->ul_nas_count, sec_ctx->dl_nas_count);
    nas_log->info(
        "GUTI Attach -- NAS Integrity OK. UL count %d, DL count %d\n", sec_ctx->ul_nas_count, sec_ctx->dl_nas_count);

    // Create new MME UE S1AP Identity
    ecm_ctx->mme_ue_s1ap_id = s1ap->get_next_mme_ue_s1ap_id();
    ecm_ctx->enb_ue_s1ap_id = enb_ue_s1ap_id;

    emm_ctx->procedure_transaction_id = pdn_con_req.proc_transaction_id;

    // Save Attach type
    emm_ctx->attach_type = attach_req.eps_attach_type;

    // Set eNB information
    ecm_ctx->enb_ue_s1ap_id = enb_ue_s1ap_id;
    memcpy(&ecm_ctx->enb_sri, enb_sri, sizeof(struct sctp_sndrcvinfo));

    // Save whether secure ESM information transfer is necessary
    ecm_ctx->eit = pdn_con_req.esm_info_transfer_flag_present;

    // Initialize E-RABs
    for (uint i = 0; i < MAX_ERABS_PER_UE; i++) {
      nas_ctx->m_esm_ctx[i].state   = ERAB_DEACTIVATED;
      nas_ctx->m_esm_ctx[i].erab_id = i;
    }

    // Store context based on MME UE S1AP id
    s1ap->add_nas_ctx_to_mme_ue_s1ap_id_map(nas_ctx);
    s1ap->add_ue_to_enb_set(enb_sri->sinfo_assoc_id, ecm_ctx->mme_ue_s1ap_id);

    // Re-generate K_eNB
    srslte::security_generate_k_enb(sec_ctx->k_asme, sec_ctx->ul_nas_count, sec_ctx->k_enb);
    nas_log->info("Generating KeNB with UL NAS COUNT: %d\n", sec_ctx->ul_nas_count);
    nas_log->console("Generating KeNB with UL NAS COUNT: %d\n", sec_ctx->ul_nas_count);
    nas_log->info_hex(sec_ctx->k_enb, 32, "Key eNodeB (k_enb)\n");

    if (args.enable_ue_state_fuzzing == false) { 
      // Send reply
      nas_tx = pool->allocate();
      if (ecm_ctx->eit) {
        nas_log->console("Secure ESM information transfer requested.\n");
        nas_log->info("Secure ESM information transfer requested.\n");
        nas_ctx->pack_esm_information_request(nas_tx);
        s1ap->send_downlink_nas_transport(ecm_ctx->enb_ue_s1ap_id, ecm_ctx->mme_ue_s1ap_id, nas_tx, *enb_sri);
      } else {
        // Get subscriber info from HSS
        uint8_t default_bearer = 5;
        hss->gen_update_loc_answer(emm_ctx->imsi, &nas_ctx->m_esm_ctx[default_bearer].qci);
        nas_log->debug("Getting subscription information -- QCI %d\n", nas_ctx->m_esm_ctx[default_bearer].qci);
        nas_log->console("Getting subscription information -- QCI %d\n", nas_ctx->m_esm_ctx[default_bearer].qci);
        gtpc->send_create_session_request(emm_ctx->imsi);
      }
      pool->deallocate(nas_tx); 
    }                           
    sec_ctx->ul_nas_count++;
    return true;
  } else { 
    if (emm_ctx->state != EMM_STATE_DEREGISTERED) {
      nas_log->error("Received GUTI-Attach Request from attached user.\n");
      nas_log->console("Received GUTI-Attach Request from attached user.\n");

      // Delete previous Ctx, restart authentication
      // Detaching previoulsy attached UE.
      gtpc->send_delete_session_request(emm_ctx->imsi);
      if (ecm_ctx->mme_ue_s1ap_id != 0) {
        s1ap->send_ue_context_release_command(ecm_ctx->mme_ue_s1ap_id);
      }
    }
    // Create new MME UE S1AP Identity

    if (args.enable_ue_state_fuzzing == false) {
      // Make sure context from previous NAS connections is not present
      if (ecm_ctx->mme_ue_s1ap_id != 0) {
        s1ap->release_ue_ecm_ctx(ecm_ctx->mme_ue_s1ap_id);
      }
    }
    ecm_ctx->mme_ue_s1ap_id =
        s1ap->get_next_mme_ue_s1ap_id(); 

    // Set EMM as de-registered
    emm_ctx->state = EMM_STATE_DEREGISTERED;
    // Save Attach type
    emm_ctx->attach_type = attach_req.eps_attach_type;

    // Set eNB information
    ecm_ctx->enb_ue_s1ap_id = enb_ue_s1ap_id;
    memcpy(&ecm_ctx->enb_sri, enb_sri, sizeof(struct sctp_sndrcvinfo));
    // Save whether secure ESM information transfer is necessary
    ecm_ctx->eit = pdn_con_req.esm_info_transfer_flag_present;

    // Initialize E-RABs
    for (uint i = 0; i < MAX_ERABS_PER_UE; i++) {
      nas_ctx->m_esm_ctx[i].state   = ERAB_DEACTIVATED;
      nas_ctx->m_esm_ctx[i].erab_id = i;
    }

    // Store context based on MME UE S1AP id
    s1ap->add_nas_ctx_to_mme_ue_s1ap_id_map(nas_ctx);
    s1ap->add_ue_to_enb_set(enb_sri->sinfo_assoc_id, ecm_ctx->mme_ue_s1ap_id);

    if (args.enable_ue_state_fuzzing == true) {
      // Re-generate K_eNB
      srslte::security_generate_k_enb(sec_ctx->k_asme, sec_ctx->ul_nas_count, sec_ctx->k_enb);
      nas_log->info("Generating KeNB with UL NAS COUNT: %d\n", sec_ctx->ul_nas_count);
      nas_log->console("Generating KeNB with UL NAS COUNT: %d\n", sec_ctx->ul_nas_count);
      nas_log->info_hex(sec_ctx->k_enb, 32, "Key eNodeB (k_enb)\n");
    }

    if (args.enable_ue_state_fuzzing == false) {
      // NAS integrity failed. Re-start authentication process.
      nas_log->console("GUTI Attach request NAS integrity failed.\n");
      nas_log->console("RE-starting authentication procedure.\n");

      // Get Authentication Vectors from HSS
      if (!hss->gen_auth_info_answer(emm_ctx->imsi, sec_ctx->k_asme, sec_ctx->autn, sec_ctx->rand, sec_ctx->xres)) {
        nas_log->console("User not found. IMSI %015" PRIu64 "\n", emm_ctx->imsi);
        nas_log->info("User not found. IMSI %015" PRIu64 "\n", emm_ctx->imsi);
        return false;
      }

      // Restarting security context. Reseting eKSI to 0.
      sec_ctx->eksi = 0;
      nas_tx        = pool->allocate();
      nas_ctx->pack_authentication_request(nas_tx);

      // Send reply to eNB
      s1ap->send_downlink_nas_transport(ecm_ctx->enb_ue_s1ap_id, ecm_ctx->mme_ue_s1ap_id, nas_tx, *enb_sri);
      pool->deallocate(nas_tx);
      nas_log->info("Downlink NAS: Sent Authentication Request\n");
      nas_log->console("Downlink NAS: Sent Authentication Request\n");
    }
    return true;
  }
}

// Service Requests
bool nas::handle_service_request(uint32_t                m_tmsi,
                                 uint32_t                enb_ue_s1ap_id,
                                 struct sctp_sndrcvinfo* enb_sri,
                                 srslte::byte_buffer_t*  nas_rx,
                                 nas_init_t              args,
                                 nas_if_t                itf,
                                 srslte::log*            nas_log)
{
  nas_log->info("Service request -- S-TMSI 0x%x\n", m_tmsi);
  nas_log->console("Service request -- S-TMSI 0x%x\n", m_tmsi);
  nas_log->info("Service request -- eNB UE S1AP Id %d\n", enb_ue_s1ap_id);
  nas_log->console("Service request -- eNB UE S1AP Id %d\n", enb_ue_s1ap_id);

  bool                                  mac_valid = false;
  LIBLTE_MME_SERVICE_REQUEST_MSG_STRUCT service_req;
  srslte::byte_buffer_pool*             pool = srslte::byte_buffer_pool::get_instance();

  // Interfaces
  s1ap_interface_nas* s1ap = itf.s1ap;
  hss_interface_nas*  hss  = itf.hss;
  gtpc_interface_nas* gtpc = itf.gtpc;
  mme_interface_nas*  mme  = itf.mme;

  LIBLTE_ERROR_ENUM err = liblte_mme_unpack_service_request_msg((LIBLTE_BYTE_MSG_STRUCT*)nas_rx, &service_req);
  if (err != LIBLTE_SUCCESS) {
    nas_log->error("Could not unpack service request\n");
    return false;
  }

  uint64_t imsi = s1ap->find_imsi_from_m_tmsi(m_tmsi);

  if (imsi == 0 && args.enable_ue_state_fuzzing == true) {
    imsi = args.ue_under_test_imsi;
  }

  if (imsi == 0) {
    nas_log->console("Could not find IMSI from M-TMSI. M-TMSI 0x%x\n", m_tmsi);
    nas_log->error("Could not find IMSI from M-TMSI. M-TMSI 0x%x\n", m_tmsi);
    nas nas_tmp(args, itf, nas_log);
    nas_tmp.m_ecm_ctx.enb_ue_s1ap_id = enb_ue_s1ap_id;
    nas_tmp.m_ecm_ctx.mme_ue_s1ap_id = s1ap->get_next_mme_ue_s1ap_id();

    if (args.enable_ue_state_fuzzing == false) {
      srslte::byte_buffer_t* nas_tx = pool->allocate();
      nas_tmp.pack_service_reject(nas_tx, LIBLTE_MME_EMM_CAUSE_IMPLICITLY_DETACHED);
      s1ap->send_downlink_nas_transport(enb_ue_s1ap_id, nas_tmp.m_ecm_ctx.mme_ue_s1ap_id, nas_tx, *enb_sri);
      pool->deallocate(nas_tx);
    }

    
    if (s1ap->get_mme_statelearner_reset_state() == false && args.enable_ue_state_fuzzing == true) {
      nas_log->console("Response: service_request 1\n");
      uint8_t response[17] = "service_request\n";
      uint8_t size         = 17;
      s1ap->notify_response(response, size);
    } 
    
    return true;
  }

  nas* nas_ctx = s1ap->find_nas_ctx_from_imsi(imsi);

  if (nas_ctx == NULL || nas_ctx->m_emm_ctx.state != EMM_STATE_REGISTERED) {
    nas_log->console("UE is not EMM-Registered.\n");
    nas_log->error("UE is not EMM-Registered.\n");
    nas nas_tmp(args, itf, nas_log);
    nas_tmp.m_ecm_ctx.enb_ue_s1ap_id = enb_ue_s1ap_id;
    nas_tmp.m_ecm_ctx.mme_ue_s1ap_id = s1ap->get_next_mme_ue_s1ap_id();

    if (args.enable_ue_state_fuzzing == false) {
      srslte::byte_buffer_t* nas_tx = pool->allocate();
      nas_tmp.pack_service_reject(nas_tx, LIBLTE_MME_EMM_CAUSE_IMPLICITLY_DETACHED);
      s1ap->send_downlink_nas_transport(enb_ue_s1ap_id, nas_tmp.m_ecm_ctx.mme_ue_s1ap_id, nas_tx, *enb_sri);
      pool->deallocate(nas_tx);
    }
    
    if (s1ap->get_mme_statelearner_reset_state() == false && args.enable_ue_state_fuzzing == true) {
      nas_log->console("Response: service_request 2\n");
      uint8_t response[17] = "service_request\n";
      uint8_t size         = 17;
      s1ap->notify_response(response, size);
    } 
    
    return true;
  }

  emm_ctx_t* emm_ctx = &nas_ctx->m_emm_ctx;
  ecm_ctx_t* ecm_ctx = &nas_ctx->m_ecm_ctx;
  sec_ctx_t* sec_ctx = &nas_ctx->m_sec_ctx;

  mac_valid = nas_ctx->short_integrity_check(nas_rx); 

  if (mac_valid) {
    nas_log->console("Service Request -- Short MAC valid\n");
    nas_log->info("Service Request -- Short MAC valid\n");

    if (ecm_ctx->state == ECM_STATE_CONNECTED) {
      nas_log->error("Service Request -- User is ECM CONNECTED\n");

      // Release previous context
      nas_log->info("Service Request -- Releasing previouse ECM context. eNB S1AP Id %d, MME UE S1AP Id %d\n",
                    ecm_ctx->enb_ue_s1ap_id,
                    ecm_ctx->mme_ue_s1ap_id);
      s1ap->send_ue_context_release_command(ecm_ctx->mme_ue_s1ap_id);
      s1ap->release_ue_ecm_ctx(ecm_ctx->mme_ue_s1ap_id);
    }

    ecm_ctx->enb_ue_s1ap_id = enb_ue_s1ap_id;

    // UE not connect. Connect normally.
    nas_log->console("Service Request -- User is ECM DISCONNECTED\n");
    nas_log->info("Service Request -- User is ECM DISCONNECTED\n");

    // Create ECM context
    ecm_ctx->mme_ue_s1ap_id = s1ap->get_next_mme_ue_s1ap_id();

    // Set eNB information
    ecm_ctx->enb_ue_s1ap_id = enb_ue_s1ap_id;
    memcpy(&ecm_ctx->enb_sri, enb_sri, sizeof(struct sctp_sndrcvinfo));

    // Save whether secure ESM information transfer is necessary
    ecm_ctx->eit = false;

    // Get UE IP, and uplink F-TEID
    if (emm_ctx->ue_ip.s_addr == 0) {
      nas_log->error("UE has no valid IP assigned upon reception of service request");
    }

    nas_log->console("UE previously assigned IP: %s\n", inet_ntoa(emm_ctx->ue_ip));

    // Re-generate K_eNB
    srslte::security_generate_k_enb(sec_ctx->k_asme, sec_ctx->ul_nas_count, sec_ctx->k_enb);
    nas_log->info("Generating KeNB with UL NAS COUNT: %d\n", sec_ctx->ul_nas_count);
    nas_log->console("Generating KeNB with UL NAS COUNT: %d\n", sec_ctx->ul_nas_count);
    nas_log->info_hex(sec_ctx->k_enb, 32, "Key eNodeB (k_enb)\n");
    nas_log->console("UE Ctr TEID %d\n", emm_ctx->sgw_ctrl_fteid.teid);

    // Stop T3413 if running
    if (mme->is_nas_timer_running(T_3413, emm_ctx->imsi)) {
      mme->remove_nas_timer(T_3413, emm_ctx->imsi);
    }

    // Save UE ctx to MME UE S1AP id
    s1ap->add_nas_ctx_to_mme_ue_s1ap_id_map(nas_ctx);


    sec_ctx->ul_nas_count++;
  } else {
    nas_log->console("Service Request -- Short MAC invalid\n");
    nas_log->info("Service Request -- Short MAC invalid\n");
    if (ecm_ctx->state == ECM_STATE_CONNECTED) {
      nas_log->error("Service Request -- User is ECM CONNECTED\n");

      // Release previous context
      nas_log->info("Service Request -- Releasing previouse ECM context. eNB S1AP Id %d, MME UE S1AP Id %d\n",
                    ecm_ctx->enb_ue_s1ap_id,
                    ecm_ctx->mme_ue_s1ap_id);
      s1ap->send_ue_context_release_command(ecm_ctx->mme_ue_s1ap_id);
      s1ap->release_ue_ecm_ctx(ecm_ctx->mme_ue_s1ap_id);
    }

    // Reset and store context with new mme s1ap id
    nas_ctx->reset();
    memcpy(&ecm_ctx->enb_sri, enb_sri, sizeof(struct sctp_sndrcvinfo));
    ecm_ctx->enb_ue_s1ap_id = enb_ue_s1ap_id;
    ecm_ctx->mme_ue_s1ap_id = s1ap->get_next_mme_ue_s1ap_id();
    s1ap->add_nas_ctx_to_mme_ue_s1ap_id_map(nas_ctx);
    s1ap->add_ue_to_enb_set(enb_sri->sinfo_assoc_id, nas_ctx->m_ecm_ctx.mme_ue_s1ap_id);

    if (args.enable_ue_state_fuzzing == false) {
      srslte::byte_buffer_t* nas_tx = pool->allocate();
      nas_ctx->pack_service_reject(nas_tx, LIBLTE_MME_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK);
      s1ap->send_downlink_nas_transport(ecm_ctx->enb_ue_s1ap_id, ecm_ctx->mme_ue_s1ap_id, nas_tx, *enb_sri);
      pool->deallocate(nas_tx);

      nas_log->console("Service Request -- Short MAC invalid. Sending service reject.\n");
      nas_log->warning("Service Request -- Short MAC invalid. Sending service reject.\n");
      nas_log->info(
          "Service Reject -- eNB_UE_S1AP_ID %d MME_UE_S1AP_ID %d.\n", enb_ue_s1ap_id, ecm_ctx->mme_ue_s1ap_id);
    }
  }
  
  if (s1ap->get_mme_statelearner_reset_state() == false && args.enable_ue_state_fuzzing == true) {
    nas_log->console("Response: service_request 3\n");
    uint8_t response[17] = "service_request\n";
    uint8_t size         = 17;
    s1ap->notify_response(response, size);
  } 
  
  return true;
}

bool nas::handle_detach_request(uint32_t                m_tmsi,
                                uint32_t                enb_ue_s1ap_id,
                                struct sctp_sndrcvinfo* enb_sri,
                                srslte::byte_buffer_t*  nas_rx,
                                nas_init_t              args,
                                nas_if_t                itf,
                                srslte::log*            nas_log)
{
  nas_log->info("Detach Request -- S-TMSI 0x%x\n", m_tmsi);
  nas_log->console("Detach Request -- S-TMSI 0x%x\n", m_tmsi);
  nas_log->info("Detach Request -- eNB UE S1AP Id %d\n", enb_ue_s1ap_id);
  nas_log->console("Detach Request -- eNB UE S1AP Id %d\n", enb_ue_s1ap_id);

  bool                                 mac_valid = false;
  LIBLTE_MME_DETACH_REQUEST_MSG_STRUCT detach_req;

  // Interfaces
  s1ap_interface_nas* s1ap = itf.s1ap;
  hss_interface_nas*  hss  = itf.hss;
  gtpc_interface_nas* gtpc = itf.gtpc;

  LIBLTE_ERROR_ENUM err = liblte_mme_unpack_detach_request_msg((LIBLTE_BYTE_MSG_STRUCT*)nas_rx, &detach_req);
  if (err != LIBLTE_SUCCESS) {
    nas_log->error("Could not unpack detach request\n");
    return false;
  }

  uint64_t imsi = s1ap->find_imsi_from_m_tmsi(m_tmsi);
  if (imsi == 0) {
    nas_log->console("Could not find IMSI from M-TMSI. M-TMSI 0x%x\n", m_tmsi);
    nas_log->error("Could not find IMSI from M-TMSI. M-TMSI 0x%x\n", m_tmsi);
    return true;
  }

  nas* nas_ctx = s1ap->find_nas_ctx_from_imsi(imsi);
  if (nas_ctx == NULL) {
    nas_log->console("Could not find UE context from IMSI\n");
    nas_log->error("Could not find UE context from IMSI\n");
    return true;
  }

  emm_ctx_t* emm_ctx = &nas_ctx->m_emm_ctx;
  ecm_ctx_t* ecm_ctx = &nas_ctx->m_ecm_ctx;
  sec_ctx_t* sec_ctx = &nas_ctx->m_sec_ctx;

  gtpc->send_delete_session_request(emm_ctx->imsi);
  emm_ctx->state = EMM_STATE_DEREGISTERED;
  sec_ctx->ul_nas_count++;

  nas_log->console("Received. M-TMSI 0x%x\n", m_tmsi);
  // Received detach request as an initial UE message
  // eNB created new ECM context to send the detach request; this needs to be cleared.
  ecm_ctx->mme_ue_s1ap_id = s1ap->get_next_mme_ue_s1ap_id();
  ecm_ctx->enb_ue_s1ap_id = enb_ue_s1ap_id;
  s1ap->send_ue_context_release_command(ecm_ctx->mme_ue_s1ap_id);

  return true;
}

bool nas::handle_tracking_area_update_request(uint32_t                m_tmsi,
                                              uint32_t                enb_ue_s1ap_id,
                                              struct sctp_sndrcvinfo* enb_sri,
                                              srslte::byte_buffer_t*  nas_rx,
                                              nas_init_t              args,
                                              nas_if_t                itf,
                                              srslte::log*            nas_log)
{
  nas* nas_ctx;

  LIBLTE_MME_TAU_REQUEST_MSG_STRUCT tau_req;

  nas_log->info("Tracking Area Update Request -- S-TMSI 0x%x\n", m_tmsi);
  nas_log->console("Tracking Area Update Request -- S-TMSI 0x%x\n", m_tmsi);
  nas_log->info("Tracking Area Update Request -- eNB UE S1AP Id %d\n", enb_ue_s1ap_id);
  nas_log->console("Tracking Area Update Request -- eNB UE S1AP Id %d\n", enb_ue_s1ap_id);

  LIBLTE_ERROR_ENUM err = liblte_mme_unpack_tracking_area_update_request_msg((LIBLTE_BYTE_MSG_STRUCT*)nas_rx, &tau_req);

  if (err != LIBLTE_SUCCESS) {
    nas_log->error("Error unpacking NAS attach request. Error: %s\n", liblte_error_text[err]);
    return false;
  }
  m_tmsi = tau_req.eps_mobile_id.guti.m_tmsi;

  // Interfaces
  s1ap_interface_nas* s1ap = itf.s1ap;
  hss_interface_nas*  hss  = itf.hss;
  gtpc_interface_nas* gtpc = itf.gtpc;

  srslte::byte_buffer_pool* pool = srslte::byte_buffer_pool::get_instance();
  bool                      msg_valid;

  uint64_t imsi = s1ap->find_imsi_from_m_tmsi(m_tmsi);

  if (imsi == 0 && args.enable_ue_state_fuzzing == true) {
    imsi = args.ue_under_test_imsi;
  }

  if (imsi == 0) {
    nas_log->console("Could not find IMSI from M-TMSI. M-TMSI 0x%x\n", m_tmsi);
    nas_log->error("Could not find IMSI from M-TMSI. M-TMSI 0x%x\n", m_tmsi);
    
    if (s1ap->get_mme_statelearner_reset_state() == false && args.enable_ue_state_fuzzing == true) {
      nas_log->console("Response: tau_request\n");
      uint8_t response[13] = "tau_request\n";
      uint8_t size         = 13;
      s1ap->notify_response(response, size);
    }
    return true;
  }

  nas_ctx = s1ap->find_nas_ctx_from_imsi(imsi);

  if (nas_ctx == NULL) {
    // Create new NAS context.
    nas_log->console("# TAU_REQUEST HANDLER: NAS CTX is not NULL #\n");
    nas_ctx = new nas(args, itf, nas_log);

    // Could not find IMSI from M-TMSI, send Id request
    // The IMSI will be set when the identity response is received
    // Set EMM ctx
    nas_ctx->m_emm_ctx.imsi = 0;
    if (args.enable_ue_state_fuzzing == true)
      nas_ctx->m_emm_ctx.imsi = args.ue_under_test_imsi; 

    nas_ctx->m_emm_ctx.state = EMM_STATE_DEREGISTERED;

    // Initialize NAS count
    nas_ctx->m_sec_ctx.ul_nas_count = 0;
    nas_ctx->m_sec_ctx.dl_nas_count = 0;


    // Set ECM context
    nas_ctx->m_ecm_ctx.enb_ue_s1ap_id = enb_ue_s1ap_id;
    nas_ctx->m_ecm_ctx.mme_ue_s1ap_id = s1ap->get_next_mme_ue_s1ap_id();


    // Add eNB info to UE ctxt
    memcpy(&nas_ctx->m_ecm_ctx.enb_sri, enb_sri, sizeof(struct sctp_sndrcvinfo));

    // Initialize E-RABs
    for (uint i = 0; i < MAX_ERABS_PER_UE; i++) {
      nas_ctx->m_esm_ctx[i].state   = ERAB_DEACTIVATED;
      nas_ctx->m_esm_ctx[i].erab_id = i;
    }

    if (args.enable_ue_state_fuzzing == true) 
      s1ap->add_nas_ctx_to_imsi_map(nas_ctx); 

    // Store temporary ue context
    s1ap->add_nas_ctx_to_mme_ue_s1ap_id_map(nas_ctx);
    s1ap->add_ue_to_enb_set(enb_sri->sinfo_assoc_id, nas_ctx->m_ecm_ctx.mme_ue_s1ap_id);

  } else {
    nas_log->console("# TAU_REQUEST HANDLER: NAS CTX is not NULL #\n");
    emm_ctx_t* emm_ctx = &nas_ctx->m_emm_ctx;
    ecm_ctx_t* ecm_ctx = &nas_ctx->m_ecm_ctx;
    sec_ctx_t* sec_ctx = &nas_ctx->m_sec_ctx;

    msg_valid = nas_ctx->integrity_check(nas_rx);

    if (emm_ctx->state == EMM_STATE_DEREGISTERED) { 
      nas_log->console("# TAU_REQUEST HANDLER: NAS CTX is not NULL and STATE = DEREGISTERED #\n");
      nas_log->console(
          "TAU REQUEST -- NAS Integrity OK. UL count %d, DL count %d\n", sec_ctx->ul_nas_count, sec_ctx->dl_nas_count);
      nas_log->info(
          "TAU REQUEST -- NAS Integrity OK. UL count %d, DL count %d\n", sec_ctx->ul_nas_count, sec_ctx->dl_nas_count);

      // Create new MME UE S1AP Identity
      ecm_ctx->mme_ue_s1ap_id = s1ap->get_next_mme_ue_s1ap_id();
      ecm_ctx->enb_ue_s1ap_id = enb_ue_s1ap_id;


      // Save Attach type
      emm_ctx->eps_update_type = tau_req.eps_update_type;

      // Set eNB information
      ecm_ctx->enb_ue_s1ap_id = enb_ue_s1ap_id;
      memcpy(&ecm_ctx->enb_sri, enb_sri, sizeof(struct sctp_sndrcvinfo));


      // Initialize E-RABs
      for (uint i = 0; i < MAX_ERABS_PER_UE; i++) {
        nas_ctx->m_esm_ctx[i].state   = ERAB_DEACTIVATED;
        nas_ctx->m_esm_ctx[i].erab_id = i;
      }

      // Store context based on MME UE S1AP id
      s1ap->add_nas_ctx_to_mme_ue_s1ap_id_map(nas_ctx);
      s1ap->add_ue_to_enb_set(enb_sri->sinfo_assoc_id, ecm_ctx->mme_ue_s1ap_id);

      // Re-generate K_eNB
      srslte::security_generate_k_enb(sec_ctx->k_asme, sec_ctx->ul_nas_count, sec_ctx->k_enb);
      nas_log->info("Generating KeNB with UL NAS COUNT: %d\n", sec_ctx->ul_nas_count);
      nas_log->console("Generating KeNB with UL NAS COUNT: %d\n", sec_ctx->ul_nas_count);
      nas_log->info_hex(sec_ctx->k_enb, 32, "Key eNodeB (k_enb)\n");

      sec_ctx->ul_nas_count++;
      return true;
    } else { // if UE is not deregistered/already registered
      nas_log->console("NOT EMM_STATE_DEREGISTERED\n");
      if (emm_ctx->state != EMM_STATE_DEREGISTERED) {
        nas_log->error("Received TAU Request from attached user.\n");
        nas_log->console("Received TAU Request from attached user.\n");

        // Delete previous Ctx, restart authentication
        // Detaching previoulsy attached UE.
        gtpc->send_delete_session_request(emm_ctx->imsi);

        if (ecm_ctx->mme_ue_s1ap_id != 0) {
          s1ap->send_ue_context_release_command(ecm_ctx->mme_ue_s1ap_id);
        }
      }

      if (args.enable_ue_state_fuzzing == false) {
        // Make sure context from previous NAS connections is not present
        if (ecm_ctx->mme_ue_s1ap_id != 0) {
          s1ap->release_ue_ecm_ctx(ecm_ctx->mme_ue_s1ap_id);
        }
      }
      ecm_ctx->mme_ue_s1ap_id =
          s1ap->get_next_mme_ue_s1ap_id(); 

      // Set EMM as de-registered
      emm_ctx->state = EMM_STATE_DEREGISTERED;

      // Save Attach type
      emm_ctx->eps_update_type = tau_req.eps_update_type;

      // Set eNB information
      ecm_ctx->enb_ue_s1ap_id = enb_ue_s1ap_id;
      memcpy(&ecm_ctx->enb_sri, enb_sri, sizeof(struct sctp_sndrcvinfo));

      // Initialize E-RABs
      for (uint i = 0; i < MAX_ERABS_PER_UE; i++) {
        nas_ctx->m_esm_ctx[i].state   = ERAB_DEACTIVATED;
        nas_ctx->m_esm_ctx[i].erab_id = i;
      }

      // Store context based on MME UE S1AP id
      s1ap->add_nas_ctx_to_mme_ue_s1ap_id_map(nas_ctx);
      s1ap->add_ue_to_enb_set(enb_sri->sinfo_assoc_id, ecm_ctx->mme_ue_s1ap_id);

      // Re-generate K_eNB
      srslte::security_generate_k_enb(sec_ctx->k_asme, sec_ctx->ul_nas_count, sec_ctx->k_enb);
      nas_log->info("Generating KeNB with UL NAS COUNT: %d\n", sec_ctx->ul_nas_count);
      nas_log->console("Generating KeNB with UL NAS COUNT: %d\n", sec_ctx->ul_nas_count);
      nas_log->info_hex(sec_ctx->k_enb, 32, "Key eNodeB (k_enb)\n");

      sec_ctx->ul_nas_count++;
      // return true;
    }
  }
  
  if (s1ap->get_mme_statelearner_reset_state() == false && args.enable_ue_state_fuzzing == true) {
    nas_log->console("Response: tau_request\n");
    uint8_t response[13] = "tau_request\n";
    uint8_t size         = 13;
    s1ap->notify_response(response, size);
  } else {
    // m_s1ap_log->console("MME_STATE = IN RESET\n");
  }
  
  return true;
}

/***************************************
 *
 * Handle Uplink NAS Transport messages
 *
 ***************************************/
bool nas::handle_attach_request(srslte::byte_buffer_t* nas_rx)
{
  uint32_t                                       m_tmsi      = 0;
  uint64_t                                       imsi        = 0;
  LIBLTE_MME_ATTACH_REQUEST_MSG_STRUCT           attach_req  = {};
  LIBLTE_MME_PDN_CONNECTIVITY_REQUEST_MSG_STRUCT pdn_con_req = {};

  m_nas_log->console("Attach_request in NAS_UPLINK_TRANSPORT\n");

  // Get NAS Attach Request and PDN connectivity request messages
  LIBLTE_ERROR_ENUM err = liblte_mme_unpack_attach_request_msg((LIBLTE_BYTE_MSG_STRUCT*)nas_rx, &attach_req);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error unpacking NAS attach request. Error: %s\n", liblte_error_text[err]);
    return false;
  }
  // Get PDN Connectivity Request*/
  err = liblte_mme_unpack_pdn_connectivity_request_msg(&attach_req.esm_msg, &pdn_con_req);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error unpacking NAS PDN Connectivity Request. Error: %s\n", liblte_error_text[err]);
    return false;
  }

  // Get UE IMSI
  if (attach_req.eps_mobile_id.type_of_id == LIBLTE_MME_EPS_MOBILE_ID_TYPE_IMSI) {
    for (int i = 0; i <= 14; i++) {
      imsi += attach_req.eps_mobile_id.imsi[i] * std::pow(10, 14 - i);
    }
    m_nas_log->console("Attach request -- IMSI: %015" PRIu64 "\n", imsi);
    m_nas_log->info("Attach request -- IMSI: %015" PRIu64 "\n", imsi);
  } else if (attach_req.eps_mobile_id.type_of_id == LIBLTE_MME_EPS_MOBILE_ID_TYPE_GUTI) {
    m_tmsi = attach_req.eps_mobile_id.guti.m_tmsi;
    imsi   = m_s1ap->find_imsi_from_m_tmsi(m_tmsi);
    m_nas_log->console("Attach request -- M-TMSI: 0x%x\n", m_tmsi);
    m_nas_log->info("Attach request -- M-TMSI: 0x%x\n", m_tmsi);
  } else {
    m_nas_log->error("Unhandled Mobile Id type in attach request\n");
    return false;
  }

  // Is UE known?
  if (m_emm_ctx.imsi == 0) {
    m_nas_log->info("Attach request from Unkonwn UE\n");
    // Get IMSI
    uint64_t imsi = 0;
    for (int i = 0; i <= 14; i++) {
      imsi += attach_req.eps_mobile_id.imsi[i] * std::pow(10, 14 - i);
    }

    // Save IMSI, eNB UE S1AP Id, MME UE S1AP Id and make sure UE is EMM_DEREGISTERED
    m_emm_ctx.imsi  = imsi;
    m_emm_ctx.state = EMM_STATE_DEREGISTERED;

    // Save UE network capabilities
    memcpy(&m_sec_ctx.ue_network_cap, &attach_req.ue_network_cap, sizeof(LIBLTE_MME_UE_NETWORK_CAPABILITY_STRUCT));
    m_sec_ctx.ms_network_cap_present = attach_req.ms_network_cap_present;
    if (attach_req.ms_network_cap_present) {
      memcpy(&m_sec_ctx.ms_network_cap, &attach_req.ms_network_cap, sizeof(LIBLTE_MME_MS_NETWORK_CAPABILITY_STRUCT));
    }

    uint8_t eps_bearer_id              = pdn_con_req.eps_bearer_id;
    m_emm_ctx.procedure_transaction_id = pdn_con_req.proc_transaction_id;

    // Initialize NAS count

    // Save whether secure ESM information transfer is necessary
    m_ecm_ctx.eit = pdn_con_req.esm_info_transfer_flag_present;

    // Initialize E-RABs
    for (uint i = 0; i < MAX_ERABS_PER_UE; i++) {
      m_esm_ctx[i].state   = ERAB_DEACTIVATED;
      m_esm_ctx[i].erab_id = i;
    }

    // Save attach request type
    m_emm_ctx.attach_type = attach_req.eps_attach_type;

    m_s1ap->add_nas_ctx_to_imsi_map(this);
    nas* nas_ctx = m_s1ap->find_nas_ctx_from_imsi(imsi);
    if (m_enable_ue_state_fuzzing == false) {
      // Get Authentication Vectors from HSS
      if (!m_hss->gen_auth_info_answer(
          m_emm_ctx.imsi, m_sec_ctx.k_asme, m_sec_ctx.autn, m_sec_ctx.rand, m_sec_ctx.xres)) {
        m_nas_log->console("User not found. IMSI %015" PRIu64 "\n", m_emm_ctx.imsi);
        m_nas_log->info("User not found. IMSI %015" PRIu64 "\n", m_emm_ctx.imsi);
        return false;
      }

      // Allocate eKSI for this authentication vector
      // Here we assume a new security context thus a new eKSI
      m_sec_ctx.eksi = 0;

      // Save the UE context
      m_s1ap->add_nas_ctx_to_imsi_map(this);

      // Pack NAS Authentication Request in Downlink NAS Transport msg
      srslte::byte_buffer_t* nas_tx = m_pool->allocate();
      pack_authentication_request(nas_tx);

      // Send reply to eNB
      m_s1ap->send_downlink_nas_transport(
          m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);
      m_pool->deallocate(nas_tx);

      m_nas_log->info("Downlink NAS: Sending Authentication Request\n");
      m_nas_log->console("Downlink NAS: Sending Authentication Request\n");
    }
    
    if (m_s1ap->get_mme_statelearner_reset_state() == false && m_enable_ue_state_fuzzing == true) {
      if (attach_req.eps_mobile_id.type_of_id == LIBLTE_MME_EPS_MOBILE_ID_TYPE_IMSI) {
        m_nas_log->console("Response: attach_request 1\n");
        uint8_t response[21] = "attach_request_guti\n";
        uint8_t size       = 21;
        key_set(&nas_ctx->m_sec_ctx.k_nas_enc[16]);
        m_s1ap->notify_response(response, size);
      } else {
        m_nas_log->console("Response: attach_request_guti\n");
        uint8_t response[21] = "attach_request_guti\n";
        key_set(&nas_ctx->m_sec_ctx.k_nas_enc[16]);
        uint8_t size = 21;
        m_s1ap->notify_response(response, size);
      }
    } 
    

    return true;
  } else {
    m_nas_log->error("Attach request from known UE\n");
  }
  return true;
}

bool nas::handle_tracking_area_update_request(srslte::byte_buffer_t* nas_rx)
{
  m_nas_log->console("Warning: Tracking Area Update Request messages not handled yet.\n");
  m_nas_log->warning("Warning: Tracking Area Update Request messages not handled yet.\n");

  uint32_t                          m_tmsi  = 0;
  uint64_t                          imsi    = 0;
  LIBLTE_MME_TAU_REQUEST_MSG_STRUCT tau_req = {};
  // LIBLTE_MME_PDN_CONNECTIVITY_REQUEST_MSG_STRUCT pdn_con_req = {};

  m_nas_log->console("TAU_request in NAS_UPLINK_TRANSPORT\n");

  // Get NAS Attach Request and PDN connectivity request messages
  LIBLTE_ERROR_ENUM err = liblte_mme_unpack_tracking_area_update_request_msg((LIBLTE_BYTE_MSG_STRUCT*)nas_rx, &tau_req);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error unpacking NAS attach request. Error: %s\n", liblte_error_text[err]);
    return false;
  }

  // Get UE IMSI
  if (tau_req.eps_mobile_id.type_of_id == LIBLTE_MME_EPS_MOBILE_ID_TYPE_IMSI) {
    for (int i = 0; i <= 14; i++) {
      imsi += tau_req.eps_mobile_id.imsi[i] * std::pow(10, 14 - i);
    }
    m_nas_log->console("TAU request -- IMSI: %015" PRIu64 "\n", imsi);
    m_nas_log->info("TAU request -- IMSI: %015" PRIu64 "\n", imsi);
  } else if (tau_req.eps_mobile_id.type_of_id == LIBLTE_MME_EPS_MOBILE_ID_TYPE_GUTI) {
    m_tmsi = tau_req.eps_mobile_id.guti.m_tmsi;
    imsi   = m_s1ap->find_imsi_from_m_tmsi(m_tmsi);

    if (imsi == 0 && m_enable_ue_state_fuzzing == true) {
      imsi = m_ue_under_test_imsi;
    }

    m_nas_log->console("TAU request -- M-TMSI: 0x%x\n", m_tmsi);
    m_nas_log->info("TAU request -- M-TMSI: 0x%x\n", m_tmsi);
  } else {
    m_nas_log->error("Unhandled Mobile Id type in attach request\n");
    return false;
  }

  if (imsi == 0) {
    m_nas_log->console("Could not find IMSI from M-TMSI. M-TMSI 0x%x\n", m_tmsi);
    m_nas_log->error("Could not find IMSI from M-TMSI. M-TMSI 0x%x\n", m_tmsi);
    
    if (m_s1ap->get_mme_statelearner_reset_state() == false && m_enable_ue_state_fuzzing == true) {
      m_nas_log->console("Response: tau_request\n");
      uint8_t response[13] = "tau_request\n";
      uint8_t size         = 13;
      m_s1ap->notify_response(response, size);
    } 
    return true;
  }

  m_nas_log->error("Received TAU Request from attached user.\n");
  m_nas_log->console("Received TAU Request from attached user.\n");

  // Delete previous Ctx, restart authentication
  // Detaching previoulsy attached UE.
  m_gtpc->send_delete_session_request(m_emm_ctx.imsi);

  if (m_ecm_ctx.mme_ue_s1ap_id != 0) {
    m_s1ap->send_ue_context_release_command(m_ecm_ctx.mme_ue_s1ap_id);
  }



  if (m_enable_ue_state_fuzzing == false) {
    // Make sure context from previous NAS connections is not present
    if (m_ecm_ctx.mme_ue_s1ap_id != 0) {
      m_s1ap->release_ue_ecm_ctx(m_ecm_ctx.mme_ue_s1ap_id);
    }
  }
  m_ecm_ctx.mme_ue_s1ap_id =
      m_s1ap->get_next_mme_ue_s1ap_id();

  // Set EMM as de-registered
  m_emm_ctx.state = EMM_STATE_DEREGISTERED;

  // Save Attach type
  m_emm_ctx.eps_update_type = tau_req.eps_update_type;

  // Initialize E-RABs
  for (uint i = 0; i < MAX_ERABS_PER_UE; i++) {
    m_esm_ctx[i].state   = ERAB_DEACTIVATED;
    m_esm_ctx[i].erab_id = i;
  }

  // Store context based on MME UE S1AP id
  m_s1ap->add_nas_ctx_to_mme_ue_s1ap_id_map(this);

  if (m_enable_ue_state_fuzzing == true) {
    // Re-generate K_eNB
    srslte::security_generate_k_enb(m_sec_ctx.k_asme, m_sec_ctx.ul_nas_count, m_sec_ctx.k_enb);
    m_nas_log->info("Generating KeNB with UL NAS COUNT: %d\n", m_sec_ctx.ul_nas_count);
    m_nas_log->console("Generating KeNB with UL NAS COUNT: %d\n", m_sec_ctx.ul_nas_count);
    m_nas_log->info_hex(m_sec_ctx.k_enb, 32, "Key eNodeB (k_enb)\n");
  }
  // return true;

  
  if (m_s1ap->get_mme_statelearner_reset_state() == false && m_enable_ue_state_fuzzing == true) {
    m_nas_log->console("Response: tau_request\n");
    uint8_t response[13] = "tau_request\n";
    uint8_t size         = 13;
    m_s1ap->notify_response(response, size);
  } 

  return true;
}

bool nas::handle_authentication_response(srslte::byte_buffer_t* nas_rx, bool flag)
{
  srslte::byte_buffer_t*                        nas_tx;
  LIBLTE_MME_AUTHENTICATION_RESPONSE_MSG_STRUCT auth_resp;
  bool                                          ue_valid = true;

  // Get NAS authentication response
  LIBLTE_ERROR_ENUM err = liblte_mme_unpack_authentication_response_msg((LIBLTE_BYTE_MSG_STRUCT*)nas_rx, &auth_resp);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error unpacking NAS authentication response. Error: %s\n", liblte_error_text[err]);
    return false;
  }

  // Log received authentication response
  m_nas_log->console("Authentication Response -- IMSI %015" PRIu64 "\n", m_emm_ctx.imsi);
  m_nas_log->info("Authentication Response -- IMSI %015" PRIu64 "\n", m_emm_ctx.imsi);
  m_nas_log->info_hex(auth_resp.res, 8, "Authentication response -- RES");
  m_nas_log->info_hex(m_sec_ctx.xres, 8, "Authentication response -- XRES");


  for (int i = 0; i < 32; i++) {
    m_sec_ctx.k_asme[i] = m_sec_ctx.k_asme_tmp[i];
  }

  ue_valid = true;


  if (m_enable_ue_state_fuzzing == false) {
    nas_tx = m_pool->allocate(); 
  }

  if (!ue_valid) {
    // Authentication rejected
    m_nas_log->console("UE Authentication Rejected.\n");
    m_nas_log->warning("UE Authentication Rejected.\n");

    if (m_enable_ue_state_fuzzing == false) {
      // Send back Athentication Reject
      pack_authentication_reject(nas_tx);
      m_nas_log->info("Downlink NAS: Sending Authentication Reject.\n");
    }
    if (m_s1ap->get_mme_statelearner_reset_state() == false && m_enable_ue_state_fuzzing == true) {
      m_nas_log->console("Response: auth_response_rejected\n");
      uint8_t response[24] = "auth_response_rejected\n";
      uint8_t size         = 24;
      m_s1ap->notify_response(response, size);
    } 

  } else {
    // Authentication accepted
    m_nas_log->console("UE Authentication Accepted.\n");
    m_nas_log->info("UE Authentication Accepted.\n");

    m_sec_ctx.dl_nas_count = 0; // statelearner

    if (m_enable_ue_state_fuzzing == false) {
      // Send Security Mode Command
      m_sec_ctx.ul_nas_count = 0;         // Reset the NAS uplink counter for the right key k_enb derivation
      pack_security_mode_command(nas_tx); 
      m_nas_log->console("Downlink NAS: Sending NAS Security Mode Command.\n");
    }
    if (m_s1ap->get_mme_statelearner_reset_state() == false && m_enable_ue_state_fuzzing == true) {
      if (flag == true) {

        m_nas_log->console("Response: auth_response\n");
        uint8_t response[16] = "auth_response\n";
        uint8_t size         = 16;
        m_s1ap->notify_response(response, size);
      } else {
        m_sec_ctx.ul_nas_count = 0;
        m_nas_log->console("Response: auth_response\n");
        uint8_t response[16] = "auth_response\n";
        uint8_t size         = 16;
        m_s1ap->notify_response(response, size);
      }

    } 
  }

  if (m_enable_ue_state_fuzzing == false) {
    // Send reply
    m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);
    m_pool->deallocate(nas_tx); 
  }
  return true;
}

bool nas::handle_security_mode_complete(srslte::byte_buffer_t* nas_rx)
{
  srslte::byte_buffer_t*                       nas_tx;
  LIBLTE_MME_SECURITY_MODE_COMPLETE_MSG_STRUCT sm_comp;

  // Get NAS security mode complete
  LIBLTE_ERROR_ENUM err = liblte_mme_unpack_security_mode_complete_msg((LIBLTE_BYTE_MSG_STRUCT*)nas_rx, &sm_comp);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error unpacking NAS authentication response. Error: %s\n", liblte_error_text[err]);
    return false;
  }

  // Log security mode complete
  m_nas_log->info("Security Mode Command Complete -- IMSI: %015" PRIu64 "\n", m_emm_ctx.imsi);
  m_nas_log->console("Security Mode Command Complete -- IMSI: %015" PRIu64 "\n", m_emm_ctx.imsi);

  if (m_enable_ue_state_fuzzing == false) {
    // Check wether secure ESM information transfer is required
    nas_tx = m_pool->allocate();
    if (m_ecm_ctx.eit == true) {
      // Secure ESM information transfer is required
      m_nas_log->console("Sending ESM information request\n");
      m_nas_log->info("Sending ESM information request\n");

      // Packing ESM information request
      pack_esm_information_request(nas_tx);
      m_s1ap->send_downlink_nas_transport(
          m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);
    } else {
      // Secure ESM information transfer not necessary
      // Sending create session request to SP-GW.
      uint8_t default_bearer = 5;
      m_hss->gen_update_loc_answer(m_emm_ctx.imsi, &m_esm_ctx[default_bearer].qci);
      m_nas_log->debug("Getting subscription information -- QCI %d\n", m_esm_ctx[default_bearer].qci);
      m_nas_log->console("Getting subscription information -- QCI %d\n", m_esm_ctx[default_bearer].qci);
      m_gtpc->send_create_session_request(m_emm_ctx.imsi);
    }
    m_pool->deallocate(nas_tx);
  }
  if (m_enable_ue_state_fuzzing == true) {
    uint8_t key_enb[32];
    srslte::security_generate_k_enb(m_sec_ctx.k_asme, m_sec_ctx.ul_nas_count, m_sec_ctx.k_enb);
    m_nas_log->info("Generating KeNB with UL NAS COUNT: %d\n", m_sec_ctx.ul_nas_count);
    m_nas_log->console("Generating KeNB with UL NAS COUNT: %d\n", m_sec_ctx.ul_nas_count);
    m_nas_log->info_hex(m_sec_ctx.k_enb, 32, "Key eNodeB (k_enb)\n");
  }
  if (m_s1ap->get_mme_statelearner_reset_state() == false && m_enable_ue_state_fuzzing == true) {
    m_nas_log->console("Response: security_mode_complete\n");
    uint8_t response[24] = "security_mode_complete\n";
    uint8_t size         = 24;
    m_s1ap->notify_response(response, size);
  } else {
  }
  return true;
}

bool nas::handle_security_mode_reject(srslte::byte_buffer_t* nas_rx)
{

  srslte::byte_buffer_t*                     nas_tx;
  LIBLTE_MME_SECURITY_MODE_REJECT_MSG_STRUCT sm_reject;

  // Get NAS security mode reject
  LIBLTE_ERROR_ENUM err = liblte_mme_unpack_security_mode_reject_msg((LIBLTE_BYTE_MSG_STRUCT*)nas_rx, &sm_reject);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error unpacking NAS security mode reject. Error: %s\n", liblte_error_text[err]);
    return false;
  }
  m_nas_log->info("Security Mode Command Reject -- IMSI: %lu\n", m_ue_under_test_imsi);
  m_nas_log->console("Security Mode Command Reject -- IMSI: %lu\n", m_ue_under_test_imsi);

  if (m_s1ap->get_mme_statelearner_reset_state() == false && m_enable_ue_state_fuzzing == true) {

    m_nas_log->console("Response: security_mode_reject\n");
    uint8_t response[22] = "security_mode_reject\n";
    uint8_t size         = 22;
    m_s1ap->notify_response(response, size);
  }

  return true;
}


bool nas::handle_attach_complete(srslte::byte_buffer_t* nas_rx)
{
  LIBLTE_MME_ATTACH_COMPLETE_MSG_STRUCT                            attach_comp;
  uint8_t                                                          pd, msg_type;
  LIBLTE_MME_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_ACCEPT_MSG_STRUCT act_bearer;
  srslte::byte_buffer_t*                                           nas_tx;

  // Get NAS authentication response
  LIBLTE_ERROR_ENUM err = liblte_mme_unpack_attach_complete_msg((LIBLTE_BYTE_MSG_STRUCT*)nas_rx, &attach_comp);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error unpacking NAS ATTACH COMPLETE. Error: %s\n", liblte_error_text[err]);
    return false;
  }

  err = liblte_mme_unpack_activate_default_eps_bearer_context_accept_msg((LIBLTE_BYTE_MSG_STRUCT*)&attach_comp.esm_msg,
                                                                         &act_bearer);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error unpacking Activate EPS Bearer Context Accept Msg. Error: %s\n", liblte_error_text[err]);
    return false;
  }

  m_nas_log->console("Unpacked Attached Complete Message. IMSI %" PRIu64 "\n", m_emm_ctx.imsi);
  m_nas_log->console("Unpacked Activate Default EPS Bearer message. EPS Bearer id %d\n", act_bearer.eps_bearer_id);

  if (act_bearer.eps_bearer_id < 5 || act_bearer.eps_bearer_id > 15) {
    m_nas_log->error("EPS Bearer ID out of range\n");
    return false;
  }
  if (m_emm_ctx.state == EMM_STATE_DEREGISTERED) {
    // Attach requested from attach request
    m_gtpc->send_modify_bearer_request(
        m_emm_ctx.imsi, act_bearer.eps_bearer_id, &m_esm_ctx[act_bearer.eps_bearer_id].enb_fteid);

    if (m_enable_ue_state_fuzzing == false) {
      // Send reply to EMM Info to UE
      nas_tx = m_pool->allocate();
      pack_emm_information(nas_tx);

      m_s1ap->send_downlink_nas_transport(
          m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);
      m_pool->deallocate(nas_tx);

      m_nas_log->console("Sending EMM Information\n");
      m_nas_log->info("Sending EMM Information\n");
    }
  }

  m_emm_ctx.state = EMM_STATE_REGISTERED;

  
  if (m_s1ap->get_mme_statelearner_reset_state() == false && m_enable_ue_state_fuzzing == true) {
    m_nas_log->console("Response: attach_complete\n");
    uint8_t response[17] = "attach_complete\n";
    uint8_t size         = 17;
    m_s1ap->notify_response(response, size);
  }
  
  return true;
}

bool nas::handle_tracking_area_update_complete(srslte::byte_buffer_t* nas_rx)
{
  LIBLTE_MME_TRACKING_AREA_UPDATE_COMPLETE_MSG_STRUCT              tau_comp;
  uint8_t                                                          pd, msg_type;
  LIBLTE_MME_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_ACCEPT_MSG_STRUCT act_bearer;
  srslte::byte_buffer_t*                                           nas_tx;

  LIBLTE_ERROR_ENUM err =
      liblte_mme_unpack_tracking_area_update_complete_msg((LIBLTE_BYTE_MSG_STRUCT*)nas_rx, &tau_comp);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error unpacking NAS TAU COMPLETES. Error: %s\n", liblte_error_text[err]);
    return false;
  }


  if (m_emm_ctx.state == EMM_STATE_DEREGISTERED) {
    // Attach requested from attach request
    m_gtpc->send_modify_bearer_request(
        m_emm_ctx.imsi, act_bearer.eps_bearer_id, &m_esm_ctx[act_bearer.eps_bearer_id].enb_fteid);

    if (m_enable_ue_state_fuzzing == false) {
      // Send reply to EMM Info to UE
      nas_tx = m_pool->allocate();
      pack_emm_information(nas_tx);

      m_s1ap->send_downlink_nas_transport(
          m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);
      m_pool->deallocate(nas_tx);

      m_nas_log->console("Sending EMM Information\n");
      m_nas_log->info("Sending EMM Information\n");
    }
  }

  m_emm_ctx.state = EMM_STATE_REGISTERED;

  
  if (m_s1ap->get_mme_statelearner_reset_state() == false && m_enable_ue_state_fuzzing == true) {
    m_nas_log->console("Response: tau_complete\n");
    uint8_t response[14] = "tau_complete\n";
    uint8_t size         = 14;
    m_s1ap->notify_response(response, size);
  }
  
  return true;
}

bool nas::handle_esm_information_response(srslte::byte_buffer_t* nas_rx)
{
  LIBLTE_MME_ESM_INFORMATION_RESPONSE_MSG_STRUCT esm_info_resp;

  // Get NAS authentication response
  LIBLTE_ERROR_ENUM err =
      srslte_mme_unpack_esm_information_response_msg((LIBLTE_BYTE_MSG_STRUCT*)nas_rx, &esm_info_resp);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error unpacking NAS authentication response. Error: %s\n", liblte_error_text[err]);
    return false;
  }

  m_nas_log->info("ESM Info: EPS bearer id %d\n", esm_info_resp.eps_bearer_id);
  if (esm_info_resp.apn_present) {
    m_nas_log->info("ESM Info: APN %s\n", esm_info_resp.apn.apn);
    m_nas_log->console("ESM Info: APN %s\n", esm_info_resp.apn.apn);
  }
  if (esm_info_resp.protocol_cnfg_opts_present) {
    m_nas_log->info("ESM Info: %d Protocol Configuration Options\n", esm_info_resp.protocol_cnfg_opts.N_opts);
    m_nas_log->console("ESM Info: %d Protocol Configuration Options\n", esm_info_resp.protocol_cnfg_opts.N_opts);
  }

  if (m_enable_ue_state_fuzzing == false) {
    // Get subscriber info from HSS
    uint8_t default_bearer = 5;
    m_hss->gen_update_loc_answer(m_emm_ctx.imsi, &m_esm_ctx[default_bearer].qci);
    m_nas_log->debug("Getting subscription information -- QCI %d\n", m_esm_ctx[default_bearer].qci);
    m_nas_log->console("Getting subscription information -- QCI %d\n", m_esm_ctx[default_bearer].qci);

    // This means that GTP-U tunnels are created with function calls, as opposed to GTP-C.
    m_gtpc->send_create_session_request(m_emm_ctx.imsi);
  }
  
  if (m_s1ap->get_mme_statelearner_reset_state() == false && m_enable_ue_state_fuzzing == true) {
    m_nas_log->console("Response: esm_info_response\n");
    uint8_t response[19] = "esm_info_response\n";
    uint8_t size         = 19;
    m_s1ap->notify_response(response, size);
  }
  
  return true;
}

bool nas::handle_identity_response(srslte::byte_buffer_t* nas_rx, bool flag)
{
  srslte::byte_buffer_t*            nas_tx;
  LIBLTE_MME_ID_RESPONSE_MSG_STRUCT id_resp;

  LIBLTE_ERROR_ENUM err = liblte_mme_unpack_identity_response_msg((LIBLTE_BYTE_MSG_STRUCT*)nas_rx, &id_resp);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error unpacking NAS identity response. Error: %s\n", liblte_error_text[err]);
    return false;
  }

  uint64_t imsi = 0;
  for (int i = 0; i <= 14; i++) {
    imsi += id_resp.mobile_id.imsi[i] * std::pow(10, 14 - i);
  }

  m_nas_log->info("ID response -- IMSI: %015" PRIu64 "\n", imsi);
  m_nas_log->console("ID Response -- IMSI: %015" PRIu64 "\n", imsi);

  // Set UE's IMSI
  m_emm_ctx.imsi = imsi;

  if (m_enable_ue_state_fuzzing == false) {
    // Get Authentication Vectors from HSS
    if (!m_hss->gen_auth_info_answer(imsi, m_sec_ctx.k_asme, m_sec_ctx.autn, m_sec_ctx.rand, m_sec_ctx.xres)) {
      m_nas_log->console("User not found. IMSI %015" PRIu64 "\n", imsi);
      m_nas_log->info("User not found. IMSI %015" PRIu64 "\n", imsi);
      return false;
    }
    // Identity reponse from unknown GUTI atach. Assigning new eKSI.
    m_sec_ctx.eksi = 0;

    // Make sure UE context was not previously stored in IMSI map
    nas* nas_ctx = m_s1ap->find_nas_ctx_from_imsi(imsi);
    if (nas_ctx != nullptr) {
      m_nas_log->warning("UE context already exists.\n");
      m_s1ap->delete_ue_ctx(imsi);
    }

    // Store UE context im IMSI map
    m_s1ap->add_nas_ctx_to_imsi_map(this);

    // Pack NAS Authentication Request in Downlink NAS Transport msg
    nas_tx = m_pool->allocate();
    pack_authentication_request(nas_tx);

    // Send reply to eNB
    m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);
    m_pool->deallocate(nas_tx);

    m_nas_log->info("Downlink NAS: Sent Authentication Request\n");
    m_nas_log->console("Downlink NAS: Sent Authentication Request\n");
  }
  
  if (m_s1ap->get_mme_statelearner_reset_state() == false && m_enable_ue_state_fuzzing == true) {
    if (flag == true) {
      m_nas_log->console("Response: identity_response\n");
      uint8_t response[19] = "identity_response\n";
      uint8_t size         = 19;
      m_s1ap->notify_response(response, size);
    } else {
      m_nas_log->console("Response: identity_response\n");
      uint8_t response[19] = "identity_response\n";
      uint8_t size         = 19;
      m_s1ap->notify_response(response, size);
    }
  }
  
  return true;
}

bool nas::handle_uplink_nas_transport(srslte::byte_buffer_t* nas_rx)
{
  m_nas_log->console("Received uplink nas transport\n");
  LIBLTE_MME_UPLINK_NAS_TRANSPORT_MSG_STRUCT ul_nas_transport;
  LIBLTE_ERROR_ENUM                          err =
      liblte_mme_unpack_uplink_nas_transport_msg((LIBLTE_BYTE_MSG_STRUCT*)nas_rx, &ul_nas_transport);
  
  if (m_s1ap->get_mme_statelearner_reset_state() == false && m_enable_ue_state_fuzzing == true) {
    m_nas_log->console("Response: ul_nas_transport\n");
    uint8_t response[18] = "ul_nas_transport\n";
    uint8_t size         = 18;
    m_s1ap->notify_response(response, size);
  }
  

  return true;
}

bool nas::handle_authentication_failure(srslte::byte_buffer_t* nas_rx)
{
  m_nas_log->info("Received Authentication Failure\n");

  srslte::byte_buffer_t*                       nas_tx;
  LIBLTE_MME_AUTHENTICATION_FAILURE_MSG_STRUCT auth_fail;
  LIBLTE_ERROR_ENUM                            err;

  err = liblte_mme_unpack_authentication_failure_msg((LIBLTE_BYTE_MSG_STRUCT*)nas_rx, &auth_fail);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error unpacking NAS authentication failure. Error: %s\n", liblte_error_text[err]);
    return false;
  }

  
  uint8_t response_mac_failure[18]    = "auth_failure_mac\n";
  uint8_t response_seq_failure[18]    = "auth_failure_seq\n";
  uint8_t response_noneps_failure[21] = "auth_failure_noneps\n";
  uint8_t size_mac_failure            = 18;
  uint8_t size_seq_failure            = 18;
  uint8_t size_noneps_failure         = 21;
  

  switch (auth_fail.emm_cause) {
    case 20:
      m_nas_log->console("MAC code failure\n");
      m_nas_log->info("MAC code failure\n");
      m_s1ap->notify_response(response_mac_failure, size_mac_failure); 
      break;
    case 26:
      m_nas_log->console("Non-EPS authentication unacceptable\n");
      m_nas_log->info("Non-EPS authentication unacceptable\n");
      m_s1ap->notify_response(response_noneps_failure, size_noneps_failure); 
      break;
    case 21:
      m_nas_log->console("Authentication Failure -- Synchronization Failure\n");
      m_nas_log->info("Authentication Failure -- Synchronization Failure\n");
      if (auth_fail.auth_fail_param_present == false) {
        m_nas_log->error("Missing fail parameter\n");
        return false;
      }
      if (!m_hss->resync_sqn(m_emm_ctx.imsi, auth_fail.auth_fail_param)) {
        m_nas_log->console("Resynchronization failed. IMSI %015" PRIu64 "\n", m_emm_ctx.imsi);
        m_nas_log->info("Resynchronization failed. IMSI %015" PRIu64 "\n", m_emm_ctx.imsi);
        return false;
      }
      m_s1ap->notify_response(response_seq_failure, size_seq_failure); 

      if (m_enable_ue_state_fuzzing == false) {
        // Get Authentication Vectors from HSS
        if (!m_hss->gen_auth_info_answer(
            m_emm_ctx.imsi, m_sec_ctx.k_asme, m_sec_ctx.autn, m_sec_ctx.rand, m_sec_ctx.xres)) {
          m_nas_log->console("User not found. IMSI %015" PRIu64 "\n", m_emm_ctx.imsi);
          m_nas_log->info("User not found. IMSI %015" PRIu64 "\n", m_emm_ctx.imsi);
          return false;
        }

        // Making sure eKSI is different from previous eKSI.
        m_sec_ctx.eksi = (m_sec_ctx.eksi + 1) % 6;

        // Pack NAS Authentication Request in Downlink NAS Transport msg
        nas_tx = m_pool->allocate();
        pack_authentication_request(nas_tx);

        // Send reply to eNB
        m_s1ap->send_downlink_nas_transport(
            m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);
        m_pool->deallocate(nas_tx);

        m_nas_log->info("Downlink NAS: Sent Authentication Request\n");
        m_nas_log->console("Downlink NAS: Sent Authentication Request\n");
      }
      break;
  }
  return true;
}

bool nas::handle_detach_request(srslte::byte_buffer_t* nas_msg)
{


  m_nas_log->console("Detach request -- IMSI %015" PRIu64 "\n", m_emm_ctx.imsi);
  m_nas_log->info("Detach request -- IMSI %015" PRIu64 "\n", m_emm_ctx.imsi);
  LIBLTE_MME_DETACH_REQUEST_MSG_STRUCT detach_req;

  LIBLTE_ERROR_ENUM err = liblte_mme_unpack_detach_request_msg((LIBLTE_BYTE_MSG_STRUCT*)nas_msg, &detach_req);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Could not unpack detach request\n");
    return false;
  }

  m_gtpc->send_delete_session_request(m_emm_ctx.imsi); 
  m_emm_ctx.state = EMM_STATE_DEREGISTERED;
  if (m_ecm_ctx.mme_ue_s1ap_id != 0) {
    m_s1ap->send_ue_context_release_command(m_ecm_ctx.mme_ue_s1ap_id);
  }

  return true;

}


bool nas::handle_nas_emm_status(srslte::byte_buffer_t* nas_msg)
{
  LIBLTE_MME_EMM_STATUS_MSG_STRUCT emm_status;

  // Get NAS authentication response
  LIBLTE_ERROR_ENUM err = liblte_mme_unpack_emm_status_msg((LIBLTE_BYTE_MSG_STRUCT*)nas_msg, &emm_status);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error unpacking NAS emm status. Error: %s\n", liblte_error_text[err]);
    return false;
  }

  m_nas_log->info("EMM Status -- IMSI: %lu\n", m_ue_under_test_imsi);

  if (m_s1ap->get_mme_statelearner_reset_state() == false && m_enable_ue_state_fuzzing == true) {
    m_nas_log->console("Response: emm_status\n");
    uint8_t response[12] = "emm_status\n";
    uint8_t size         = 12;
    m_s1ap->notify_response(response, size);
  }

  return true;
}

bool nas::handle_guti_reallocation_complete(srslte::byte_buffer_t* nas_msg)
{
  LIBLTE_MME_GUTI_REALLOCATION_COMPLETE_MSG_STRUCT guti_reallocation_complete;

  // Get NAS authentication response
  LIBLTE_ERROR_ENUM err =
      liblte_mme_unpack_guti_reallocation_complete_msg((LIBLTE_BYTE_MSG_STRUCT*)nas_msg, &guti_reallocation_complete);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error unpacking NAS emm status. Error: %s\n", liblte_error_text[err]);
    return false;
  }

  m_nas_log->info("EMM Status -- IMSI: %lu\n", m_ue_under_test_imsi);

  if (m_s1ap->get_mme_statelearner_reset_state() == false && m_enable_ue_state_fuzzing == true) {
    m_nas_log->console("Response: GUTI Reallocation Complete\n");
    uint8_t response[28] = "GUTI_reallocation_complete\n";
    uint8_t size         = 28;
    m_s1ap->notify_response(response, size);
  }

  return true;
}


/*Packing/Unpacking helper functions*/
bool nas::pack_authentication_request(srslte::byte_buffer_t* nas_buffer)
{
  m_nas_log->info("Packing Authentication Request\n");

  // Pack NAS msg
  LIBLTE_MME_AUTHENTICATION_REQUEST_MSG_STRUCT auth_req;
  memcpy(auth_req.autn, m_sec_ctx.autn, 16);
  memcpy(auth_req.rand, m_sec_ctx.rand, 16);
  auth_req.nas_ksi.tsc_flag = LIBLTE_MME_TYPE_OF_SECURITY_CONTEXT_FLAG_NATIVE;
  auth_req.nas_ksi.nas_ksi  = m_sec_ctx.eksi;

  LIBLTE_ERROR_ENUM err = liblte_mme_pack_authentication_request_msg(&auth_req, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error packing Authentication Request\n");
    m_nas_log->console("Error packing Authentication Request\n");
    return false;
  }
  return true;
}

bool nas::pack_authentication_request_mac(srslte::byte_buffer_t* nas_buffer)
{
  m_nas_log->info("Packing Authentication Request\n");

  // Pack NAS msg
  LIBLTE_MME_AUTHENTICATION_REQUEST_MSG_STRUCT auth_req;
  memcpy(auth_req.autn, m_sec_ctx.autn, 16);
  memcpy(auth_req.rand, m_sec_ctx.rand, 16);
  auth_req.nas_ksi.tsc_flag = LIBLTE_MME_TYPE_OF_SECURITY_CONTEXT_FLAG_NATIVE;
  auth_req.nas_ksi.nas_ksi  = m_sec_ctx.eksi;
  uint8_t sec_hdr_type      = 2;
  m_sec_ctx.dl_nas_count++;
  LIBLTE_ERROR_ENUM err = liblte_mme_pack_authentication_request_msg_mac(
      &auth_req, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer, m_sec_ctx.dl_nas_count, sec_hdr_type);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error packing Authentication Request\n");
    m_nas_log->console("Error packing Authentication Request\n");
    return false;
  }
  uint8_t mac[4];
  integrity_generate(nas_buffer, mac);
  memcpy(&nas_buffer->msg[1], mac, 4);
  return true;
}
bool nas::pack_authentication_request_replay(srslte::byte_buffer_t* nas_buffer)
{
  m_nas_log->info("Packing Authentication Request\n");

  // Pack NAS msg
  LIBLTE_MME_AUTHENTICATION_REQUEST_MSG_STRUCT auth_req;
  memcpy(auth_req.autn, m_sec_ctx.autn, 16);
  memcpy(auth_req.rand, m_sec_ctx.rand, 16);
  auth_req.nas_ksi.tsc_flag = LIBLTE_MME_TYPE_OF_SECURITY_CONTEXT_FLAG_NATIVE;
  auth_req.nas_ksi.nas_ksi  = m_sec_ctx.eksi;
  uint8_t sec_hdr_type      = 2;
  LIBLTE_ERROR_ENUM err = liblte_mme_pack_authentication_request_msg_mac(
      &auth_req, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer, m_sec_ctx.dl_nas_count, sec_hdr_type);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error packing Authentication Request\n");
    m_nas_log->console("Error packing Authentication Request\n");
    return false;
  }
  uint8_t mac[4];
  integrity_generate(nas_buffer, mac);
  memcpy(&nas_buffer->msg[1], mac, 4);
  return true;
}
bool nas::pack_authentication_request_encrypt_mac(srslte::byte_buffer_t* nas_buffer)
{
  m_nas_log->info("Packing Authentication Request\n");

  // Pack NAS msg
  LIBLTE_MME_AUTHENTICATION_REQUEST_MSG_STRUCT auth_req;
  memcpy(auth_req.autn, m_sec_ctx.autn, 16);
  memcpy(auth_req.rand, m_sec_ctx.rand, 16);
  auth_req.nas_ksi.tsc_flag = LIBLTE_MME_TYPE_OF_SECURITY_CONTEXT_FLAG_NATIVE;
  auth_req.nas_ksi.nas_ksi  = m_sec_ctx.eksi;
  uint8_t sec_hdr_type      = 2;
  m_sec_ctx.dl_nas_count++;
  LIBLTE_ERROR_ENUM err = liblte_mme_pack_authentication_request_msg_mac(
      &auth_req, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer, m_sec_ctx.dl_nas_count, sec_hdr_type);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error packing Authentication Request\n");
    m_nas_log->console("Error packing Authentication Request\n");
    return false;
  }
  cipher_encrypt(nas_buffer);
  uint8_t mac[4];
  integrity_generate(nas_buffer, mac);
  memcpy(&nas_buffer->msg[1], mac, 4);
  return true;
}
bool nas::pack_authentication_request_wmac(srslte::byte_buffer_t* nas_buffer)
{
  m_nas_log->info("Packing Authentication Request\n");

  // Pack NAS msg
  LIBLTE_MME_AUTHENTICATION_REQUEST_MSG_STRUCT auth_req;
  memcpy(auth_req.autn, m_sec_ctx.autn, 16);
  memcpy(auth_req.rand, m_sec_ctx.rand, 16);
  auth_req.nas_ksi.tsc_flag = LIBLTE_MME_TYPE_OF_SECURITY_CONTEXT_FLAG_NATIVE;
  auth_req.nas_ksi.nas_ksi  = m_sec_ctx.eksi;
  uint8_t sec_hdr_type      = 2;
  m_sec_ctx.dl_nas_count++;
  LIBLTE_ERROR_ENUM err = liblte_mme_pack_authentication_request_msg_mac(
      &auth_req, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer, m_sec_ctx.dl_nas_count, sec_hdr_type);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error packing Authentication Request\n");
    m_nas_log->console("Error packing Authentication Request\n");
    return false;
  }
  cipher_encrypt(nas_buffer);
  uint8_t mac[4];
  mac[0] = mac[0] + 1;
  integrity_generate(nas_buffer, mac);
  memcpy(&nas_buffer->msg[1], mac, 4);
  return true;
}

bool nas::pack_authentication_reject(srslte::byte_buffer_t* nas_buffer)
{
  m_nas_log->info("Packing Authentication Reject\n");

  LIBLTE_MME_AUTHENTICATION_REJECT_MSG_STRUCT auth_rej;
  LIBLTE_ERROR_ENUM err = liblte_mme_pack_authentication_reject_msg(&auth_rej, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error packing Authentication Reject\n");
    m_nas_log->console("Error packing Authentication Reject\n");
    return false;
  }
  return true;
}


bool nas::pack_attach_reject(srslte::byte_buffer_t* nas_buffer, uint8_t emm_cause)
{

  m_nas_log->info("Packing Attach Reject\n");

  LIBLTE_MME_ATTACH_REJECT_MSG_STRUCT attach_rej;
  attach_rej.emm_cause           = emm_cause;
  attach_rej.esm_msg_present     = false;
  attach_rej.t3446_value_present = false;

  LIBLTE_ERROR_ENUM err = liblte_mme_pack_attach_reject_msg(&attach_rej, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);

  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error packing Attach Reject\n");
    return false;
  }
  return true;
}
bool nas::pack_security_mode_command_no_integrity(srslte::byte_buffer_t* nas_buffer)
{
  m_nas_log->info("Packing Security Mode Command\n");

  // Pack NAS PDU
  LIBLTE_MME_SECURITY_MODE_COMMAND_MSG_STRUCT sm_cmd;
  sm_cmd.selected_nas_sec_algs.type_of_eea = (LIBLTE_MME_TYPE_OF_CIPHERING_ALGORITHM_ENUM)m_sec_ctx.cipher_algo;
  sm_cmd.selected_nas_sec_algs.type_of_eia = LIBLTE_MME_TYPE_OF_INTEGRITY_ALGORITHM_EIA0;

  sm_cmd.nas_ksi.tsc_flag = LIBLTE_MME_TYPE_OF_SECURITY_CONTEXT_FLAG_NATIVE;
  sm_cmd.nas_ksi.nas_ksi  = m_sec_ctx.eksi;

  // Replay UE security cap
  memcpy(sm_cmd.ue_security_cap.eea, m_sec_ctx.ue_network_cap.eea, 8 * sizeof(bool));
  memcpy(sm_cmd.ue_security_cap.eia, m_sec_ctx.ue_network_cap.eia, 8 * sizeof(bool));

  sm_cmd.ue_security_cap.uea_present = m_sec_ctx.ue_network_cap.uea_present;
  memcpy(sm_cmd.ue_security_cap.uea, m_sec_ctx.ue_network_cap.uea, 8 * sizeof(bool));

  sm_cmd.ue_security_cap.uia_present = m_sec_ctx.ue_network_cap.uia_present;
  memcpy(sm_cmd.ue_security_cap.uia, m_sec_ctx.ue_network_cap.uia, 8 * sizeof(bool));

  sm_cmd.ue_security_cap.gea_present = m_sec_ctx.ms_network_cap_present;
  memcpy(sm_cmd.ue_security_cap.gea, m_sec_ctx.ms_network_cap.gea, 8 * sizeof(bool));

  sm_cmd.imeisv_req_present = false;
  sm_cmd.nonce_ue_present   = false;
  sm_cmd.nonce_mme_present  = false;

  uint8_t           sec_hdr_type = 3;
  LIBLTE_ERROR_ENUM err          = liblte_mme_pack_security_mode_command_msg(
      &sm_cmd, sec_hdr_type, m_sec_ctx.dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->console("Error packing Authentication Request\n");
    return false;
  }

  // Generate EPS security context
  srslte::security_generate_k_nas(
      m_sec_ctx.k_asme, m_sec_ctx.cipher_algo, m_sec_ctx.integ_algo, m_sec_ctx.k_nas_enc, m_sec_ctx.k_nas_int);

  m_nas_log->info_hex(m_sec_ctx.k_nas_enc, 32, "Key NAS Encryption (k_nas_enc)\n");
  m_nas_log->info_hex(m_sec_ctx.k_nas_int, 32, "Key NAS Integrity (k_nas_int)\n");

  if (m_enable_ue_state_fuzzing == false) {
    uint8_t key_enb[32];
    srslte::security_generate_k_enb(m_sec_ctx.k_asme, m_sec_ctx.ul_nas_count, m_sec_ctx.k_enb);
    m_nas_log->info("Generating KeNB with UL NAS COUNT: %d\n", m_sec_ctx.ul_nas_count);
    m_nas_log->console("Generating KeNB with UL NAS COUNT: %d\n", m_sec_ctx.ul_nas_count);
    m_nas_log->info_hex(m_sec_ctx.k_enb, 32, "Key eNodeB (k_enb)\n");
  }

  // Generate MAC for integrity protection
  uint8_t mac[4];
  mac[0] = 0;
  mac[1] = 0;
  mac[2] = 0;
  mac[3] = 0;

  memcpy(&nas_buffer->msg[1], mac, 4);
  return true;
}
bool nas::pack_security_mode_command(srslte::byte_buffer_t* nas_buffer)
{
  m_nas_log->info("Packing Security Mode Command\n");

  // Pack NAS PDU
  LIBLTE_MME_SECURITY_MODE_COMMAND_MSG_STRUCT sm_cmd;
  sm_cmd.selected_nas_sec_algs.type_of_eea = (LIBLTE_MME_TYPE_OF_CIPHERING_ALGORITHM_ENUM)m_sec_ctx.cipher_algo;
  sm_cmd.selected_nas_sec_algs.type_of_eia = (LIBLTE_MME_TYPE_OF_INTEGRITY_ALGORITHM_ENUM)m_sec_ctx.integ_algo;

  sm_cmd.nas_ksi.tsc_flag = LIBLTE_MME_TYPE_OF_SECURITY_CONTEXT_FLAG_NATIVE;
  sm_cmd.nas_ksi.nas_ksi  = m_sec_ctx.eksi;

  // Replay UE security cap
  memcpy(sm_cmd.ue_security_cap.eea, m_sec_ctx.ue_network_cap.eea, 8 * sizeof(bool));
  memcpy(sm_cmd.ue_security_cap.eia, m_sec_ctx.ue_network_cap.eia, 8 * sizeof(bool));

  sm_cmd.ue_security_cap.uea_present = m_sec_ctx.ue_network_cap.uea_present;
  memcpy(sm_cmd.ue_security_cap.uea, m_sec_ctx.ue_network_cap.uea, 8 * sizeof(bool));

  sm_cmd.ue_security_cap.uia_present = m_sec_ctx.ue_network_cap.uia_present;
  memcpy(sm_cmd.ue_security_cap.uia, m_sec_ctx.ue_network_cap.uia, 8 * sizeof(bool));

  sm_cmd.ue_security_cap.gea_present = m_sec_ctx.ms_network_cap_present;
  memcpy(sm_cmd.ue_security_cap.gea, m_sec_ctx.ms_network_cap.gea, 8 * sizeof(bool));

  sm_cmd.imeisv_req_present = false;
  sm_cmd.nonce_ue_present   = false;
  sm_cmd.nonce_mme_present  = false;

  uint8_t           sec_hdr_type = 3;
  LIBLTE_ERROR_ENUM err          = liblte_mme_pack_security_mode_command_msg(
      &sm_cmd, sec_hdr_type, m_sec_ctx.dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->console("Error packing Authentication Request\n");
    return false;
  }

  // Generate EPS security context
  srslte::security_generate_k_nas(
      m_sec_ctx.k_asme, m_sec_ctx.cipher_algo, m_sec_ctx.integ_algo, m_sec_ctx.k_nas_enc, m_sec_ctx.k_nas_int);

  m_nas_log->info_hex(m_sec_ctx.k_nas_enc, 32, "Key NAS Encryption (k_nas_enc)\n");
  m_nas_log->info_hex(m_sec_ctx.k_nas_int, 32, "Key NAS Integrity (k_nas_int)\n");

  if (m_enable_ue_state_fuzzing == false) {
    uint8_t key_enb[32];
    srslte::security_generate_k_enb(m_sec_ctx.k_asme, m_sec_ctx.ul_nas_count, m_sec_ctx.k_enb);
    m_nas_log->info("Generating KeNB with UL NAS COUNT: %d\n", m_sec_ctx.ul_nas_count);
    m_nas_log->console("Generating KeNB with UL NAS COUNT: %d\n", m_sec_ctx.ul_nas_count);
    m_nas_log->info_hex(m_sec_ctx.k_enb, 32, "Key eNodeB (k_enb)\n");
  }

  // Generate MAC for integrity protection
  uint8_t mac[4];
  integrity_generate(nas_buffer, mac);

  memcpy(&nas_buffer->msg[1], mac, 4);
  return true;
}


bool nas::pack_security_mode_command_plain(srslte::byte_buffer_t* nas_buffer)
{
  m_nas_log->info("Packing Security Mode Command\n");

  // Pack NAS PDU
  LIBLTE_MME_SECURITY_MODE_COMMAND_MSG_STRUCT sm_cmd;
  sm_cmd.selected_nas_sec_algs.type_of_eea = (LIBLTE_MME_TYPE_OF_CIPHERING_ALGORITHM_ENUM)m_sec_ctx.cipher_algo;
  sm_cmd.selected_nas_sec_algs.type_of_eia = (LIBLTE_MME_TYPE_OF_INTEGRITY_ALGORITHM_ENUM)m_sec_ctx.integ_algo;

  sm_cmd.nas_ksi.tsc_flag = LIBLTE_MME_TYPE_OF_SECURITY_CONTEXT_FLAG_NATIVE;
  sm_cmd.nas_ksi.nas_ksi  = m_sec_ctx.eksi;

  // Replay UE security cap
  memcpy(sm_cmd.ue_security_cap.eea, m_sec_ctx.ue_network_cap.eea, 8 * sizeof(bool));
  memcpy(sm_cmd.ue_security_cap.eia, m_sec_ctx.ue_network_cap.eia, 8 * sizeof(bool));

  sm_cmd.ue_security_cap.uea_present = m_sec_ctx.ue_network_cap.uea_present;
  memcpy(sm_cmd.ue_security_cap.uea, m_sec_ctx.ue_network_cap.uea, 8 * sizeof(bool));

  sm_cmd.ue_security_cap.uia_present = m_sec_ctx.ue_network_cap.uia_present;
  memcpy(sm_cmd.ue_security_cap.uia, m_sec_ctx.ue_network_cap.uia, 8 * sizeof(bool));

  sm_cmd.ue_security_cap.gea_present = m_sec_ctx.ms_network_cap_present;
  memcpy(sm_cmd.ue_security_cap.gea, m_sec_ctx.ms_network_cap.gea, 8 * sizeof(bool));

  sm_cmd.imeisv_req_present = false;
  sm_cmd.nonce_ue_present   = false;
  sm_cmd.nonce_mme_present  = false;

  uint8_t           sec_hdr_type = 0;
  LIBLTE_ERROR_ENUM err          = liblte_mme_pack_security_mode_command_msg(
      &sm_cmd, sec_hdr_type, m_sec_ctx.dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->console("Error packing Authentication Request\n");
    return false;
  }

  // Generate EPS security context
  srslte::security_generate_k_nas(
      m_sec_ctx.k_asme, m_sec_ctx.cipher_algo, m_sec_ctx.integ_algo, m_sec_ctx.k_nas_enc, m_sec_ctx.k_nas_int);

  m_nas_log->info_hex(m_sec_ctx.k_nas_enc, 32, "Key NAS Encryption (k_nas_enc)\n");
  m_nas_log->info_hex(m_sec_ctx.k_nas_int, 32, "Key NAS Integrity (k_nas_int)\n");

  if (m_enable_ue_state_fuzzing == false) {
    uint8_t key_enb[32];
    srslte::security_generate_k_enb(m_sec_ctx.k_asme, m_sec_ctx.ul_nas_count, m_sec_ctx.k_enb);
    m_nas_log->info("Generating KeNB with UL NAS COUNT: %d\n", m_sec_ctx.ul_nas_count);
    m_nas_log->console("Generating KeNB with UL NAS COUNT: %d\n", m_sec_ctx.ul_nas_count);
    m_nas_log->info_hex(m_sec_ctx.k_enb, 32, "Key eNodeB (k_enb)\n");
  }

  // Generate MAC for integrity protection
  uint8_t mac[4];

  return true;
}
bool nas::pack_esm_information_request(srslte::byte_buffer_t* nas_buffer)
{
  m_nas_log->info("Packing ESM Information request\n");

  LIBLTE_MME_ESM_INFORMATION_REQUEST_MSG_STRUCT esm_info_req;
  esm_info_req.eps_bearer_id       = 0;
  esm_info_req.proc_transaction_id = m_emm_ctx.procedure_transaction_id;

  uint8_t sec_hdr_type = LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED;

  m_sec_ctx.dl_nas_count++;
  LIBLTE_ERROR_ENUM err = srslte_mme_pack_esm_information_request_msg(
      &esm_info_req, sec_hdr_type, m_sec_ctx.dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error packing ESM information request\n");
    m_nas_log->console("Error packing ESM information request\n");
    return false;
  }

  cipher_encrypt(nas_buffer);
  uint8_t mac[4];
  integrity_generate(nas_buffer, mac);
  memcpy(&nas_buffer->msg[1], mac, 4);

  return true;
}
int gflag = 1;
bool nas::pack_guti_rellocation_request(srslte::byte_buffer_t* nas_buffer)
{
  m_nas_log->info("Packing GUTI Reallocation Request\n");

  LIBLTE_MME_GUTI_REALLOCATION_COMMAND_MSG_STRUCT                   guti_reallocation_request;
  LIBLTE_MME_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST_MSG_STRUCT act_def_eps_bearer_context_req;

  // Get decimal MCC and MNC
  uint32_t mcc = 0;
  mcc += 0x000F & m_mcc;
  mcc += 10 * ((0x00F0 & m_mcc) >> 4);
  mcc += 100 * ((0x0F00 & m_mcc) >> 8);

  uint32_t mnc = 0;
  if (0xFF00 == (m_mnc & 0xFF00)) {
    // Two digit MNC
    mnc += 0x000F & m_mnc;
    mnc += 10 * ((0x00F0 & m_mnc) >> 4);
  } else {
    // Three digit MNC
    mnc += 0x000F & m_mnc;
    mnc += 10 * ((0x00F0 & m_mnc) >> 4);
    mnc += 100 * ((0x0F00 & m_mnc) >> 8);
  }

  guti_reallocation_request.tai_list_present    = true;
  guti_reallocation_request.tai_list.N_tais     = 1;
  guti_reallocation_request.tai_list.tai[0].mcc = mcc;
  guti_reallocation_request.tai_list.tai[0].mnc = mnc;
  guti_reallocation_request.tai_list.tai[0].tac = m_tac;

  // Allocate a GUTI ot the UE
  guti_reallocation_request.guti.type_of_id        = 6; // 110 -> GUTI
  guti_reallocation_request.guti.guti.mcc          = mcc;
  guti_reallocation_request.guti.guti.mnc          = mnc;
  guti_reallocation_request.guti.guti.mme_group_id = m_mme_group;
  guti_reallocation_request.guti.guti.mme_code     = m_mme_code;
  guti_reallocation_request.guti.guti.m_tmsi       = m_s1ap->allocate_m_tmsi(m_emm_ctx.imsi);

  memcpy(&m_sec_ctx.guti, &guti_reallocation_request.guti, sizeof(LIBLTE_MME_EPS_MOBILE_ID_GUTI_STRUCT));

  
  uint8_t sec_hdr_type = 2;
  m_sec_ctx.dl_nas_count++;

  gflag++;

  liblte_mme_pack_guti_reallocation_command_msg(
      &guti_reallocation_request, sec_hdr_type, m_sec_ctx.dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);
  // Encrypt NAS message
  cipher_encrypt(nas_buffer);

  // Integrity protect NAS message
  uint8_t mac[4];
  integrity_generate(nas_buffer, mac);
  memcpy(&nas_buffer->msg[1], mac, 4);

  // Log attach accept info
  m_nas_log->console("Packed GUTI Reallocation request\n");
  printf("dl_nas_count for GUTI Reallocation: %d\n",m_sec_ctx.dl_nas_count);
  return true;
}
bool nas::pack_guti_rellocation_request_plain(srslte::byte_buffer_t* nas_buffer)
{
  m_nas_log->info("Packing GUTI Reallocation Request plain\n");

  LIBLTE_MME_GUTI_REALLOCATION_COMMAND_MSG_STRUCT                   guti_reallocation_request;
  LIBLTE_MME_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST_MSG_STRUCT act_def_eps_bearer_context_req;

  // Get decimal MCC and MNC
  uint32_t mcc = 0;
  mcc += 0x000F & m_mcc;
  mcc += 10 * ((0x00F0 & m_mcc) >> 4);
  mcc += 100 * ((0x0F00 & m_mcc) >> 8);

  uint32_t mnc = 0;
  if (0xFF00 == (m_mnc & 0xFF00)) {
    // Two digit MNC
    mnc += 0x000F & m_mnc;
    mnc += 10 * ((0x00F0 & m_mnc) >> 4);
  } else {
    // Three digit MNC
    mnc += 0x000F & m_mnc;
    mnc += 10 * ((0x00F0 & m_mnc) >> 4);
    mnc += 100 * ((0x0F00 & m_mnc) >> 8);
  }

  guti_reallocation_request.tai_list_present    = true;
  guti_reallocation_request.tai_list.N_tais     = 1;
  guti_reallocation_request.tai_list.tai[0].mcc = mcc;
  guti_reallocation_request.tai_list.tai[0].mnc = mnc;
  guti_reallocation_request.tai_list.tai[0].tac = m_tac;

  // Allocate a GUTI ot the UE
  guti_reallocation_request.guti.type_of_id        = 6; // 110 -> GUTI
  guti_reallocation_request.guti.guti.mcc          = mcc;
  guti_reallocation_request.guti.guti.mnc          = mnc;
  guti_reallocation_request.guti.guti.mme_group_id = m_mme_group;
  guti_reallocation_request.guti.guti.mme_code     = m_mme_code;
  guti_reallocation_request.guti.guti.m_tmsi       = m_s1ap->allocate_m_tmsi(m_emm_ctx.imsi);

  memcpy(&m_sec_ctx.guti, &guti_reallocation_request.guti, sizeof(LIBLTE_MME_EPS_MOBILE_ID_GUTI_STRUCT));

  
  uint8_t sec_hdr_type = 0;
  m_sec_ctx.dl_nas_count++;

  liblte_mme_pack_guti_reallocation_command_msg(
      &guti_reallocation_request, sec_hdr_type, m_sec_ctx.dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);
  // Encrypt NAS message
  cipher_encrypt(nas_buffer);

  // Log attach accept info
  m_nas_log->console("Packed GUTI Reallocation request plain without the header\n");
  return true;
}
bool nas::pack_tau_accept(srslte::byte_buffer_t* nas_buffer)
{
  m_nas_log->info("Packing TAU Accept\n");

  LIBLTE_MME_TRACKING_AREA_UPDATE_ACCEPT_MSG_STRUCT                 tau_accept;
  LIBLTE_MME_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST_MSG_STRUCT act_def_eps_bearer_context_req;

  // Get decimal MCC and MNC
  uint32_t mcc = 0;
  mcc += 0x000F & m_mcc;
  mcc += 10 * ((0x00F0 & m_mcc) >> 4);
  mcc += 100 * ((0x0F00 & m_mcc) >> 8);

  uint32_t mnc = 0;
  if (0xFF00 == (m_mnc & 0xFF00)) {
    // Two digit MNC
    mnc += 0x000F & m_mnc;
    mnc += 10 * ((0x00F0 & m_mnc) >> 4);
  } else {
    // Three digit MNC
    mnc += 0x000F & m_mnc;
    mnc += 10 * ((0x00F0 & m_mnc) >> 4);
    mnc += 100 * ((0x0F00 & m_mnc) >> 8);
  }

  // TAU accept
  tau_accept.eps_update_result = 1; // m_emm_ctx.eps_update_type.type;

  tau_accept.t3412.unit  = LIBLTE_MME_GPRS_TIMER_UNIT_1_MINUTE; // GPRS 1 minute unit
  tau_accept.t3412.value = 30;                                  // 30 minute periodic timer

  tau_accept.tai_list.N_tais     = 1;
  tau_accept.tai_list.tai[0].mcc = mcc;
  tau_accept.tai_list.tai[0].mnc = mnc;
  tau_accept.tai_list.tai[0].tac = m_tac;

  m_nas_log->console("TAU Accept -- MCC 0x%x, MNC 0x%x\n", m_mcc, m_mnc);

  // Allocate a GUTI ot the UE
  tau_accept.guti_present           = true;
  tau_accept.guti.type_of_id        = 6; // 110 -> GUTI
  tau_accept.guti.guti.mcc          = mcc;
  tau_accept.guti.guti.mnc          = mnc;
  tau_accept.guti.guti.mme_group_id = m_mme_group;
  tau_accept.guti.guti.mme_code     = m_mme_code;
  tau_accept.guti.guti.m_tmsi       = m_s1ap->allocate_m_tmsi(m_emm_ctx.imsi);
  m_nas_log->debug("Allocated GUTI: MCC %d, MNC %d, MME Group Id %d, MME Code 0x%x, M-TMSI 0x%x\n",
                   tau_accept.guti.guti.mcc,
                   tau_accept.guti.guti.mnc,
                   tau_accept.guti.guti.mme_group_id,
                   tau_accept.guti.guti.mme_code,
                   tau_accept.guti.guti.m_tmsi);

  memcpy(&m_sec_ctx.guti, &tau_accept.guti, sizeof(LIBLTE_MME_EPS_MOBILE_ID_GUTI_STRUCT));

  // Set up LAI for combined EPS/IMSI attach
  tau_accept.lai_present = true;
  tau_accept.lai.mcc     = mcc;
  tau_accept.lai.mnc     = mnc;
  tau_accept.lai.lac     = 001;

  tau_accept.ms_id_present    = true;
  tau_accept.ms_id.type_of_id = LIBLTE_MME_MOBILE_ID_TYPE_TMSI;
  tau_accept.ms_id.tmsi       = tau_accept.guti.guti.m_tmsi;

  // Make sure all unused options are set to false
  tau_accept.emm_cause_present                   = false;
  tau_accept.t3402_present                       = false;
  tau_accept.t3423_present                       = false;
  tau_accept.equivalent_plmns_present            = false;
  tau_accept.emerg_num_list_present              = false;
  tau_accept.eps_network_feature_support_present = false;
  tau_accept.additional_update_result_present    = false;
  tau_accept.t3412_ext_present                   = false;
  tau_accept.eps_bearer_context_status_present   = false;
  // Set activate default eps bearer (esm_ms)
  // Set pdn_addr

  act_def_eps_bearer_context_req.pdn_addr.pdn_type = LIBLTE_MME_PDN_TYPE_IPV4;
  memcpy(act_def_eps_bearer_context_req.pdn_addr.addr, &m_emm_ctx.ue_ip.s_addr, 4);
  // Set eps bearer id
  act_def_eps_bearer_context_req.eps_bearer_id          = 5;
  act_def_eps_bearer_context_req.transaction_id_present = false;
  // set eps_qos
  act_def_eps_bearer_context_req.eps_qos.qci            = m_esm_ctx[5].qci;
  act_def_eps_bearer_context_req.eps_qos.br_present     = false;
  act_def_eps_bearer_context_req.eps_qos.br_ext_present = false;

  // set apn
  strncpy(act_def_eps_bearer_context_req.apn.apn, m_apn.c_str(), LIBLTE_STRING_LEN - 1);
  act_def_eps_bearer_context_req.proc_transaction_id = m_emm_ctx.procedure_transaction_id;

  // Set DNS server
  act_def_eps_bearer_context_req.protocol_cnfg_opts_present    = true;
  act_def_eps_bearer_context_req.protocol_cnfg_opts.N_opts     = 1;
  act_def_eps_bearer_context_req.protocol_cnfg_opts.opt[0].id  = 0x0d;
  act_def_eps_bearer_context_req.protocol_cnfg_opts.opt[0].len = 4;

  struct sockaddr_in dns_addr;
  inet_pton(AF_INET, m_dns.c_str(), &(dns_addr.sin_addr));
  memcpy(act_def_eps_bearer_context_req.protocol_cnfg_opts.opt[0].contents, &dns_addr.sin_addr.s_addr, 4);

  // Make sure all unused options are set to false
  act_def_eps_bearer_context_req.negotiated_qos_present    = false;
  act_def_eps_bearer_context_req.llc_sapi_present          = false;
  act_def_eps_bearer_context_req.radio_prio_present        = false;
  act_def_eps_bearer_context_req.packet_flow_id_present    = false;
  act_def_eps_bearer_context_req.apn_ambr_present          = false;
  act_def_eps_bearer_context_req.esm_cause_present         = false;
  act_def_eps_bearer_context_req.connectivity_type_present = false;
  uint8_t sec_hdr_type                                     = 2;
  m_sec_ctx.dl_nas_count++;


  liblte_mme_pack_tracking_area_update_accept_msg(
      &tau_accept, sec_hdr_type, m_sec_ctx.dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);
  // Encrypt NAS message
  cipher_encrypt(nas_buffer);

  uint8_t mac[4];
  integrity_generate(nas_buffer, mac);
  memcpy(&nas_buffer->msg[1], mac, 4);

  // Log attach accept info
  m_nas_log->console("Packed TAU Accept\n");
  return true;
}
bool nas::pack_tau_accept_plain(srslte::byte_buffer_t* nas_buffer)
{
  m_nas_log->info("Packing TAU Accept Plain\n");

  LIBLTE_MME_TRACKING_AREA_UPDATE_ACCEPT_MSG_STRUCT                 tau_accept;
  LIBLTE_MME_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST_MSG_STRUCT act_def_eps_bearer_context_req;

  // Get decimal MCC and MNC
  uint32_t mcc = 0;
  mcc += 0x000F & m_mcc;
  mcc += 10 * ((0x00F0 & m_mcc) >> 4);
  mcc += 100 * ((0x0F00 & m_mcc) >> 8);

  uint32_t mnc = 0;
  if (0xFF00 == (m_mnc & 0xFF00)) {
    // Two digit MNC
    mnc += 0x000F & m_mnc;
    mnc += 10 * ((0x00F0 & m_mnc) >> 4);
  } else {
    // Three digit MNC
    mnc += 0x000F & m_mnc;
    mnc += 10 * ((0x00F0 & m_mnc) >> 4);
    mnc += 100 * ((0x0F00 & m_mnc) >> 8);
  }

  // TAU accept
  tau_accept.eps_update_result = 1; // m_emm_ctx.eps_update_type.type;

  tau_accept.t3412.unit  = LIBLTE_MME_GPRS_TIMER_UNIT_1_MINUTE; // GPRS 1 minute unit
  tau_accept.t3412.value = 30;                                  // 30 minute periodic timer

  tau_accept.tai_list.N_tais     = 1;
  tau_accept.tai_list.tai[0].mcc = mcc;
  tau_accept.tai_list.tai[0].mnc = mnc;
  tau_accept.tai_list.tai[0].tac = m_tac;

  m_nas_log->console("TAU Accept -- MCC 0x%x, MNC 0x%x\n", m_mcc, m_mnc);

  // Allocate a GUTI ot the UE
  tau_accept.guti_present           = true;
  tau_accept.guti.type_of_id        = 6; // 110 -> GUTI
  tau_accept.guti.guti.mcc          = mcc;
  tau_accept.guti.guti.mnc          = mnc;
  tau_accept.guti.guti.mme_group_id = m_mme_group;
  tau_accept.guti.guti.mme_code     = m_mme_code;
  tau_accept.guti.guti.m_tmsi       = m_s1ap->allocate_m_tmsi(m_emm_ctx.imsi);
  m_nas_log->debug("Allocated GUTI: MCC %d, MNC %d, MME Group Id %d, MME Code 0x%x, M-TMSI 0x%x\n",
                   tau_accept.guti.guti.mcc,
                   tau_accept.guti.guti.mnc,
                   tau_accept.guti.guti.mme_group_id,
                   tau_accept.guti.guti.mme_code,
                   tau_accept.guti.guti.m_tmsi);

  memcpy(&m_sec_ctx.guti, &tau_accept.guti, sizeof(LIBLTE_MME_EPS_MOBILE_ID_GUTI_STRUCT));

  // Set up LAI for combined EPS/IMSI attach
  tau_accept.lai_present = true;
  tau_accept.lai.mcc     = mcc;
  tau_accept.lai.mnc     = mnc;
  tau_accept.lai.lac     = 001;

  tau_accept.ms_id_present    = true;
  tau_accept.ms_id.type_of_id = LIBLTE_MME_MOBILE_ID_TYPE_TMSI;
  tau_accept.ms_id.tmsi       = tau_accept.guti.guti.m_tmsi;

  // Make sure all unused options are set to false
  tau_accept.emm_cause_present                   = false;
  tau_accept.t3402_present                       = false;
  tau_accept.t3423_present                       = false;
  tau_accept.equivalent_plmns_present            = false;
  tau_accept.emerg_num_list_present              = false;
  tau_accept.eps_network_feature_support_present = false;
  tau_accept.additional_update_result_present    = false;
  tau_accept.t3412_ext_present                   = false;
  tau_accept.eps_bearer_context_status_present   = false;
  // Set activate default eps bearer (esm_ms)
  // Set pdn_addr

  act_def_eps_bearer_context_req.pdn_addr.pdn_type = LIBLTE_MME_PDN_TYPE_IPV4;
  memcpy(act_def_eps_bearer_context_req.pdn_addr.addr, &m_emm_ctx.ue_ip.s_addr, 4);
  // Set eps bearer id
  act_def_eps_bearer_context_req.eps_bearer_id          = 5;
  act_def_eps_bearer_context_req.transaction_id_present = false;
  // set eps_qos
  act_def_eps_bearer_context_req.eps_qos.qci            = m_esm_ctx[5].qci;
  act_def_eps_bearer_context_req.eps_qos.br_present     = false;
  act_def_eps_bearer_context_req.eps_qos.br_ext_present = false;

  // set apn
  strncpy(act_def_eps_bearer_context_req.apn.apn, m_apn.c_str(), LIBLTE_STRING_LEN - 1);
  act_def_eps_bearer_context_req.proc_transaction_id = m_emm_ctx.procedure_transaction_id; 

  // Set DNS server
  act_def_eps_bearer_context_req.protocol_cnfg_opts_present    = true;
  act_def_eps_bearer_context_req.protocol_cnfg_opts.N_opts     = 1;
  act_def_eps_bearer_context_req.protocol_cnfg_opts.opt[0].id  = 0x0d;
  act_def_eps_bearer_context_req.protocol_cnfg_opts.opt[0].len = 4;

  struct sockaddr_in dns_addr;
  inet_pton(AF_INET, m_dns.c_str(), &(dns_addr.sin_addr));
  memcpy(act_def_eps_bearer_context_req.protocol_cnfg_opts.opt[0].contents, &dns_addr.sin_addr.s_addr, 4);

  // Make sure all unused options are set to false
  act_def_eps_bearer_context_req.negotiated_qos_present    = false;
  act_def_eps_bearer_context_req.llc_sapi_present          = false;
  act_def_eps_bearer_context_req.radio_prio_present        = false;
  act_def_eps_bearer_context_req.packet_flow_id_present    = false;
  act_def_eps_bearer_context_req.apn_ambr_present          = false;
  act_def_eps_bearer_context_req.esm_cause_present         = false;
  act_def_eps_bearer_context_req.connectivity_type_present = false;
  uint8_t sec_hdr_type                                     = 1;
  m_sec_ctx.dl_nas_count++;


  liblte_mme_pack_tracking_area_update_accept_msg(
      &tau_accept, sec_hdr_type, m_sec_ctx.dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);

  // Log attach accept info
  m_nas_log->console("Packed TAU Accept\n");
  return true;
}

bool nas::pack_attach_accept_no_integrity(srslte::byte_buffer_t* nas_buffer)
{
  m_nas_log->info("Packing Attach Accept\n");

  LIBLTE_MME_ATTACH_ACCEPT_MSG_STRUCT                               attach_accept;
  LIBLTE_MME_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST_MSG_STRUCT act_def_eps_bearer_context_req;

  // Get decimal MCC and MNC
  uint32_t mcc = 0;
  mcc += 0x000F & m_mcc;
  mcc += 10 * ((0x00F0 & m_mcc) >> 4);
  mcc += 100 * ((0x0F00 & m_mcc) >> 8);

  uint32_t mnc = 0;
  if (0xFF00 == (m_mnc & 0xFF00)) {
    // Two digit MNC
    mnc += 0x000F & m_mnc;
    mnc += 10 * ((0x00F0 & m_mnc) >> 4);
  } else {
    // Three digit MNC
    mnc += 0x000F & m_mnc;
    mnc += 10 * ((0x00F0 & m_mnc) >> 4);
    mnc += 100 * ((0x0F00 & m_mnc) >> 8);
  }

  // Attach accept
  attach_accept.eps_attach_result = m_emm_ctx.attach_type;

  attach_accept.t3412.unit  = LIBLTE_MME_GPRS_TIMER_UNIT_1_MINUTE; // GPRS 1 minute unit
  attach_accept.t3412.value = 30;                                  // 30 minute periodic timer

  attach_accept.tai_list.N_tais     = 1;
  attach_accept.tai_list.tai[0].mcc = mcc;
  attach_accept.tai_list.tai[0].mnc = mnc;
  attach_accept.tai_list.tai[0].tac = m_tac;

  m_nas_log->info("Attach Accept -- MCC 0x%x, MNC 0x%x\n", m_mcc, m_mnc);

  // Allocate a GUTI ot the UE
  attach_accept.guti_present           = true;
  attach_accept.guti.type_of_id        = 6; // 110 -> GUTI
  attach_accept.guti.guti.mcc          = mcc;
  attach_accept.guti.guti.mnc          = mnc;
  attach_accept.guti.guti.mme_group_id = m_mme_group;
  attach_accept.guti.guti.mme_code     = m_mme_code;
  attach_accept.guti.guti.m_tmsi       = m_s1ap->allocate_m_tmsi(m_emm_ctx.imsi);
  m_nas_log->debug("Allocated GUTI: MCC %d, MNC %d, MME Group Id %d, MME Code 0x%x, M-TMSI 0x%x\n",
                   attach_accept.guti.guti.mcc,
                   attach_accept.guti.guti.mnc,
                   attach_accept.guti.guti.mme_group_id,
                   attach_accept.guti.guti.mme_code,
                   attach_accept.guti.guti.m_tmsi);

  memcpy(&m_sec_ctx.guti, &attach_accept.guti, sizeof(LIBLTE_MME_EPS_MOBILE_ID_GUTI_STRUCT));

  // Set up LAI for combined EPS/IMSI attach
  attach_accept.lai_present = true;
  attach_accept.lai.mcc     = mcc;
  attach_accept.lai.mnc     = mnc;
  attach_accept.lai.lac     = 001;

  attach_accept.ms_id_present    = true;
  attach_accept.ms_id.type_of_id = LIBLTE_MME_MOBILE_ID_TYPE_TMSI;
  attach_accept.ms_id.tmsi       = attach_accept.guti.guti.m_tmsi;

  // Make sure all unused options are set to false
  attach_accept.emm_cause_present                   = false;
  attach_accept.t3402_present                       = false;
  attach_accept.t3423_present                       = false;
  attach_accept.equivalent_plmns_present            = false;
  attach_accept.emerg_num_list_present              = false;
  attach_accept.eps_network_feature_support_present = false;
  attach_accept.additional_update_result_present    = false;
  attach_accept.t3412_ext_present                   = false;

  // Set activate default eps bearer (esm_ms)
  // Set pdn_addr
  act_def_eps_bearer_context_req.pdn_addr.pdn_type = LIBLTE_MME_PDN_TYPE_IPV4;
  memcpy(act_def_eps_bearer_context_req.pdn_addr.addr, &m_emm_ctx.ue_ip.s_addr, 4);
  // Set eps bearer id
  act_def_eps_bearer_context_req.eps_bearer_id          = 5;
  act_def_eps_bearer_context_req.transaction_id_present = false;
  // set eps_qos
  act_def_eps_bearer_context_req.eps_qos.qci            = m_esm_ctx[5].qci;
  act_def_eps_bearer_context_req.eps_qos.br_present     = false;
  act_def_eps_bearer_context_req.eps_qos.br_ext_present = false;

  // set apn
  strncpy(act_def_eps_bearer_context_req.apn.apn, m_apn.c_str(), LIBLTE_STRING_LEN - 1);
  act_def_eps_bearer_context_req.proc_transaction_id = m_emm_ctx.procedure_transaction_id; 

  // Set DNS server
  act_def_eps_bearer_context_req.protocol_cnfg_opts_present    = true;
  act_def_eps_bearer_context_req.protocol_cnfg_opts.N_opts     = 1;
  act_def_eps_bearer_context_req.protocol_cnfg_opts.opt[0].id  = 0x0d;
  act_def_eps_bearer_context_req.protocol_cnfg_opts.opt[0].len = 4;

  struct sockaddr_in dns_addr;
  inet_pton(AF_INET, m_dns.c_str(), &(dns_addr.sin_addr));
  memcpy(act_def_eps_bearer_context_req.protocol_cnfg_opts.opt[0].contents, &dns_addr.sin_addr.s_addr, 4);

  // Make sure all unused options are set to false
  act_def_eps_bearer_context_req.negotiated_qos_present    = false;
  act_def_eps_bearer_context_req.llc_sapi_present          = false;
  act_def_eps_bearer_context_req.radio_prio_present        = false;
  act_def_eps_bearer_context_req.packet_flow_id_present    = false;
  act_def_eps_bearer_context_req.apn_ambr_present          = false;
  act_def_eps_bearer_context_req.esm_cause_present         = false;
  act_def_eps_bearer_context_req.connectivity_type_present = false;

  uint8_t sec_hdr_type = 2;
  m_sec_ctx.dl_nas_count++;


  liblte_mme_pack_activate_default_eps_bearer_context_request_msg(&act_def_eps_bearer_context_req,
                                                                  &attach_accept.esm_msg);
  liblte_mme_pack_attach_accept_msg(
      &attach_accept, sec_hdr_type, m_sec_ctx.dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);



  cipher_encrypt(nas_buffer);
  // Integrity protect NAS message
  uint8_t mac[4];

  mac[0] = 0x0;
  mac[1] = 0x0;
  mac[2] = 0x0;
  mac[3] = 0x0;
  memcpy(&nas_buffer->msg[1], mac, 4);

  // Log attach accept info
  m_nas_log->info("Packed Attach Accept no integrity\n");
  return true;
}

bool nas::pack_attach_accept_null_header(srslte::byte_buffer_t* nas_buffer)
{
  m_nas_log->info("Packing Attach Accept null header\n");

  LIBLTE_MME_ATTACH_ACCEPT_MSG_STRUCT                               attach_accept;
  LIBLTE_MME_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST_MSG_STRUCT act_def_eps_bearer_context_req;

  // Get decimal MCC and MNC
  uint32_t mcc = 0;
  mcc += 0x000F & m_mcc;
  mcc += 10 * ((0x00F0 & m_mcc) >> 4);
  mcc += 100 * ((0x0F00 & m_mcc) >> 8);

  uint32_t mnc = 0;
  if (0xFF00 == (m_mnc & 0xFF00)) {
    // Two digit MNC
    mnc += 0x000F & m_mnc;
    mnc += 10 * ((0x00F0 & m_mnc) >> 4);
  } else {
    // Three digit MNC
    mnc += 0x000F & m_mnc;
    mnc += 10 * ((0x00F0 & m_mnc) >> 4);
    mnc += 100 * ((0x0F00 & m_mnc) >> 8);
  }

  // Attach accept
  attach_accept.eps_attach_result = m_emm_ctx.attach_type;

  attach_accept.t3412.unit  = LIBLTE_MME_GPRS_TIMER_UNIT_1_MINUTE; // GPRS 1 minute unit
  attach_accept.t3412.value = 30;                                  // 30 minute periodic timer

  attach_accept.tai_list.N_tais     = 1;
  attach_accept.tai_list.tai[0].mcc = mcc;
  attach_accept.tai_list.tai[0].mnc = mnc;
  attach_accept.tai_list.tai[0].tac = m_tac;

  m_nas_log->info("Attach Accept -- MCC 0x%x, MNC 0x%x\n", m_mcc, m_mnc);

  // Allocate a GUTI ot the UE
  attach_accept.guti_present           = true;
  attach_accept.guti.type_of_id        = 6; // 110 -> GUTI
  attach_accept.guti.guti.mcc          = mcc;
  attach_accept.guti.guti.mnc          = mnc;
  attach_accept.guti.guti.mme_group_id = m_mme_group;
  attach_accept.guti.guti.mme_code     = m_mme_code;
  attach_accept.guti.guti.m_tmsi       = m_s1ap->allocate_m_tmsi(m_emm_ctx.imsi);
  m_nas_log->debug("Allocated GUTI: MCC %d, MNC %d, MME Group Id %d, MME Code 0x%x, M-TMSI 0x%x\n",
                   attach_accept.guti.guti.mcc,
                   attach_accept.guti.guti.mnc,
                   attach_accept.guti.guti.mme_group_id,
                   attach_accept.guti.guti.mme_code,
                   attach_accept.guti.guti.m_tmsi);

  memcpy(&m_sec_ctx.guti, &attach_accept.guti, sizeof(LIBLTE_MME_EPS_MOBILE_ID_GUTI_STRUCT));

  // Set up LAI for combined EPS/IMSI attach
  attach_accept.lai_present = true;
  attach_accept.lai.mcc     = mcc;
  attach_accept.lai.mnc     = mnc;
  attach_accept.lai.lac     = 001;

  attach_accept.ms_id_present    = true;
  attach_accept.ms_id.type_of_id = LIBLTE_MME_MOBILE_ID_TYPE_TMSI;
  attach_accept.ms_id.tmsi       = attach_accept.guti.guti.m_tmsi;

  // Make sure all unused options are set to false
  attach_accept.emm_cause_present                   = false;
  attach_accept.t3402_present                       = false;
  attach_accept.t3423_present                       = false;
  attach_accept.equivalent_plmns_present            = false;
  attach_accept.emerg_num_list_present              = false;
  attach_accept.eps_network_feature_support_present = false;
  attach_accept.additional_update_result_present    = false;
  attach_accept.t3412_ext_present                   = false;

  // Set activate default eps bearer (esm_ms)
  // Set pdn_addr
  act_def_eps_bearer_context_req.pdn_addr.pdn_type = LIBLTE_MME_PDN_TYPE_IPV4;
  memcpy(act_def_eps_bearer_context_req.pdn_addr.addr, &m_emm_ctx.ue_ip.s_addr, 4);
  // Set eps bearer id
  act_def_eps_bearer_context_req.eps_bearer_id          = 5;
  act_def_eps_bearer_context_req.transaction_id_present = false;
  // set eps_qos
  act_def_eps_bearer_context_req.eps_qos.qci            = m_esm_ctx[5].qci;
  act_def_eps_bearer_context_req.eps_qos.br_present     = false;
  act_def_eps_bearer_context_req.eps_qos.br_ext_present = false;

  // set apn
  strncpy(act_def_eps_bearer_context_req.apn.apn, m_apn.c_str(), LIBLTE_STRING_LEN - 1);
  act_def_eps_bearer_context_req.proc_transaction_id = m_emm_ctx.procedure_transaction_id; 

  // Set DNS server
  act_def_eps_bearer_context_req.protocol_cnfg_opts_present    = true;
  act_def_eps_bearer_context_req.protocol_cnfg_opts.N_opts     = 1;
  act_def_eps_bearer_context_req.protocol_cnfg_opts.opt[0].id  = 0x0d;
  act_def_eps_bearer_context_req.protocol_cnfg_opts.opt[0].len = 4;

  struct sockaddr_in dns_addr;
  inet_pton(AF_INET, m_dns.c_str(), &(dns_addr.sin_addr));
  memcpy(act_def_eps_bearer_context_req.protocol_cnfg_opts.opt[0].contents, &dns_addr.sin_addr.s_addr, 4);

  // Make sure all unused options are set to false
  act_def_eps_bearer_context_req.negotiated_qos_present    = false;
  act_def_eps_bearer_context_req.llc_sapi_present          = false;
  act_def_eps_bearer_context_req.radio_prio_present        = false;
  act_def_eps_bearer_context_req.packet_flow_id_present    = false;
  act_def_eps_bearer_context_req.apn_ambr_present          = false;
  act_def_eps_bearer_context_req.esm_cause_present         = false;
  act_def_eps_bearer_context_req.connectivity_type_present = false;

  uint8_t sec_hdr_type = 0;
  m_sec_ctx.dl_nas_count++;

  liblte_mme_pack_activate_default_eps_bearer_context_request_msg(&act_def_eps_bearer_context_req,
                                                                  &attach_accept.esm_msg);
  liblte_mme_pack_attach_accept_msg(
      &attach_accept, sec_hdr_type, m_sec_ctx.dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);


  // Log attach accept info
  m_nas_log->info("Packed Attach Accept no integrity\n");
  return true;
}

bool nas::pack_attach_accept(srslte::byte_buffer_t* nas_buffer)
{
  m_nas_log->info("Packing Attach Accept\n");

  LIBLTE_MME_ATTACH_ACCEPT_MSG_STRUCT                               attach_accept;
  LIBLTE_MME_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST_MSG_STRUCT act_def_eps_bearer_context_req;

  // Get decimal MCC and MNC
  uint32_t mcc = 0;
  mcc += 0x000F & m_mcc;
  mcc += 10 * ((0x00F0 & m_mcc) >> 4);
  mcc += 100 * ((0x0F00 & m_mcc) >> 8);

  uint32_t mnc = 0;
  if (0xFF00 == (m_mnc & 0xFF00)) {
    // Two digit MNC
    mnc += 0x000F & m_mnc;
    mnc += 10 * ((0x00F0 & m_mnc) >> 4);
  } else {
    // Three digit MNC
    mnc += 0x000F & m_mnc;
    mnc += 10 * ((0x00F0 & m_mnc) >> 4);
    mnc += 100 * ((0x0F00 & m_mnc) >> 8);
  }

  // Attach accept
  attach_accept.eps_attach_result = m_emm_ctx.attach_type;

  attach_accept.t3412.unit  = LIBLTE_MME_GPRS_TIMER_UNIT_1_MINUTE; // GPRS 1 minute unit
  attach_accept.t3412.value = 30;                                  // 30 minute periodic timer

  attach_accept.tai_list.N_tais     = 1;
  attach_accept.tai_list.tai[0].mcc = mcc;
  attach_accept.tai_list.tai[0].mnc = mnc;
  attach_accept.tai_list.tai[0].tac = m_tac;

  m_nas_log->info("Attach Accept -- MCC 0x%x, MNC 0x%x\n", m_mcc, m_mnc);

  // Allocate a GUTI ot the UE
  attach_accept.guti_present           = true;
  attach_accept.guti.type_of_id        = 6; // 110 -> GUTI
  attach_accept.guti.guti.mcc          = mcc;
  attach_accept.guti.guti.mnc          = mnc;
  attach_accept.guti.guti.mme_group_id = m_mme_group;
  attach_accept.guti.guti.mme_code     = m_mme_code;
  attach_accept.guti.guti.m_tmsi       = m_s1ap->allocate_m_tmsi(m_emm_ctx.imsi);
  m_nas_log->debug("Allocated GUTI: MCC %d, MNC %d, MME Group Id %d, MME Code 0x%x, M-TMSI 0x%x\n",
                   attach_accept.guti.guti.mcc,
                   attach_accept.guti.guti.mnc,
                   attach_accept.guti.guti.mme_group_id,
                   attach_accept.guti.guti.mme_code,
                   attach_accept.guti.guti.m_tmsi);

  memcpy(&m_sec_ctx.guti, &attach_accept.guti, sizeof(LIBLTE_MME_EPS_MOBILE_ID_GUTI_STRUCT));

  // Set up LAI for combined EPS/IMSI attach
  attach_accept.lai_present = true;
  attach_accept.lai.mcc     = mcc;
  attach_accept.lai.mnc     = mnc;
  attach_accept.lai.lac     = 001;

  attach_accept.ms_id_present    = true;
  attach_accept.ms_id.type_of_id = LIBLTE_MME_MOBILE_ID_TYPE_TMSI;
  attach_accept.ms_id.tmsi       = attach_accept.guti.guti.m_tmsi;

  // Make sure all unused options are set to false
  attach_accept.emm_cause_present                   = false;
  attach_accept.t3402_present                       = false;
  attach_accept.t3423_present                       = false;
  attach_accept.equivalent_plmns_present            = false;
  attach_accept.emerg_num_list_present              = false;
  attach_accept.eps_network_feature_support_present = false;
  attach_accept.additional_update_result_present    = false;
  attach_accept.t3412_ext_present                   = false;

  // Set activate default eps bearer (esm_ms)
  // Set pdn_addr
  act_def_eps_bearer_context_req.pdn_addr.pdn_type = LIBLTE_MME_PDN_TYPE_IPV4;
  memcpy(act_def_eps_bearer_context_req.pdn_addr.addr, &m_emm_ctx.ue_ip.s_addr, 4);
  // Set eps bearer id
  act_def_eps_bearer_context_req.eps_bearer_id          = 5;
  act_def_eps_bearer_context_req.transaction_id_present = false;
  // set eps_qos
  act_def_eps_bearer_context_req.eps_qos.qci            = m_esm_ctx[5].qci;
  act_def_eps_bearer_context_req.eps_qos.br_present     = false;
  act_def_eps_bearer_context_req.eps_qos.br_ext_present = false;

  // set apn
  strncpy(act_def_eps_bearer_context_req.apn.apn, m_apn.c_str(), LIBLTE_STRING_LEN - 1);
  act_def_eps_bearer_context_req.proc_transaction_id = m_emm_ctx.procedure_transaction_id;

  // Set DNS server
  act_def_eps_bearer_context_req.protocol_cnfg_opts_present    = true;
  act_def_eps_bearer_context_req.protocol_cnfg_opts.N_opts     = 1;
  act_def_eps_bearer_context_req.protocol_cnfg_opts.opt[0].id  = 0x0d;
  act_def_eps_bearer_context_req.protocol_cnfg_opts.opt[0].len = 4;

  struct sockaddr_in dns_addr;
  inet_pton(AF_INET, m_dns.c_str(), &(dns_addr.sin_addr));
  memcpy(act_def_eps_bearer_context_req.protocol_cnfg_opts.opt[0].contents, &dns_addr.sin_addr.s_addr, 4);

  // Make sure all unused options are set to false
  act_def_eps_bearer_context_req.negotiated_qos_present    = false;
  act_def_eps_bearer_context_req.llc_sapi_present          = false;
  act_def_eps_bearer_context_req.radio_prio_present        = false;
  act_def_eps_bearer_context_req.packet_flow_id_present    = false;
  act_def_eps_bearer_context_req.apn_ambr_present          = false;
  act_def_eps_bearer_context_req.esm_cause_present         = false;
  act_def_eps_bearer_context_req.connectivity_type_present = false;

  uint8_t sec_hdr_type = 2;
  m_sec_ctx.dl_nas_count++;

  liblte_mme_pack_activate_default_eps_bearer_context_request_msg(&act_def_eps_bearer_context_req,
                                                                  &attach_accept.esm_msg);
  liblte_mme_pack_attach_accept_msg(
      &attach_accept, sec_hdr_type, m_sec_ctx.dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);


  cipher_encrypt(nas_buffer);
  // Integrity protect NAS message
  uint8_t mac[4];
  integrity_generate(nas_buffer, mac);
  
  memcpy(&nas_buffer->msg[1], mac, 4);

  // Log attach accept info
  m_nas_log->info("Packed Attach Accept\n");
  return true;
}

bool nas::handle_statelearner_query_reset_attach_accept_setup()
{
  msg_type_global = FUZZING_MSG_TYPE_EOL;
}

bool nas::pack_identity_request(srslte::byte_buffer_t* nas_buffer)
{
  m_nas_log->info("Packing Identity Request\n");

  LIBLTE_MME_ID_REQUEST_MSG_STRUCT id_req;
  id_req.id_type        = LIBLTE_MME_EPS_MOBILE_ID_TYPE_IMSI;
  LIBLTE_ERROR_ENUM err = liblte_mme_pack_identity_request_msg(&id_req, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error packing Identity Request\n");
    m_nas_log->console("Error packing Identity REquest\n");
    return false;
  }
  return true;
}
bool nas::pack_identity_request_mac(srslte::byte_buffer_t* nas_buffer)
{
  m_nas_log->info("Packing Identity Request\n");

  LIBLTE_MME_ID_REQUEST_MSG_STRUCT id_req;
  id_req.id_type       = LIBLTE_MME_EPS_MOBILE_ID_TYPE_IMSI;
  uint8_t sec_hdr_type = 2;
  m_sec_ctx.dl_nas_count++;
  LIBLTE_ERROR_ENUM err = liblte_mme_pack_identity_request_msg_mac(
      &id_req, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer, m_sec_ctx.dl_nas_count, sec_hdr_type);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error packing Identity Request\n");
    m_nas_log->console("Error packing Identity REquest\n");
    return false;
  }

  uint8_t mac[4];
  integrity_generate(nas_buffer, mac);
  memcpy(&nas_buffer->msg[1], mac, 4);
  return true;
}
bool nas::pack_identity_request_encrypt_mac(srslte::byte_buffer_t* nas_buffer)
{
  m_nas_log->info("Packing Identity Request\n");

  LIBLTE_MME_ID_REQUEST_MSG_STRUCT id_req;
  id_req.id_type       = LIBLTE_MME_EPS_MOBILE_ID_TYPE_IMSI;
  uint8_t sec_hdr_type = 2;
  m_sec_ctx.dl_nas_count++;
  LIBLTE_ERROR_ENUM err = liblte_mme_pack_identity_request_msg_mac(
      &id_req, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer, m_sec_ctx.dl_nas_count, sec_hdr_type);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error packing Identity Request\n");
    m_nas_log->console("Error packing Identity REquest\n");
    return false;
  }
  cipher_encrypt(nas_buffer);
  uint8_t mac[4];
  integrity_generate(nas_buffer, mac);
  memcpy(&nas_buffer->msg[1], mac, 4);
  return true;
}
bool nas::pack_dl_nas_transport(srslte::byte_buffer_t* nas_buffer)
{
  m_nas_log->info("Packing DL NAS Transport Request\n");

  LIBLTE_MME_DOWNLINK_NAS_TRANSPORT_MSG_STRUCT dl_nas_transport;
  int                                          size = 35;
  uint8_t                                      msg[size];
  msg[0] = 0x9;
  printf("Timestamp: %d\n", (int)time(NULL));
  int t  = (int)time(NULL);
  msg[1] = LIBLTE_MME_MSG_TYPE;
  msg[2] = 0x20;
  msg[3] = 0x1;
  msg[4] = 0x1;
  msg[5] = 0x7;
  msg[6] = 0x91;
  msg[7]  = 0x21;
  msg[8]  = 0x60;
  msg[9]  = 0x13;
  msg[10] = 0x03;
  msg[11] = 0x50;
  msg[12] = 0xf7;
  msg[13] = 0x0;
  msg[14] = 0x14;
  msg[15] = 0x04;
  msg[16] = 0xb;
  msg[17] = 0x11;
  msg[18] = 0x71;
  msg[19] = 0x56;
  msg[20] = 0x04;
  msg[21] = 0x79;
  msg[22] = 0x30;
  msg[23] = 0xf8;
  msg[24] = 0x0;
  msg[25] = 0x0;
  msg[26] = 0x91;
  msg[27] = 0x90;
  msg[28] = 0x82;
  msg[29] = 0x10;
  msg[30] = 0x45;
  msg[31] = 0x11;
  msg[32] = 0xa;
  msg[33] = 0x1;
  msg[34] = '1';

  dl_nas_transport.nas_msg.N_bytes = size;
  memcpy(&dl_nas_transport.nas_msg.msg, msg, size);
  // liblte_mme_pack_nas_message_container_ie(&dl_nas_transport.nas_msg, &msg);
  uint8_t sec_hdr_type = 2;
  m_sec_ctx.dl_nas_count++;
  LIBLTE_ERROR_ENUM err = liblte_mme_pack_downlink_nas_transport_msg(
      &dl_nas_transport, sec_hdr_type, m_sec_ctx.dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error packing Identity Request\n");
    m_nas_log->console("Error packing Identity REquest\n");
    return false;
  }
  cipher_encrypt(nas_buffer);
  uint8_t mac[4];
  integrity_generate(nas_buffer, mac);
  memcpy(&nas_buffer->msg[1], mac, 4);
  return true;
}
bool nas::pack_dl_nas_transport_plain(srslte::byte_buffer_t* nas_buffer)
{
  m_nas_log->info("Packing DL NAS Transport Request\n");

  LIBLTE_MME_DOWNLINK_NAS_TRANSPORT_MSG_STRUCT dl_nas_transport;
  int                                          size = 35;
  uint8_t                                      msg[size];
  msg[0] = 0x9;
  printf("Timestamp: %d\n", (int)time(NULL));
  int t  = (int)time(NULL);
  msg[1] = LIBLTE_MME_MSG_TYPE;
  msg[2] = 0x20;
  msg[3] = 0x1;
  msg[4] = 0x1;
  msg[5] = 0x7;
  msg[6] = 0x91;
  msg[7]  = 0x21;
  msg[8]  = 0x60;
  msg[9]  = 0x13;
  msg[10] = 0x03;
  msg[11] = 0x50;
  msg[12] = 0xf7;
  msg[13] = 0x0;
  msg[14] = 0x14;
  msg[15] = 0x04;
  msg[16] = 0xb;
  msg[17] = 0x11;
  msg[18] = 0x71;
  msg[19] = 0x56;
  msg[20] = 0x04;
  msg[21] = 0x79;
  msg[22] = 0x30;
  msg[23] = 0xf8;
  msg[24] = 0x0;
  msg[25] = 0x0;
  msg[26] = 0x91;
  msg[27] = 0x90;
  msg[28] = 0x82;
  msg[29] = 0x10;
  msg[30] = 0x45;
  msg[31] = 0x11;
  msg[32] = 0xa;
  msg[33] = 0x1;
  msg[34] = '1';
  dl_nas_transport.nas_msg.N_bytes = size;
  memcpy(&dl_nas_transport.nas_msg.msg, msg, size);
  uint8_t sec_hdr_type = 0;
  m_sec_ctx.dl_nas_count++;
  LIBLTE_ERROR_ENUM err = liblte_mme_pack_downlink_nas_transport_msg(
      &dl_nas_transport, sec_hdr_type, m_sec_ctx.dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error packing Identity Request\n");
    m_nas_log->console("Error packing Identity REquest\n");
    return false;
  }

  return true;
}
bool nas::pack_identity_request_replay(srslte::byte_buffer_t* nas_buffer)
{
  m_nas_log->info("Packing Identity Request\n");

  LIBLTE_MME_ID_REQUEST_MSG_STRUCT id_req;
  id_req.id_type       = LIBLTE_MME_EPS_MOBILE_ID_TYPE_IMSI;
  uint8_t sec_hdr_type = 2;
  LIBLTE_ERROR_ENUM err = liblte_mme_pack_identity_request_msg_mac(
      &id_req, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer, m_sec_ctx.dl_nas_count, sec_hdr_type);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error packing Identity Request\n");
    m_nas_log->console("Error packing Identity REquest\n");
    return false;
  }

  uint8_t mac[4];
  integrity_generate(nas_buffer, mac);
  memcpy(&nas_buffer->msg[1], mac, 4);
  return true;
}
bool nas::pack_identity_request_wrong_mac(srslte::byte_buffer_t* nas_buffer)
{
  m_nas_log->info("Packing Identity Request\n");

  LIBLTE_MME_ID_REQUEST_MSG_STRUCT id_req;
  id_req.id_type                 = LIBLTE_MME_EPS_MOBILE_ID_TYPE_IMSI;
  uint8_t           sec_hdr_type = 2;
  LIBLTE_ERROR_ENUM err          = liblte_mme_pack_identity_request_msg_mac(
      &id_req, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer, m_sec_ctx.dl_nas_count, sec_hdr_type);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error packing Identity Request\n");
    m_nas_log->console("Error packing Identity REquest\n");
    return false;
  }
  uint8_t mac[4];
  integrity_generate(nas_buffer, mac);
  /// Make the mac wrong//
  mac[0] = mac[0] + 1;
  memcpy(&nas_buffer->msg[1], mac, 4);
  return true;
}
bool nas::pack_emm_information(srslte::byte_buffer_t* nas_buffer)
{
  m_nas_log->info("Packing EMM Information\n");

  LIBLTE_MME_EMM_INFORMATION_MSG_STRUCT emm_info;
  emm_info.full_net_name_present = true;
  strncpy(emm_info.full_net_name.name, "Software Radio Systems LTE", LIBLTE_STRING_LEN);
  emm_info.full_net_name.add_ci   = LIBLTE_MME_ADD_CI_DONT_ADD;
  emm_info.short_net_name_present = true;
  strncpy(emm_info.short_net_name.name, "srsLTE", LIBLTE_STRING_LEN);
  emm_info.short_net_name.add_ci = LIBLTE_MME_ADD_CI_DONT_ADD;

  emm_info.local_time_zone_present         = false;
  emm_info.utc_and_local_time_zone_present = false;
  emm_info.net_dst_present                 = false;

  uint8_t sec_hdr_type = LIBLTE_MME_SECURITY_HDR_TYPE_INTEGRITY_AND_CIPHERED;
  m_sec_ctx.dl_nas_count++;
  LIBLTE_ERROR_ENUM err = liblte_mme_pack_emm_information_msg(
      &emm_info, sec_hdr_type, m_sec_ctx.dl_nas_count, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error packing EMM Information\n");
    m_nas_log->console("Error packing EMM Information\n");
    return false;
  }

  // Encrypt NAS message
  cipher_encrypt(nas_buffer);

  // Integrity protect NAS message
  uint8_t mac[4];
  integrity_generate(nas_buffer, mac);
  memcpy(&nas_buffer->msg[1], mac, 4);

  m_nas_log->info("Packed UE EMM information\n");
  return true;
}

bool nas::pack_service_reject(srslte::byte_buffer_t* nas_buffer, uint8_t emm_cause)
{
  LIBLTE_MME_SERVICE_REJECT_MSG_STRUCT service_rej;
  service_rej.t3442_present = true;
  service_rej.t3442.unit    = LIBLTE_MME_GPRS_TIMER_DEACTIVATED;
  service_rej.t3442.value   = 0;
  service_rej.t3446_present = true;
  service_rej.t3446         = 0;
  service_rej.emm_cause     = emm_cause;

  LIBLTE_ERROR_ENUM err = liblte_mme_pack_service_reject_msg(
      &service_rej, LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS, 0, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error packing Service Reject\n");
    m_nas_log->console("Error packing Service Reject\n");
    return false;
  }
  return true;
}
bool nas::pack_emm_information_plain(srslte::byte_buffer_t* nas_buffer)
{
  m_nas_log->info("Packing EMM Information\n");

  LIBLTE_MME_EMM_INFORMATION_MSG_STRUCT emm_info;
  emm_info.full_net_name_present = true;
  strncpy(emm_info.full_net_name.name, "Software Radio Systems LTE", LIBLTE_STRING_LEN);
  emm_info.full_net_name.add_ci   = LIBLTE_MME_ADD_CI_DONT_ADD;
  emm_info.short_net_name_present = true;
  strncpy(emm_info.short_net_name.name, "srsLTE", LIBLTE_STRING_LEN);
  emm_info.short_net_name.add_ci = LIBLTE_MME_ADD_CI_DONT_ADD;

  emm_info.local_time_zone_present         = false;
  emm_info.utc_and_local_time_zone_present = false;
  emm_info.net_dst_present                 = false;

  uint8_t sec_hdr_type = 0;
  m_sec_ctx.dl_nas_count++;

  LIBLTE_ERROR_ENUM err = liblte_mme_pack_emm_information_msg(&emm_info, sec_hdr_type, m_sec_ctx.dl_nas_count,
                                                              (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error packing EMM Information\n");
    m_nas_log->console("Error packing EMM Information\n");
    return false;
  }

  // Encrypt NAS message
  cipher_encrypt(nas_buffer);

  m_nas_log->info("Packed UE EMM information\n");
  return true;
}
bool nas::pack_tau_reject(srslte::byte_buffer_t* nas_buffer, uint8_t emm_cause)
{
  LIBLTE_MME_TRACKING_AREA_UPDATE_REJECT_MSG_STRUCT tau_rej;
  tau_rej.t3446_present = false;
  tau_rej.emm_cause = emm_cause;
  LIBLTE_ERROR_ENUM err = liblte_mme_pack_tracking_area_update_reject_msg(&tau_rej, LIBLTE_MME_SECURITY_HDR_TYPE_PLAIN_NAS, 0,
                                                                          (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error packing TAU Reject\n");
    m_nas_log->console("Error packing TAU Reject\n");
    return false;
  }
  return true;
}
/************************
 *
 * Security Functions
 *
 ************************/
bool nas::short_integrity_check(srslte::byte_buffer_t* pdu)
{
  uint8_t  exp_mac[4] = {0x00, 0x00, 0x00, 0x00};
  uint8_t* mac        = &pdu->msg[2];
  int      i;

  if (pdu->N_bytes < 4) {
    m_nas_log->warning("NAS message to short for short integrity check (pdu len: %d)", pdu->N_bytes);
    return false;
  }

  
  m_sec_ctx.ul_nas_count = pdu->msg[1];
  m_nas_log->console("UL Local: count=%d, Received: UL count=%d\n", m_sec_ctx.ul_nas_count, pdu->msg[1]);
  

  switch (m_sec_ctx.integ_algo) {
    case srslte::INTEGRITY_ALGORITHM_ID_EIA0:
      break;
    case srslte::INTEGRITY_ALGORITHM_ID_128_EIA1:
      srslte::security_128_eia1(
          &m_sec_ctx.k_nas_int[16], m_sec_ctx.ul_nas_count, 0, SECURITY_DIRECTION_UPLINK, &pdu->msg[0], 2, &exp_mac[0]);
      break;
    case srslte::INTEGRITY_ALGORITHM_ID_128_EIA2:
      srslte::security_128_eia2(
          &m_sec_ctx.k_nas_int[16], m_sec_ctx.ul_nas_count, 0, SECURITY_DIRECTION_UPLINK, &pdu->msg[0], 2, &exp_mac[0]);
      break;
    default:
      break;
  }
  // Check if expected mac equals the sent mac
  for (i = 0; i < 2; i++) {
    if (exp_mac[i + 2] != mac[i]) {
      m_nas_log->warning("Short integrity check failure. Local: count=%d, [%02x %02x %02x %02x], "
                         "Received: count=%d, [%02x %02x]\n",
                         m_sec_ctx.ul_nas_count,
                         exp_mac[0],
                         exp_mac[1],
                         exp_mac[2],
                         exp_mac[3],
                         pdu->msg[1] & 0x1F,
                         mac[0],
                         mac[1]);
      return false;
    }
  }
  m_nas_log->info(
      "Integrity check ok. Local: count=%d, Received: count=%d\n", m_sec_ctx.ul_nas_count, pdu->msg[1] & 0x1F);
  return true;
}

bool nas::integrity_check(srslte::byte_buffer_t* pdu)
{
  uint8_t  exp_mac[4] = {0x00, 0x00, 0x00, 0x00};
  uint8_t* mac        = &pdu->msg[1];
  int      i;

  
  m_sec_ctx.ul_nas_count = pdu->msg[5];
  m_nas_log->console("UL Local: count=%d, Received: UL count=%d\n", m_sec_ctx.ul_nas_count, pdu->msg[5]);
  

  switch (m_sec_ctx.integ_algo) {
    case srslte::INTEGRITY_ALGORITHM_ID_EIA0:
      break;
    case srslte::INTEGRITY_ALGORITHM_ID_128_EIA1:
      srslte::security_128_eia1(&m_sec_ctx.k_nas_int[16],
                                m_sec_ctx.ul_nas_count,
                                0,
                                SECURITY_DIRECTION_UPLINK,
                                &pdu->msg[5],
                                pdu->N_bytes - 5,
                                &exp_mac[0]);
      break;
    case srslte::INTEGRITY_ALGORITHM_ID_128_EIA2:
      srslte::security_128_eia2(&m_sec_ctx.k_nas_int[16],
                                m_sec_ctx.ul_nas_count,
                                0,
                                SECURITY_DIRECTION_UPLINK,
                                &pdu->msg[5],
                                pdu->N_bytes - 5,
                                &exp_mac[0]);
      break;
    default:
      break;
  }
  // Check if expected mac equals the sent mac
  for (i = 0; i < 4; i++) {
    if (exp_mac[i] != mac[i]) {
      m_nas_log->warning("Integrity check failure. Algorithm=EIA%d\n", (int)m_sec_ctx.integ_algo);
      m_nas_log->warning("UL Local: count=%d, MAC=[%02x %02x %02x %02x], "
                         "Received: UL count=%d, MAC=[%02x %02x %02x %02x]\n",
                         m_sec_ctx.ul_nas_count,
                         exp_mac[0],
                         exp_mac[1],
                         exp_mac[2],
                         exp_mac[3],
                         pdu->msg[5],
                         mac[0],
                         mac[1],
                         mac[2],
                         mac[3]);
      m_nas_log->console("Integrity check failure. UL Local: count=%d, [%02x %02x %02x %02x], "
                         "Received: UL count=%d, [%02x %02x %02x %02x]\n",
                         m_sec_ctx.ul_nas_count,
                         exp_mac[0],
                         exp_mac[1],
                         exp_mac[2],
                         exp_mac[3],
                         pdu->msg[5],
                         mac[0],
                         mac[1],
                         mac[2],
                         mac[3]);

      return false;
    }
  }
  m_nas_log->info("Integrity check ok. Local: count=%d, Received: count=%d\n", m_sec_ctx.ul_nas_count, pdu->msg[5]);
  return true;
}

void nas::integrity_generate(srslte::byte_buffer_t* pdu, uint8_t* mac)
{
  switch (m_sec_ctx.integ_algo) {
    case srslte::INTEGRITY_ALGORITHM_ID_EIA0:
      break;
    case srslte::INTEGRITY_ALGORITHM_ID_128_EIA1:
      srslte::security_128_eia1(&m_sec_ctx.k_nas_int[16],
                                m_sec_ctx.dl_nas_count,
                                0, // Bearer always 0 for NAS
                                SECURITY_DIRECTION_DOWNLINK,
                                &pdu->msg[5],
                                pdu->N_bytes - 5,
                                mac);
      break;
    case srslte::INTEGRITY_ALGORITHM_ID_128_EIA2:
      srslte::security_128_eia2(&m_sec_ctx.k_nas_int[16],
                                m_sec_ctx.dl_nas_count,
                                0, // Bearer always 0 for NAS
                                SECURITY_DIRECTION_DOWNLINK,
                                &pdu->msg[5],
                                pdu->N_bytes - 5,
                                mac);
      break;
    default:
      break;
  }
  m_nas_log->console("Generating MAC with inputs: Algorithm %s, DL COUNT %d\n",
                     srslte::integrity_algorithm_id_text[m_sec_ctx.integ_algo],
                     m_sec_ctx.dl_nas_count);
}

void nas::cipher_decrypt(srslte::byte_buffer_t* pdu)
{
  srslte::byte_buffer_t tmp_pdu;
  switch (m_sec_ctx.cipher_algo) {
    case srslte::CIPHERING_ALGORITHM_ID_EEA0:
      break;
    case srslte::CIPHERING_ALGORITHM_ID_128_EEA1:
      srslte::security_128_eea1(&m_sec_ctx.k_nas_enc[16],
                                pdu->msg[5],
                                0, // Bearer always 0 for NAS
                                SECURITY_DIRECTION_UPLINK,
                                &pdu->msg[6],
                                pdu->N_bytes - 6,
                                &tmp_pdu.msg[6]);
      memcpy(&pdu->msg[6], &tmp_pdu.msg[6], pdu->N_bytes - 6);
      m_nas_log->debug_hex(tmp_pdu.msg, pdu->N_bytes, "Decrypted");
      break;
    case srslte::CIPHERING_ALGORITHM_ID_128_EEA2:
      srslte::security_128_eea2(&m_sec_ctx.k_nas_enc[16],
                                pdu->msg[5],
                                0, // Bearer always 0 for NAS
                                SECURITY_DIRECTION_UPLINK,
                                &pdu->msg[6],
                                pdu->N_bytes - 6,
                                &tmp_pdu.msg[6]);
      m_nas_log->debug_hex(tmp_pdu.msg, pdu->N_bytes, "Decrypted");
      memcpy(&pdu->msg[6], &tmp_pdu.msg[6], pdu->N_bytes - 6);
      break;
    default:
      m_nas_log->error("Ciphering algorithms not known\n");
      break;
  }
}
bool check(uint8_t* key)
{
  if (key[0] == 0 && key[1] == 0 && key[2] == 0) {
    printf(" caught!!\n ");
    return true;
  }
  return false;
}

void nas::cipher_encrypt(srslte::byte_buffer_t* pdu)
{

  srslte::byte_buffer_t pdu_tmp;
  switch (m_sec_ctx.cipher_algo) {
    case srslte::CIPHERING_ALGORITHM_ID_EEA0:
      break;
    case srslte::CIPHERING_ALGORITHM_ID_128_EEA1:
      srslte::security_128_eea1(&m_sec_ctx.k_nas_enc[16],
                                pdu->msg[5],
                                0, // Bearer always 0 for NAS
                                SECURITY_DIRECTION_DOWNLINK,
                                &pdu->msg[6],
                                pdu->N_bytes - 6,
                                &pdu_tmp.msg[6]);
      // m_nas_log->console("Encrypted 2");
      memcpy(&pdu->msg[6], &pdu_tmp.msg[6], pdu->N_bytes - 6);
      m_nas_log->debug_hex(pdu_tmp.msg, pdu->N_bytes, "Encrypted");
      // m_nas_log->console("Encrypted");
      break;
    case srslte::CIPHERING_ALGORITHM_ID_128_EEA2:
      srslte::security_128_eea2(&m_sec_ctx.k_nas_enc[16],
                                pdu->msg[5],
                                0, // Bearer always 0 for NAS
                                SECURITY_DIRECTION_DOWNLINK,
                                &pdu->msg[6],
                                pdu->N_bytes - 6,
                                &pdu_tmp.msg[6]);
      memcpy(&pdu->msg[6], &pdu_tmp.msg[6], pdu->N_bytes - 6);
      m_nas_log->debug_hex(pdu_tmp.msg, pdu->N_bytes, "Encrypted");
      break;
    default:
      m_nas_log->error("Ciphering algorithm not known\n");
      break;
  }
}

/**************************
 *
 * Timer related functions
 *
 **************************/
bool nas::start_timer(enum nas_timer_type type)
{
  m_nas_log->debug("Starting NAS timer\n");
  bool err = false;
  switch (type) {
    case T_3413:
      err = start_t3413();
      break;
    default:
      m_nas_log->error("Invalid timer type\n");
  }
  return err;
}

bool nas::expire_timer(enum nas_timer_type type)
{
  m_nas_log->debug("NAS timer expired\n");
  bool err = false;
  switch (type) {
    case T_3413:
      err = expire_t3413();
      break;
    default:
      m_nas_log->error("Invalid timer type\n");
  }
  return err;
}

// T3413 -> Paging timer
bool nas::start_t3413()
{
  m_nas_log->info("Starting T3413 Timer: Timeout value %d\n", m_t3413);
  if (m_emm_ctx.state != EMM_STATE_REGISTERED) {
    m_nas_log->error("EMM invalid status to start T3413\n");
    return false;
  }

  int fdt = timerfd_create(CLOCK_MONOTONIC, 0);
  if (fdt < 0) {
    m_nas_log->error("Error creating timer. %s\n", strerror(errno));
    return false;
  }
  struct itimerspec t_value;
  t_value.it_value.tv_sec     = m_t3413;
  t_value.it_value.tv_nsec    = 0;
  t_value.it_interval.tv_sec  = 0;
  t_value.it_interval.tv_nsec = 0;

  if (timerfd_settime(fdt, 0, &t_value, NULL) == -1) {
    m_nas_log->error("Could not set timer\n");
    close(fdt);
    return false;
  }

  m_mme->add_nas_timer(fdt, T_3413, m_emm_ctx.imsi);
  return true;
}

bool nas::expire_t3413()
{
  m_nas_log->info("T3413 expired -- Could not page the ue.\n");
  m_nas_log->console("T3413 expired -- Could not page the ue.\n");
  if (m_emm_ctx.state != EMM_STATE_REGISTERED) {
    m_nas_log->error("EMM invalid status upon T3413 expiration\n");
    return false;
  }
  // Send Paging Failure to the SPGW
  m_gtpc->send_downlink_data_notification_failure_indication(m_emm_ctx.imsi,
                                                             srslte::GTPC_CAUSE_VALUE_UE_NOT_RESPONDING);
  return true;
}


bool nas::handle_statelearner_query_authentication_request()
{

  srslte::byte_buffer_t* nas_tx;
  // Get Authentication Vectors from HSS
  
  if (!m_hss->gen_auth_info_answer(
      m_emm_ctx.imsi, m_sec_ctx.k_asme_tmp, m_sec_ctx.autn, m_sec_ctx.rand, m_sec_ctx.xres)) {
    m_nas_log->console("User not found. IMSI %015" PRIu64 "\n", m_emm_ctx.imsi);
    m_nas_log->info("User not found. IMSI %015" PRIu64 "\n", m_emm_ctx.imsi);
    return false;
  }

  // Allocate eKSI for this authentication vector
  // Here we assume a new security context thus a new eKSI
  m_sec_ctx.eksi = 0;

  // Save the UE context
  m_s1ap->add_nas_ctx_to_imsi_map(this);
  m_s1ap->add_nas_ctx_to_mme_ue_s1ap_id_map(this);
  m_s1ap->add_ue_to_enb_set(m_ecm_ctx.enb_sri.sinfo_assoc_id, m_ecm_ctx.mme_ue_s1ap_id);

  // Pack NAS Authentication Request in Downlink NAS Transport msg
  nas_tx = m_pool->allocate();

  pack_authentication_request(nas_tx);

  // Send reply to eNB
  auth_replay_buffer = m_pool->allocate();
  auth_replay_buffer = nas_tx;
  m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);


  m_nas_log->info("Downlink NAS: Sending Authentication Request\n");
  m_nas_log->console("Downlink NAS: Sending Authentication Request\n");
  return true;
}

bool nas::handle_statelearner_query_authentication_request_encrypt()
{

  srslte::byte_buffer_t* nas_tx;
  // Get Authentication Vectors from HSS
  if (!m_hss->gen_auth_info_answer(m_emm_ctx.imsi, m_sec_ctx.k_asme, m_sec_ctx.autn, m_sec_ctx.rand, m_sec_ctx.xres)) {
    m_nas_log->console("User not found. IMSI %015" PRIu64 "\n", m_emm_ctx.imsi);
    m_nas_log->info("User not found. IMSI %015" PRIu64 "\n", m_emm_ctx.imsi);
    return false;
  }

  // Allocate eKSI for this authentication vector
  // Here we assume a new security context thus a new eKSI
  m_sec_ctx.eksi = 0;

  // Save the UE context
  m_s1ap->add_nas_ctx_to_imsi_map(this);
  m_s1ap->add_nas_ctx_to_mme_ue_s1ap_id_map(this);
  m_s1ap->add_ue_to_enb_set(m_ecm_ctx.enb_sri.sinfo_assoc_id, m_ecm_ctx.mme_ue_s1ap_id);

  // Pack NAS Authentication Request in Downlink NAS Transport msg
  nas_tx = m_pool->allocate();
  pack_authentication_request(nas_tx);
  cipher_encrypt(nas_tx);
  // Send reply to eNB
  m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);
  m_pool->deallocate(nas_tx);

  m_nas_log->info("Downlink NAS: Sending Authentication Request\n");
  m_nas_log->console("Downlink NAS: Sending Authentication Request\n");
  return true;
}

bool nas::handle_statelearner_query_authentication_request_mac()
{

  srslte::byte_buffer_t* nas_tx;
  // Get Authentication Vectors from HSS
  if (!m_hss->gen_auth_info_answer(m_emm_ctx.imsi, m_sec_ctx.k_asme, m_sec_ctx.autn, m_sec_ctx.rand, m_sec_ctx.xres)) {
    m_nas_log->console("User not found. IMSI %015" PRIu64 "\n", m_emm_ctx.imsi);
    m_nas_log->info("User not found. IMSI %015" PRIu64 "\n", m_emm_ctx.imsi);
    return false;
  }

  // Allocate eKSI for this authentication vector
  // Here we assume a new security context thus a new eKSI
  m_sec_ctx.eksi = 0;

  // Save the UE context
  m_s1ap->add_nas_ctx_to_imsi_map(this);
  m_s1ap->add_nas_ctx_to_mme_ue_s1ap_id_map(this);
  m_s1ap->add_ue_to_enb_set(m_ecm_ctx.enb_sri.sinfo_assoc_id, m_ecm_ctx.mme_ue_s1ap_id);

  // Pack NAS Authentication Request in Downlink NAS Transport msg
  nas_tx = m_pool->allocate();
  pack_authentication_request_mac(nas_tx);

  // Send reply to eNB
  m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);
  m_pool->deallocate(nas_tx);

  m_nas_log->info("Downlink NAS: Sending Authentication Request\n");
  m_nas_log->console("Downlink NAS: Sending Authentication Request\n");
  return true;
}
bool nas::handle_statelearner_query_authentication_request_replay()
{

  srslte::byte_buffer_t* nas_tx;

  // Save the UE context
  m_s1ap->add_nas_ctx_to_imsi_map(this);
  m_s1ap->add_nas_ctx_to_mme_ue_s1ap_id_map(this);
  m_s1ap->add_ue_to_enb_set(m_ecm_ctx.enb_sri.sinfo_assoc_id, m_ecm_ctx.mme_ue_s1ap_id);

  // Pack NAS Authentication Request in Downlink NAS Transport msg

  if (auth_replay_buffer == NULL) {
    m_nas_log->console("*******Replayed authentication request not sending!************\n");
    return true;
  } else {
    // Send reply to eNB
    m_s1ap->send_downlink_nas_transport(
        m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, auth_replay_buffer, m_ecm_ctx.enb_sri);

    m_nas_log->info("Downlink NAS: Sending Authentication Request Replayed\n");
    m_nas_log->console("Downlink NAS: Sending Authentication Request Replayed\n");
  }
  return true;
}
bool nas::handle_statelearner_query_authentication_request_encrypt_mac()
{
  if (check(&m_sec_ctx.k_nas_enc[16])) {
    if (m_s1ap->get_mme_statelearner_reset_state() == false && m_enable_ue_state_fuzzing == true) {
      m_nas_log->console("********portected auth_request not sending!!************\n");
      return true;
    }
  } else {
    srslte::byte_buffer_t* nas_tx;
    // Get Authentication Vectors from HSS
    if (!m_hss->gen_auth_info_answer(
        m_emm_ctx.imsi, m_sec_ctx.k_asme, m_sec_ctx.autn, m_sec_ctx.rand, m_sec_ctx.xres)) {
      m_nas_log->console("User not found. IMSI %015" PRIu64 "\n", m_emm_ctx.imsi);
      m_nas_log->info("User not found. IMSI %015" PRIu64 "\n", m_emm_ctx.imsi);
      return false;
    }

    // Allocate eKSI for this authentication vector
    // Here we assume a new security context thus a new eKSI
    m_sec_ctx.eksi = 0;

    // Save the UE context
    m_s1ap->add_nas_ctx_to_imsi_map(this);
    m_s1ap->add_nas_ctx_to_mme_ue_s1ap_id_map(this);
    m_s1ap->add_ue_to_enb_set(m_ecm_ctx.enb_sri.sinfo_assoc_id, m_ecm_ctx.mme_ue_s1ap_id);

    // Pack NAS Authentication Request in Downlink NAS Transport msg
    nas_tx = m_pool->allocate();
    pack_authentication_request_encrypt_mac(nas_tx);
    auth_replay_buffer = nas_tx;
    // Send reply to eNB
    m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);

    m_nas_log->info("Downlink NAS: Sending Authentication Request\n");
    m_nas_log->console("Downlink NAS: Sending Authentication Request\n");
    return true;
  }
}
bool nas::handle_statelearner_query_authentication_request_wmac()
{

  srslte::byte_buffer_t* nas_tx;
  // Get Authentication Vectors from HSS
  if (!m_hss->gen_auth_info_answer(m_emm_ctx.imsi, m_sec_ctx.k_asme, m_sec_ctx.autn, m_sec_ctx.rand, m_sec_ctx.xres)) {
    m_nas_log->console("User not found. IMSI %015" PRIu64 "\n", m_emm_ctx.imsi);
    m_nas_log->info("User not found. IMSI %015" PRIu64 "\n", m_emm_ctx.imsi);
    return false;
  }

  // Allocate eKSI for this authentication vector
  // Here we assume a new security context thus a new eKSI
  m_sec_ctx.eksi = 0;

  // Save the UE context
  m_s1ap->add_nas_ctx_to_imsi_map(this);
  m_s1ap->add_nas_ctx_to_mme_ue_s1ap_id_map(this);
  m_s1ap->add_ue_to_enb_set(m_ecm_ctx.enb_sri.sinfo_assoc_id, m_ecm_ctx.mme_ue_s1ap_id);

  // Pack NAS Authentication Request in Downlink NAS Transport msg
  nas_tx = m_pool->allocate();
  pack_authentication_request_wmac(nas_tx);

  // Send reply to eNB
  m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);
  m_pool->deallocate(nas_tx);

  m_nas_log->info("Downlink NAS: Sending Authentication Request\n");
  m_nas_log->console("Downlink NAS: Sending Authentication Request\n");
  return true;
}

bool nas::handle_statelearner_query_authentication_reject()
{

  srslte::byte_buffer_t* nas_tx;
  bool                   ret = false;

  nas_tx = m_pool->allocate();
  pack_authentication_reject(nas_tx);

  // Send reply
  m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);
  m_pool->deallocate(nas_tx);
  return true;
}

bool nas::handle_statelearner_query_attach_reject()
{

  srslte::byte_buffer_t* nas_tx;
  bool                   ret = false;

  nas_tx = m_pool->allocate();
  pack_attach_reject(nas_tx, LIBLTE_MME_EMM_CAUSE_PLMN_NOT_ALLOWED);

  // Send reply
  m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);
  m_pool->deallocate(nas_tx);
  return true;
}

bool nas::handle_statelearner_query_identity_request()
{

  srslte::byte_buffer_t* nas_tx;
  bool                   ret = false;
  nas_tx                     = m_pool->allocate();
  pack_identity_request(nas_tx);
  printf("Size of nas_tx in identity_request %d\n", sizeof(nas_tx));
  identity_replay_buffer = m_pool->allocate();
  identity_replay_buffer = nas_tx;

  m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);

  return true;
}
bool nas::handle_statelearner_query_identity_request_mac()
{

  srslte::byte_buffer_t* nas_tx;
  bool                   ret = false;

  nas_tx = m_pool->allocate();
  pack_identity_request_mac(nas_tx);
  m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);
  m_pool->deallocate(nas_tx);

  return true;
}
bool nas::handle_statelearner_query_identity_request_encrypt_mac()
{
  if (check(&m_sec_ctx.k_nas_enc[16])) {
    if (m_s1ap->get_mme_statelearner_reset_state() == false && m_enable_ue_state_fuzzing == true) {

      m_nas_log->console("********protected identity request not sending!!************\n");
      return true;
    }
  } else {

    srslte::byte_buffer_t* nas_tx;
    bool                   ret = false;

    nas_tx = m_pool->allocate();
    pack_identity_request_encrypt_mac(nas_tx);
    m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);
    m_pool->deallocate(nas_tx);

    return true;
  }
}
bool nas::handle_statelearner_query_dl_nas_transport()
{
  if (check(&m_sec_ctx.k_nas_enc[16])) {
    if (m_s1ap->get_mme_statelearner_reset_state() == false && m_enable_ue_state_fuzzing == true) {

      m_nas_log->console("********dl_nas_transport not sending!!************\n");
      return true;
    }
  } else {

    srslte::byte_buffer_t* nas_tx;
    bool                   ret = false;

    nas_tx = m_pool->allocate();
    pack_dl_nas_transport(nas_tx);
    m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);
    dl_replay_buffer = nas_tx;
    return true;
  }
  return false;
}
bool nas::handle_statelearner_query_dl_nas_transport_replay()
{
  if (dl_replay_buffer == NULL) {

    m_nas_log->console("*******Replayed dl_nas_transport request not sending!************\n");
    return true;
  } else {
    bool ret = false;
    m_nas_log->console("*******Sending replayed dl_nas_transport request!************\n");
    m_s1ap->send_downlink_nas_transport(
        m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, dl_replay_buffer, m_ecm_ctx.enb_sri);

    return true;
  }
}
bool nas::handle_statelearner_query_dl_nas_transport_plain()
{
  if (check(&m_sec_ctx.k_nas_enc[16])) {
    if (m_s1ap->get_mme_statelearner_reset_state() == false && m_enable_ue_state_fuzzing == true) {
      m_nas_log->console("********dl_nas_transport not sending!!************\n");
      return true;
    }
  } else {

    srslte::byte_buffer_t* nas_tx;
    bool                   ret = false;

    nas_tx = m_pool->allocate();
    pack_dl_nas_transport_plain(nas_tx);
    m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);
    m_pool->deallocate(nas_tx);

    return true;
  }
  return false;
}
bool nas::handle_statelearner_query_identity_request_replay()
{
  if (identity_replay_buffer == NULL) {

    m_nas_log->console("********replayed identity  request not sending!!************\n");
    return true;
  } else {

    m_s1ap->send_downlink_nas_transport(
        m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, identity_replay_buffer, m_ecm_ctx.enb_sri);

    return true;
  }
}
bool nas::pack_identity_request(srslte::byte_buffer_t* nas_buffer, uint8_t id_type)
{
  m_nas_log->info("Packing Identity Request\n");

  LIBLTE_MME_ID_REQUEST_MSG_STRUCT id_req;
  id_req.id_type        = id_type; //LIBLTE_MME_EPS_MOBILE_ID_TYPE_IMSI;
  LIBLTE_ERROR_ENUM err = liblte_mme_pack_identity_request_msg(&id_req, (LIBLTE_BYTE_MSG_STRUCT*)nas_buffer);
  if (err != LIBLTE_SUCCESS) {
    m_nas_log->error("Error packing Identity Request\n");
    m_nas_log->console("Error packing Identity REquest\n");
    return false;
  }
  return true;
}
bool nas::handle_statelearner_query_identity_request_wrong_mac()
{

  srslte::byte_buffer_t* nas_tx;
  bool                   ret = false;

  nas_tx = m_pool->allocate();
  pack_identity_request_wrong_mac(nas_tx);
  m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);
  m_pool->deallocate(nas_tx);

  return true;
}
bool nas::handle_statelearner_query_identity_request_encrypt()
{

  srslte::byte_buffer_t* nas_tx;
  bool                   ret = false;

  nas_tx = m_pool->allocate();

  pack_identity_request(nas_tx);
  if (check(m_sec_ctx.k_nas_enc)) {
    nas_tx->msg[1] = 0;
    nas_tx->msg[2] = 0;
  } else {
    cipher_encrypt(nas_tx);
  }
  m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);

  m_pool->deallocate(nas_tx);

  return true;
}
bool nas::handle_statelearner_query_security_mode_command()
{

  srslte::byte_buffer_t* nas_tx;
  bool                   ret = false;

  nas_tx                 = m_pool->allocate();
  m_sec_ctx.dl_nas_count = 0; // Reset the NAS uplink counter for the right key k_enb derivation
  pack_security_mode_command(nas_tx);
  smd_replay_buffer = m_pool->allocate();
  smd_replay_buffer = nas_tx;
  m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);

  return true;
}

bool nas::handle_statelearner_query_security_mode_command_ns()
{

  srslte::byte_buffer_t* nas_tx;
  bool                   ret = false;

  nas_tx                 = m_pool->allocate();
  m_sec_ctx.dl_nas_count++; // Reset the NAS uplink counter for the right key k_enb derivation
  pack_security_mode_command(nas_tx);
  smd_ns_replay_buffer = m_pool->allocate();
  smd_ns_replay_buffer = nas_tx;
  m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);

  return true;
}
bool nas::handle_statelearner_query_security_mode_command_ns_replay()
{
  if (smd_ns_replay_buffer == NULL) {
   
    m_nas_log->console("********replayed smd NS not sending!!************\n");
    return true;
  } else {
    bool ret = false;

    m_s1ap->send_downlink_nas_transport(
        m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, smd_ns_replay_buffer, m_ecm_ctx.enb_sri);
    return true;
  }
}


bool nas::handle_statelearner_query_security_mode_command_plain()
{

  srslte::byte_buffer_t* nas_tx;
  bool                   ret = false;

  nas_tx                 = m_pool->allocate();
  m_sec_ctx.dl_nas_count = 0; // Reset the NAS uplink counter for the right key k_enb derivation
  pack_security_mode_command_plain(nas_tx);
  m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);

  return true;
}
bool nas::handle_statelearner_query_security_mode_command_no_integrity()
{

  srslte::byte_buffer_t* nas_tx;
  bool                   ret = false;

  nas_tx                 = m_pool->allocate();
  m_sec_ctx.dl_nas_count = 0; // Reset the NAS uplink counter for the right key k_enb derivation
  pack_security_mode_command_no_integrity(nas_tx);

  m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);

  return true;
}
bool nas::handle_statelearner_query_security_mode_command_replay()
{
  if (smd_replay_buffer == NULL) {

    m_nas_log->console("********replayed smd not sending!!************\n");
    return true;
  } else {
    bool ret = false;

    m_sec_ctx.dl_nas_count = 0; // Reset the NAS uplink counter for the right key k_enb derivation

    m_s1ap->send_downlink_nas_transport(
        m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, smd_replay_buffer, m_ecm_ctx.enb_sri);

    return true;
  }
}
bool nas::handle_statelearner_query_rrc_security_mode_command_replay(uint8_t msg_type)
{
  if (check(&m_sec_ctx.k_nas_enc[16])) {
    if (m_s1ap->get_mme_statelearner_reset_state() == false && m_enable_ue_state_fuzzing == true) {
      m_nas_log->console("********rrc_security_mode_command not sending!!************\n");
      return true;
    }
  } else {

    bool ret = false;
    uint8_t default_bearer = 5;
    m_hss->gen_update_loc_answer(m_emm_ctx.imsi, &m_esm_ctx[default_bearer].qci);
    m_nas_log->debug("Getting subscription information -- QCI %d\n", m_esm_ctx[default_bearer].qci);
    m_nas_log->console("Getting subscription information -- QCI %d\n", m_esm_ctx[default_bearer].qci);
    // This means that GTP-U tunnels are created with function calls, as opposed to GTP-C.
    m_gtpc->send_create_session_request_replay(m_emm_ctx.imsi);
    m_nas_log->console("Downlink NAS: Sending NAS ATTACH ACCEPT Message.\n");
  }
  return true;
}

bool nas::handle_statelearner_query_rrc_security_mode_command_downgraded(uint8_t msg_type)
{
  if (check(&m_sec_ctx.k_nas_enc[16])) {
    if (m_s1ap->get_mme_statelearner_reset_state() == false && m_enable_ue_state_fuzzing == true) {
      m_nas_log->console("********rrc_security_mode_command not sending!!************\n");
      return true;
    }
  } else {
    bool ret = false;

    uint8_t default_bearer = 5;
    m_hss->gen_update_loc_answer(m_emm_ctx.imsi, &m_esm_ctx[default_bearer].qci);
    m_nas_log->debug("Getting subscription information -- QCI %d\n", m_esm_ctx[default_bearer].qci);
    m_nas_log->console("Getting subscription information -- QCI %d\n", m_esm_ctx[default_bearer].qci);
    // This means that GTP-U tunnels are created with function calls, as opposed to GTP-C.
    m_gtpc->send_create_session_request_downgraded(m_emm_ctx.imsi);
    m_nas_log->console("Downlink NAS: Sending NAS ATTACH ACCEPT Message.\n");
    }
    return true;
}

bool nas::handle_statelearner_query_attach_accept(uint8_t msg_type)
{

  if (check(&m_sec_ctx.k_nas_enc[16])) {
    if (m_s1ap->get_mme_statelearner_reset_state() == false && m_enable_ue_state_fuzzing == true) {

      m_nas_log->console("********rrc_security_mode_command not sending!!************\n");
      return true;
    }
  } else {
    bool ret = false;

    uint8_t default_bearer = 5;
    m_hss->gen_update_loc_answer(m_emm_ctx.imsi, &m_esm_ctx[default_bearer].qci);
    m_nas_log->debug("Getting subscription information -- QCI %d\n", m_esm_ctx[default_bearer].qci);
    m_nas_log->console("Getting subscription information -- QCI %d\n", m_esm_ctx[default_bearer].qci);
    m_gtpc->send_create_session_request(m_emm_ctx.imsi);
    m_nas_log->console("Downlink NAS: Sending NAS ATTACH ACCEPT Message.\n");
    
  }
    return true;
}
bool nas::handle_statelearner_query_guti_rellocation()
{


  srslte::byte_buffer_t* nas_tx;
  bool                   ret = false;

  nas_tx = m_pool->allocate();
  pack_guti_rellocation_request(nas_tx);
  guti_replay_buffer = nas_tx;
  m_nas_log->console("Downlink NAS: Sending NAS GUTI REALLOCATION Message.\n");
  m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);

  return true;
}
bool nas::handle_statelearner_query_guti_rellocation_replay()
{


  if (guti_replay_buffer == NULL) {
    m_nas_log->console("********replayed guti reallocation not sending!!************\n");
    return true;
  } else {
    srslte::byte_buffer_t* nas_tx;
    bool                   ret = false;


    m_nas_log->console("Downlink NAS: Sending Replayed NAS GUTI REALLOCATION Message.\n");
    m_s1ap->send_downlink_nas_transport(
        m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, guti_replay_buffer, m_ecm_ctx.enb_sri);

    return true;
  }
}
bool nas::handle_statelearner_query_guti_rellocation_plain()
{

  srslte::byte_buffer_t* nas_tx;
  bool                   ret = false;

  nas_tx = m_pool->allocate();
  pack_guti_rellocation_request_plain(nas_tx);
  m_nas_log->console("Downlink NAS: Sending NAS GUTI REALLOCATION Message.\n");
  m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);
  m_pool->deallocate(nas_tx);

  return true;
}
bool nas::handle_statelearner_query_tau_accept()
{
  if (check(&m_sec_ctx.k_nas_enc[16])) {
    if (m_s1ap->get_mme_statelearner_reset_state() == false && m_enable_ue_state_fuzzing == true) {
      m_nas_log->console("********tau accept not sending!!************\n");
      return true;
    }
  } else {
    srslte::byte_buffer_t* nas_tx;
    bool                   ret = false;

    nas_tx = m_pool->allocate();

    pack_tau_accept(nas_tx);
    m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);
    m_pool->deallocate(nas_tx);

    return true;
  }
  return false;
}
bool nas::handle_statelearner_query_tau_accept_plain()
{
  if (check(&m_sec_ctx.k_nas_enc[16])) {
    if (m_s1ap->get_mme_statelearner_reset_state() == false && m_enable_ue_state_fuzzing == true) {
      m_nas_log->console("********tau accept not sending!!************\n");
      return true;
    }
  } else {
    srslte::byte_buffer_t* nas_tx;
    bool                   ret = false;

    nas_tx = m_pool->allocate();

    pack_tau_accept_plain(nas_tx);
    m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);
    m_pool->deallocate(nas_tx);

    return true;
  }
  return false;
}
bool nas::handle_statelearner_query_attach_accept_single()
{
  if (check(&m_sec_ctx.k_nas_enc[16])) {
    if (m_s1ap->get_mme_statelearner_reset_state() == false && m_enable_ue_state_fuzzing == true) {
      m_nas_log->console("********attach accept not sending!!************\n");
      return true;
    }
  } else {

    srslte::byte_buffer_t* nas_tx;
    bool                   ret = false;

    nas_tx = m_pool->allocate();

    pack_attach_accept(nas_tx);
    m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);
    m_pool->deallocate(nas_tx);

    return true;
  }
}
bool nas::handle_statelearner_query_attach_accept_single_no_integrity()
{
  if (check(&m_sec_ctx.k_nas_enc[16])) {
    if (m_s1ap->get_mme_statelearner_reset_state() == false && m_enable_ue_state_fuzzing == true) {
      m_nas_log->console("********attach accept not sending!!************\n");
      return true;
    }
  } else {

    srslte::byte_buffer_t* nas_tx;
    bool                   ret = false;

    nas_tx = m_pool->allocate();

    pack_attach_accept_no_integrity(nas_tx);
    m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);
    m_pool->deallocate(nas_tx);

    return true;
  }
}

bool nas::handle_statelearner_query_emm_information_plain() {

  srslte::byte_buffer_t*            nas_tx;
  bool ret = false;

  nas_tx = m_pool->allocate();

  pack_emm_information_plain(nas_tx);
  m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx,
                                      m_ecm_ctx.enb_sri);
  m_pool->deallocate(nas_tx);

  return true;
}
bool nas::handle_statelearner_query_tau_reject(){

  srslte::byte_buffer_t*            nas_tx;
  bool ret = false;

  nas_tx = m_pool->allocate();

  pack_tau_reject(nas_tx, LIBLTE_MME_EMM_CAUSE_IMPLICITLY_DETACHED);

  // Send reply
  m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);
  m_pool->deallocate(nas_tx);
  return true;
}

bool nas::handle_statelearner_query_service_reject(){

  srslte::byte_buffer_t*            nas_tx;
  bool ret = false;

  nas_tx = m_pool->allocate();
  pack_service_reject(nas_tx, LIBLTE_MME_EMM_CAUSE_IMPLICITLY_DETACHED);

  // Send reply
  m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);
  m_pool->deallocate(nas_tx);
  m_nas_log->info("Downlink NAS: Sending Service Reject\n");
  m_nas_log->console("Downlink NAS: Sending Service Reject\n");
  return true;
}
bool nas::handle_statelearner_query_identity_request_imei(){

  srslte::byte_buffer_t*            nas_tx;
  bool ret = false;
  nas_tx = m_pool->allocate();
  pack_identity_request(nas_tx, LIBLTE_MME_EPS_MOBILE_ID_TYPE_IMEI);
  printf("Size of nas_tx in identity_request imei %d\n",sizeof(nas_tx));
  identity_replay_buffer = m_pool->allocate();
  identity_replay_buffer = nas_tx;
  
  m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx,
                                      m_ecm_ctx.enb_sri);

  return true;
}
bool nas::handle_statelearner_query_attach_accept_single_null_header()
{
  if (check(&m_sec_ctx.k_nas_enc[16])) {
    if (m_s1ap->get_mme_statelearner_reset_state() == false && m_enable_ue_state_fuzzing == true) {
      m_nas_log->console("********attach accept not sending!!************\n");
      return true;
    }
  } else {

    srslte::byte_buffer_t* nas_tx;
    bool                   ret = false;

    nas_tx = m_pool->allocate();

    pack_attach_accept_null_header(nas_tx);
    m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);
    m_pool->deallocate(nas_tx);

    return true;
  }
}
bool nas::handle_statelearner_query_emm_information()
{

  srslte::byte_buffer_t* nas_tx;
  bool                   ret = false;

  nas_tx = m_pool->allocate();

  pack_emm_information(nas_tx);
  m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);
  m_pool->deallocate(nas_tx);

  return true;
}

bool nas::handle_statelearner_query_paging_with_tmsi()
{

  srslte::byte_buffer_t* nas_tx;
  bool                   ret = false;

  nas_tx = m_pool->allocate();

  pack_emm_information(nas_tx);
  m_s1ap->send_downlink_nas_transport(m_ecm_ctx.enb_ue_s1ap_id, m_ecm_ctx.mme_ue_s1ap_id, nas_tx, m_ecm_ctx.enb_sri);
  m_pool->deallocate(nas_tx);

  return true;
}



} // namespace srsepc