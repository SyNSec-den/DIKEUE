"""
Dummy UE program written for DIKUE
Authors: Imtiaz Karim, Syed Rafiul Hussain
Contact: karim7@purdue.edu, hussain1@psu.edu
"""

import socket

DEVICE_PORT = 58888

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("localhost", DEVICE_PORT))
s.listen(1)

(client, address) = s.accept()

print "Adapter connected..."

# ue states
deregistered = 0
registered_initiated = 1
registered = 2

authenticated = False
sec_ctx_exist = False
sec_ctx_updated = False

ooo_accept_received = False
ooo_guti_realloc_received = False

initial_registration_completed = False
accept_unprotected_messages = True
rrc_con_established = False
rrc_con_request = False

state = deregistered  # initial state

while 1:
    cmd = client.recv(1024).strip()
    print("Command recevied: " +cmd)

    # print cmd

    if cmd == "":
        print "Got empty command"
        break

    response = 'null_action'

    if cmd == "RESET":
        state = deregistered
        authenticated = False
        sec_ctx_exist = False
        sec_ctx_updated = False
        ooo_accept_received = False
        rrc_con_established = False
        ooo_guti_realloc_received = False
        initial_registration_completed = False
        tau_requested = False
        sec_mode_rejected = False
        tau_accept_failed = False
        rrc_con_request = False
        rrc_release_tau_failed = False
        paging_tmsi_failed = False
        GUTI_reallocation_failed = False
        auth_updated = False
        response = "DONE"
        print "RESET DONE"
        enable_attach_again = False
        attach_accept_failed = False
        sec_ctx_updated = False
        sec_ctx_update_needed = False
        tau_inbetween = False
        tau_inbetween_smd = False

    ########### cmd = enable_attach ###########
    elif cmd == "enable_attach":
        if rrc_con_established:
            if state == deregistered:
                response = "attach_request"

            elif state == registered_initiated:
                if initial_registration_completed == True:
                    response = "attach_request"
                else:
                    response = "attach_request"
            elif state == registered:
                response = "attach_request"
                enable_attach_again = True
                # if initial_registration_completed == True:
                # sec_ctx_exist = True
                # authenticated = True
                # initial_registration_completed = False

            # if initial_registration_completed == False:
            sec_ctx_exist = False
            authenticated = False

            state = registered_initiated

            accept_unprotected_messages = True
            # sec_ctx_exist = False
            ooo_accept_received = False
            ooo_guti_realloc_received = False
            tau_requested = False
            sec_mode_rejected = False
            # tau_accept_failed = False
            rrc_release_tau_failed = False
            paging_tmsi_failed = False
            GUTI_reallocation_failed = False
            attach_accept_failed = False
            service_requested = False
            tau_inbetween_attach_accept = False
            tau_request_failed = False
            rrc_release_tau_smd = False
        else:
            response = "null_action"


    ################# cmd = identity_request_plain_text ######################
    elif cmd == "identity_request_plain_text":
        if rrc_con_established:
            if (ooo_accept_received == True) and (state == deregistered or state == registered_initiated):
                response = "null_action"
            else:
                if state == deregistered:
                    response = "null_action"

                elif state == registered_initiated:

                    response = "null_action"  # default response

                    if not initial_registration_completed:
                        if accept_unprotected_messages:
                            if sec_ctx_exist and authenticated and tau_accept_failed:
                                response = "null_action"
                            else:
                                response = "identity_response"


                    else:  # initial registration completed
                        if accept_unprotected_messages and not tau_accept_failed:
                            response = "identity_response"
                        else:
                            response = "null_action"

                    if rrc_release_tau_failed or paging_tmsi_failed:  # sec_mode_rejected or tau_accept_failed or  or paging_tmsi_failed:
                        response = "null_action"

                elif state == registered:
                    if (tau_requested and (
                            not tau_inbetween_smd and not tau_inbetween_attach_accept and not tau_request_failed)) or service_requested:
                        response = "identity_response"
                    else:
                        response = "null_action"
        else:
            response = "null_action"

    ########### cmd = auth_request_plain_text ###########
    elif cmd == "auth_request_plain_text":
        if rrc_con_established:
            if ooo_accept_received == True and (state == deregistered or state == registered_initiated):
                response = "null_action"
            else:
                if state == deregistered:
                    response = "null_action"

                elif state == registered_initiated:
                    response = "null_action"  # default

                    if not initial_registration_completed:
                        if accept_unprotected_messages == True:
                            response = "auth_response"
                            authenticated = True

                    else:  # initial registration completed
                        if accept_unprotected_messages == True:
                            response = "auth_response"
                            auth_updated = True
                            sec_ctx_updated = False
                            sec_ctx_update_needed = True

                    # TODO: Need to check the following
                    if rrc_release_tau_failed or paging_tmsi_failed:  # sec_mode_rejected or tau_accept_failed or rrc_release_tau_failed or paging_tmsi_failed:
                        response = "null_action"

                elif state == registered:
                    if (tau_requested and (
                            not tau_inbetween_smd and not tau_inbetween_attach_accept and not tau_request_failed)) or service_requested:
                        response = "auth_response"
                        tau_inbetween = True
                    else:
                        response = "null_action"
        else:
            response = "null_action"


    ########### cmd = sm_command_protected ###########
    elif cmd == "sm_command_protected":
        if rrc_con_established:
            if ooo_accept_received == True and (state == deregistered or state == registered_initiated):
                response = "null_action"

            else:
                if state == deregistered:
                    response = "null_action"

                elif state == registered_initiated:
                    response = "null_action"  # default

                    if not initial_registration_completed:
                        if not authenticated and not sec_ctx_exist:
                            response = "sm_reject"
                            sec_mode_rejected = True

                        elif not authenticated and sec_ctx_exist:
                            response = "null_action"

                        elif authenticated and not sec_ctx_exist:
                            sec_ctx_exist = True
                            response = "sm_complete"
                            accept_unprotected_messages = False

                        elif authenticated and sec_ctx_exist:
                            response = "sm_complete"
                            accept_unprotected_messages = False

                    else:  # initial registration completed
                        if accept_unprotected_messages:
                            response = "sm_complete"
                            accept_unprotected_messages = False

                        if auth_updated and sec_ctx_updated == False:
                            response = "sm_complete"
                            accept_unprotected_messages = False
                            auth_updated = False
                            sec_ctx_updated = True
                            sec_ctx_update_needed = False
                        response = "sm_complete"

                    if rrc_release_tau_failed or paging_tmsi_failed:  # sec_mode_rejected or tau_accept_failed or rrc_release_tau_failed or paging_tmsi_failed:
                        response = "null_action"

                elif state == registered:
                    response = "sm_complete"
                    tau_inbetween_smd = True
                    if rrc_release_tau_smd:
                        response = "null_action"
        else:
            response = "null_action"


    ########### cmd = attach_accept_protected ###########
    elif cmd == "attach_accept_protected":
        if rrc_con_established:
            if state == deregistered:
                response = "null_action"
                ooo_accept_received = True
            elif state == registered_initiated:
                if initial_registration_completed == False:
                    if not authenticated and not sec_ctx_exist:
                        response = "null_action"
                        # ooo_accept_received = True
                    elif authenticated and not sec_ctx_exist:
                        response = "null_action"
                        # ooo_accept_received = True
                    elif not authenticated and sec_ctx_exist:
                        if initial_registration_completed:
                            authenticated = True
                            response = "attach_complete"
                            state = registered
                            ooo_accept_received = False

                    elif authenticated and sec_ctx_exist and not tau_accept_failed and not rrc_release_tau_failed and not paging_tmsi_failed:
                        response = "attach_complete"
                        state = registered
                        initial_registration_completed = True
                        ooo_accept_received = False
                else:
                    if authenticated and sec_ctx_exist and not tau_accept_failed and not rrc_release_tau_failed and not paging_tmsi_failed and (
                    not sec_ctx_update_needed):
                        response = "attach_complete"
                        state = registered
                        accept_unprotected_messages = False
                        # sec_ctx_exist = False
                        # initial_registration_completed = True
                        ooo_accept_received = False
                    else:
                        response = "null_action"
            
            elif state == registered:
                response = "null_action"
                attach_accept_failed = True
                if tau_requested:
                    tau_inbetween_attach_accept = True
                    tau_requested = False
                    tau_request_failed = True
        else:
            response = "null_action"

    ########### cmd = enable_tau ###########
    elif cmd == "enable_tau":
        if rrc_con_established:
            if state == deregistered:
                response = "null_action"
            elif state == registered_initiated:
                # if initial_registration_completed:
                # response = "tau_request"
                # else:
                response = "null_action"
                rrc_release_tau_failed = True
            elif state == registered:
                if tau_requested or service_requested or tau_request_failed:
                    response = "null_action"
                    tau_request_failed = True
                    rrc_release_tau_smd = True
                else:
                    response = "tau_request"
                    tau_requested = True
                    registered_initiated = True
        else:
            response = "null_action"


    ########### cmd = tau_accept_protected ###########
    elif cmd == "tau_accept_protected":
        if rrc_con_established:
            if state == deregistered:
                response = "null_action"
            elif state == registered_initiated:
                if initial_registration_completed and tau_requested:
                    response = "tau_complete"
                    tau_requested = False
                else:
                    response = "null_action"
                    tau_accept_failed = True
            elif state == registered:
                if tau_requested:
                    response = "tau_complete"
                    tau_requested = False
                else:
                    response = "null_action"
                    tau_accept_failed = True
        else:
            response = "null_action"



    ########### cmd = paging ###########
    elif cmd == "paging":
        if rrc_con_established:
            if state == deregistered:
                response = "null_action"
            elif state == registered_initiated:
                response = "null_action"
                paging_tmsi_failed = True
            elif state == registered:
                response = "service_request"
                service_requested = True
                # tau_request_failed = True
        else:
            response = "null_action"


    ########### cmd = GUTI_reallocation_protected ###########
    elif cmd == "GUTI_reallocation_protected":
        if rrc_con_established:
            if state == deregistered:
                response = "null_action"
            elif state == registered_initiated:
                # if initial_registration_completed == False:
                if sec_ctx_exist and not rrc_release_tau_failed and not paging_tmsi_failed:
                    response = "GUTI_reallocation_complete"
                else:
                    response = "null_action"
            elif state == registered:
                if tau_requested or tau_request_failed:
                    response = "null_action"
                    tau_request_failed = True
                else:
                    response = "GUTI_reallocation_complete"
        else:
            response = "null_action"



    ########### cmd = DL_NAS_transport_protected ###########
    elif cmd == "DL_NAS_transport_protected":
        if rrc_con_established:
            if state == deregistered:
                response = "null_action"
            elif state == registered_initiated:
                if initial_registration_completed:
                    response = "null_action"
                else:
                    response = "null_action"
            elif state == registered:
                if tau_requested or service_requested or tau_request_failed:
                    response = "null_action"
                    tau_request_failed = True
                else:
                    response = "UL_nas_transport"
        else:
            response = "null_action"

    ################# cmd = sm_command_replay ######################
    elif cmd == "sm_command_replay":
        response = "null_action"

    ################# cmd = sm_command_plain_text ######################
    elif cmd == "sm_command_plain_text":
        response = "null_action"

    ################# cmd = sm_command_plain_header ######################
    elif cmd == "sm_command_plain_header":
        response = "null_action"

    ################# cmd = sm_command_null_security ######################
    elif cmd == "sm_command_null_security":
        response = "null_action"


    ################# cmd = attach_accept_plain_text ######################
    elif cmd == "attach_accept_plain_text":
        response = "null_action"


    ################# cmd = tau_accept_plain_header ######################
    elif cmd == "tau_accept_plain_header":
        response = "null_action"


    ################# cmd = GUTI_reallocation_replay ######################
    elif cmd == "GUTI_reallocation_replay":
        response = "null_action"


    ################# cmd = auth_reject ######################
    elif cmd == "auth_reject":
        response = "null_action"



    ################# cmd = tau_reject ######################
    elif cmd == "tau_reject":
        response = "null_action"



    ################# cmd = enable_RRC_con ######################
    elif cmd == "enable_RRC_con":
        response = "RRC_con_req"
        rrc_con_request = True


    ################# cmd = RRC_connection_setup_plain_text ######################
    elif cmd == "RRC_connection_setup_plain_text":
        if rrc_con_request:
            response = "RRC_connection_setup_complete"
            rrc_con_established = True
            rrc_con_request = False
        else:
            response = "null_action"

    ################# cmd = RRC_connection_setup_plain_header ######################
    elif cmd == "RRC_connection_setup_plain_header":
       response = "null_action"


    ################# cmd = RRC_sm_command_replay ######################
    elif cmd == "RRC_sm_command_replay":
        response = "null_action"


    ################# cmd = RRC_sm_command_plain_text ######################
    elif cmd == "RRC_sm_command_plain_text":
        response = "null_action"



    ################# cmd = RRC_sm_command_plain_header ######################
    elif cmd == "RRC_sm_command_plain_header":
        response = "null_action"


    ################# cmd = RRC_sm_command_protected ######################
    elif cmd == "RRC_sm_command_protected":
        if rrc_con_established:
            response = "RRC_sm_complete"
        else:
            response = "null_action"



    ################# cmd = RRC_sm_command_null_security ######################
    elif cmd == "RRC_sm_command_null_security":
        response = "null_action"


    ################# cmd = RRC_reconf_reply ######################
    elif cmd == "RRC_reconf_replay":
        response = "null_action"


    ################# cmd = RRC_reconf_plain_text ######################
    elif cmd == "RRC_reconf_plain_text":
        if rrc_con_established:
            response = "RRC_reconf_complete"
        else:
            response = "null_action"

    ################# cmd = enable_RRC_reest ######################
    elif cmd == "enable_RRC_reest":
        response = "null_action"

    ################# cmd = enable_RRC_mea_report ######################
    elif cmd == "enable_RRC_mea_report":
        if rrc_con_established:
            response = "RRC_mea_report"
        else:
            response = "null_action"


    ################# cmd = RRC_con_reest_plain_text ######################
    elif cmd == "RRC_con_reest_plain_text":
        response = "null_action"


    ################# cmd = RRC_con_reeest_protected ######################
    elif cmd == "RRC_con_reeest_protected":
        response = "null_action"


    ################# cmd = RRC_ue_info_req_protected ######################
    elif cmd == "RRC_ue_info_req_protected":
        if rrc_con_established:
            response = "RRC_ue_info_req"
        else:
            response = "null_action"

    

    ################# cmd = RRC_release ######################
    elif cmd == "RRC_release":
        response = "null_action"


    print "CMD = ", cmd, "-> RESPONSE = ", response
    client.sendall(response)