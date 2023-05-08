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

package lte.statelearner.lteue;

import java.io.*;
import java.net.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

import net.automatalib.words.Word;
import net.automatalib.words.impl.SimpleAlphabet;
import lte.statelearner.StateLearnerSUL;
import de.learnlib.api.SUL;
import static java.lang.Thread.sleep;



public class LTEUESUL implements StateLearnerSUL<String, String> {
	LTEUEConfig config;
	SimpleAlphabet<String> alphabet;
	ArrayList<String> output_symbols;
	Socket mme_socket, enodeb_socket, ue_socket;
	BufferedWriter mme_out, enodeb_out, ue_out;
	BufferedReader mme_in, enodeb_in, ue_in;
	int reboot_count = 0;
	int enable_attach_count = 0;
	int attach_request_guti_count = 0;
	int enable_attach_timeout_count = 0;
	int reset_mme_count = 0;
	int reset_counter  = 0;
	boolean sqn_synchronized = false;
	public String device_name = "huwaeiy5_test";
	BufferedReader epc_br;
	BufferedReader enb_br;

	private static final String[] WIN_RUNTIME = {"cmd.exe", "/C"};
	private static final String[] OS_LINUX_RUNTIME = {"/bin/bash", "-l", "-c"};


	private static final int WAIT_BEFORE_ENABLE_ATTACH = 5 * 1000; // 5 seconds
	int unexpected = 0;
	public LTEUESUL(LTEUEConfig config) throws Exception {
		this.config = config;
		alphabet = new SimpleAlphabet<String>(Arrays.asList(config.alphabet.split(" ")));

		System.out.println(config.output_symbols);
		this.output_symbols = new ArrayList<String>(Arrays.asList(config.output_symbols.split(" ")));

		System.out.println("Starting EPC & eNodeB");
		System.out.println("Finished starting up EPC & eNodeB");

		init_epc_enb_con();
		init_ue_con();
		System.out.println("Done with initializing the connection with UE, eNodeB, and EPC");

	}

	public SimpleAlphabet<String> getAlphabet() {
		return alphabet;
	}

	public ArrayList<String> getOutputSymbols() {
		return output_symbols;
	}

	public String queryToString(Word<String> query) {
		StringBuilder builder = new StringBuilder();
		boolean first = true;
		for (String input : query) {
			if (first) {
				first = false;
			} else {
				builder.append(config.delimiter_input);
			}
			builder.append(input);
		}
		return builder.toString();
	}

	public Word<String> wordFromResponse(String response) {
		String[] outputs = response.split(config.delimiter_output);
		return Word.fromArray(outputs, 0, outputs.length);
	}

	public boolean canFork() {
		return false;
	}

	public SUL<String, String> fork() throws UnsupportedOperationException {
		throw new UnsupportedOperationException("Cannot fork SocketSUL");
	}

	public void post() {
		System.out.println("Counting how many enable_attach: "+how_many_enable_attach);
		how_many_enable_attach = 0;
		enable_attach_flag = 0;
		recevied_before_enable_attach = 0;
	}
	int recevied_before_enable_attach = 0;
	int how_many_enable_attach = 0;
	int flag_for_device = 0 ;
	int enable_attach_flag = 0;
	public String step(String symbol) {
		int mme_rrc = 0;
		try {
			sleep(50); //50 milliseconds
		} catch (Exception e) {
			e.printStackTrace();
		}

		String result = "";
		String result_mme = "";
		String attach_result = "";
		String result_for_ue = "";
		try {

			if (symbol.startsWith("enable_attach")) {
				enable_attach_flag = 1;
				if(how_many_enable_attach > 0 || recevied_before_enable_attach == 1){
					pre();
				}
				recevied_before_enable_attach = 0;
				how_many_enable_attach++;
				unexpected = 0;
				try{
					while (!result_mme.contains("attach_request")) {

						mme_socket.setSoTimeout(180 * 1000);
						send_enable_attach();
						result_mme = mme_in.readLine();
						if (result_mme.compareTo("") != 0 && result_mme.toCharArray()[0] == ' ') {
							result_mme = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
						}

					}
					if (!result_mme.contains("attach_request")) {
						result_mme = mme_in.readLine();
						if (result_mme.compareTo("") != 0 && result_mme.toCharArray()[0] == ' ') {
							result_mme = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
						}
					}
					if (result_mme.contains("attach_request_guti")) {
						result_mme = "attach_request";
					}
					System.out.println(symbol  + "-> MME:" + result_mme);
					return result_mme;
				}catch (Exception e1){
					while (!result_mme.contains("attach_request")) {

						mme_socket.setSoTimeout(180 * 1000);
						send_enable_attach();

						result_mme = mme_in.readLine();
						if (result_mme.compareTo("") != 0 && result_mme.toCharArray()[0] == ' ') {
							result_mme = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
						}


					}
					if (!result_mme.contains("attach_request")) {
						result_mme = mme_in.readLine();
						if (result_mme.compareTo("") != 0 && result_mme.toCharArray()[0] == ' ') {
							result_mme = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
						}
					}
					if (result_mme.contains("attach_request_guti")) {
						result_mme = "attach_request";
					}
					System.out.println(symbol  + "-> MME:" + result_mme);
					return result_mme;
				}
			}
		} catch (SocketTimeoutException e) {
			System.out.println("Timeout occured in step for" + symbol);
			try{
				mme_out.write(symbol + "\n");
				mme_out.flush();
			}catch(Exception e1) {
				handle_timeout();
				return "timeout";
			}

		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("Attempting to restart device and reset srsEPC. Also restarting query.");
			handle_enb_epc_failure();
			return "null_action";
		}

		try {
			if (symbol.contains("reject")) {
				mme_socket.setSoTimeout(5 * 1000);
				mme_out.write(symbol + "\n");
				mme_out.flush();

				result = mme_in.readLine();
				if (result.compareTo("") != 0 && result.toCharArray()[0] == ' ') {
					result = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
				}

				System.out.println(symbol + "->" + result);
				return result;
			}
		} catch (SocketTimeoutException e) {
			System.out.println("Timeout occured for " + symbol);
			System.out.println("Restarting UE and marking following command as null action");
			handle_timeout();
			return "timeout";
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("Attempting to restart device and reset srsEPC. Also restarting query.");
			handle_enb_epc_failure();
			return "null_action";
		}
		try {
			recevied_before_enable_attach = 1;
			if(unexpected == 1){
				if(symbol.startsWith("enable_tau")){
					unexpected = 0;
				}
			}
			if(unexpected == 1 || enable_attach_flag == 0){
				result = "null_action";
				return result;
			}
			if (!symbol.startsWith("enable_attach") && !symbol.contains("reject") && unexpected == 0) {
				if (symbol.startsWith("RRC_sm_command_protected") || symbol.startsWith("RRC_sm_command_replay") || symbol.startsWith("RRC_sm_command_null_security") || symbol.startsWith("RRC_sm_command_plain_text") || symbol.startsWith("RRC_sm_command_plain_header")) {
					mme_rrc = 1;
					enodeb_socket.setSoTimeout(2 * 1000);
					mme_out.write(symbol + "\n");
					mme_out.flush();
				} else if (symbol.startsWith("RRC_reconf") || symbol.startsWith("RRC_reconf_replay") || symbol.startsWith("RRC_reconf_plain_text")||symbol.startsWith("rrc_reconf_downgraded") ) {
					mme_rrc = 1;
					enodeb_socket.setSoTimeout(2 * 1000);
					enodeb_out.write(symbol + "\n");
					enodeb_out.flush();
				}  else if (symbol.startsWith("RRC_con_reest_plain_text") || symbol.startsWith("RRC_con_reest_protected")) {
					mme_rrc = 1;
					enodeb_socket.setSoTimeout(2 * 1000);
					enodeb_out.write(symbol + "\n");
					enodeb_out.flush();
				} else if (symbol.startsWith("RRC_connection_setup_plain_text") || symbol.startsWith("RRC_connection_setup_plain_header")) {
					mme_rrc = 1;
					enodeb_socket.setSoTimeout(2 * 1000);
					enodeb_out.write(symbol + "\n");
					enodeb_out.flush();
				} else if (symbol.startsWith("RRC_ue_info_req_protected")) {
					mme_rrc = 1;
					enodeb_socket.setSoTimeout(2 * 1000);
					enodeb_out.write(symbol + "\n");
					enodeb_out.flush();
				} else if ( symbol.startsWith("attach_accept_protected") || symbol.startsWith("attach_accept_no_integrity") || symbol.startsWith("attach_accept_null_header")  || symbol.startsWith("attach_accept_plain_text") ) {
					mme_rrc = 0;
					mme_socket.setSoTimeout(2 * 1000);
					mme_out.write(symbol + "\n");
					mme_out.flush();
				} else if (symbol.startsWith("auth_request_plain_text") || symbol.startsWith("sm_command_protected")  || symbol.contains("sm_command_replay") || symbol.startsWith("security_mode_command_no_integrity") || symbol.startsWith("sm_command_plain_text") || symbol.startsWith("sm_command_null_security") || symbol.startsWith("sm_command_null_security_replay") || symbol.startsWith("sm_command_plain_header")) {
					mme_rrc = 0;
					mme_socket.setSoTimeout(2 * 1000);
					mme_out.write(symbol + "\n");
					mme_out.flush();
					
				} else if (symbol.startsWith("enable_tau")) {
					mme_rrc = 0;
					System.out.println("### enable_tau ###");
					TimeUnit.SECONDS.sleep(8);
					mme_socket.setSoTimeout(5 * 1000);
					mme_out.write(symbol + "\n");
					mme_out.flush();
				} else if (symbol.startsWith("enable_RRC_con")) {
					mme_rrc = 0;
					System.out.println("### enable_RRC_con ###");
					TimeUnit.SECONDS.sleep(8);
					mme_socket.setSoTimeout(5 * 1000);
					mme_out.write(symbol + "\n");
					mme_out.flush();
				} else if (symbol.startsWith("enable_RRC_reest")) {
					mme_rrc = 0;
					System.out.println("### enable_RRC_reest ###");
					TimeUnit.SECONDS.sleep(8);
					mme_socket.setSoTimeout(5 * 1000);
					mme_out.write(symbol + "\n");
					mme_out.flush();
				} else if (symbol.startsWith("enable_RRC_mea_report")) {
					mme_rrc = 0;
					System.out.println("### enable_RRC_mea_report ###");
					TimeUnit.SECONDS.sleep(8);
					mme_socket.setSoTimeout(5 * 1000);
					mme_out.write(symbol + "\n");
					mme_out.flush();
				} else if (symbol.startsWith("RRC_release")) {
					mme_rrc = 0;
					System.out.println("### RRC RELEASE ###");
					mme_socket.setSoTimeout(1 * 1000);
					mme_out.write(symbol + "\n");
					mme_out.flush();
				} else if (symbol.startsWith("paging")) {
					mme_rrc = 0;
					System.out.println("### paging ###");
					mme_socket.setSoTimeout(5 * 1000);
					mme_out.write(symbol + "\n");
					mme_out.flush();
				} else if (symbol.startsWith("tau_accept_protected") || symbol.startsWith("tau_accept_plain_header")) {
					mme_rrc = 0;
					mme_socket.setSoTimeout(2 * 1000);
					mme_out.write(symbol + "\n");
					mme_out.flush();
				}else if(symbol.contains("identity_request_plain_text") || symbol.contains("identity_request_mac") || symbol.contains("identity_request_wrong_mac") || symbol.contains("identity_request_replay")){
					mme_rrc = 0;
					System.out.println("case "+symbol);
					mme_socket.setSoTimeout(2 * 1000);
					mme_out.write(symbol + "\n");
					mme_out.flush();

				}else if(symbol.contains("GUTI_reallocation_protected") || symbol.contains("GUTI_reallocation_replay") ){
					mme_rrc = 0;
					System.out.println("case "+symbol);
					mme_socket.setSoTimeout(2 * 1000);
					mme_out.write(symbol + "\n");
					mme_out.flush();
				} else {
					mme_rrc = 0;
					System.out.println("the except case: "+symbol);
					mme_socket.setSoTimeout(2 * 1000);
					mme_out.write(symbol + "\n");
					mme_out.flush();
				}

				result = "";
				if(mme_rrc == 0){
					System.out.println("Reading from MME");
					result = mme_in.readLine();
				} else{
					System.out.println("Reading from RRC");
					result = enodeb_in.readLine();
					if (result.contains("rrc_connection_setup_complete")) {
						System.out.println("Reading again!");
						result = enodeb_in.readLine();
					}
				}
				if (result.compareTo("") != 0 && result.toCharArray()[0] == ' ') {
					result = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
				}
				if (result.contains("attach_request") || result.contains("DONE")) {
					System.out.println("Response of " + symbol + " = Unexpected attach_request");
					unexpected = 1;
				}else if (!symbol.startsWith("enable_tau") && result.contains("tau_request")){
					System.out.println("Unexpected tau_request caught!");
					unexpected = 1;
				}else {
					if (result.contains("emm_status")) {
						System.out.println("Actual response of " + symbol + " = emm_status");
						result = "null_action";
					}
					if (result.contains("attach_request_guti")) {
						System.out.println("Actual response of " + symbol + " = attach_request_guti");
						result = "attach_request";
					}
					if (result.contains("detach_request")) {
						result = "null_action";
						System.out.println("Actual response of " + symbol + " = detach_request");
					} else {
						System.out.println("Response of " + symbol + " = " + result);
						System.out.println(symbol + "->" + result);
						return result;
					}
				}



			}
		} catch (SocketTimeoutException e) {
			System.out.println("Timeout occured for " + symbol);
			return "null_action";
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("Attempting to restart device and reset srsEPC. Also restarting query.");
			handle_enb_epc_failure();
			return "null_action";

		}

		try {
			if (result.compareTo("") != 0 && result.toCharArray()[0] == ' ') {
				result = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
				if (result.toLowerCase().startsWith("null_action")) {
					result = "null_action";
				}
				if (result.toLowerCase().startsWith("detach_request")) {
					result = "null_action";
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("Attempting to restart device and reset srsEPC. Also restarting query.");
			handle_enb_epc_failure();
			return "null_action";
		}

		System.out.println("####" + symbol + "/" + result + "####");


		return result;
	}

	private Boolean detect_failure(String log_file) {
		try (BufferedReader br = new BufferedReader(new FileReader(log_file))) {
			Boolean error_encountered = false;
			String line = br.readLine();
			while (line != null) {
				line = br.readLine();
				line = line.toLowerCase();
				if (line.contains("error") || line.contains("fail")) {
					System.out.println("ERROR found in log file");
					System.out.println(line);
					error_encountered = true;
					break;
				}
			}

			return error_encountered;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return true;
		} catch (IOException e) {
			e.printStackTrace();
			return true;
		}
	}

	public void pre() {
		int flag = 0;
		try {

			if (!config.combine_query) {

				String result = new String("");
				String result_for_mme = new String("");
				String result_for_ue = new String("");
				String result_for_enodeb = new String("");
				String attach_result = new String("");
				boolean reset_done = false;

				attach_request_guti_count = 0;
				enable_attach_timeout_count = 0;
				reboot_count = 0;
				int i = 0;
				System.out.println("---- Starting RESET ----");

				do {
					try {

						if((config.device.equals(device_name) && reset_counter== 0) || !config.device.equals(device_name)){
                            result_for_ue = reset_ue();
                        }
						if(flag == 2){
							result_for_mme = reset_mme();
						}

						result = new String("");
						attach_result = new String("");
						if (config.device.equals(device_name)) {
							enodeb_socket.setSoTimeout(120 * 1000);
							mme_socket.setSoTimeout(120 * 1000);
						}else{
							enodeb_socket.setSoTimeout(120 * 1000);
							mme_socket.setSoTimeout(120 * 1000);
						}

						if((config.device.equals(device_name) && reset_counter!= 0) || !config.device.equals(device_name)){
                            System.out.println("Sending enable_attach");
							send_enable_attach();
                        }

						result = mme_in.readLine();
						System.out.println("This is time: " + result);
						if (result == null || result.compareTo("") == 0 || result.contains("null_action")) {
							result = mme_in.readLine();
							continue;
						}
						result = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));

						if(result.contains("DONE")){
						}

						if( result.contains("tau_request")){
							continue;
						}

						if (result.contains("detach_request")) {
							System.out.println("Caught detach_request and sending enable_attach again!");

							pre();
							return;

						}
						if(flag == 0) {
							mme_out.write("attach_reject\n");
							mme_out.flush();
							flag = 1;
							reset_counter++;
							System.out.println("Passing!!\n");
							continue;
						}
						System.out.println("Response of enable_attach: " + result);
						mme_socket.setSoTimeout(30 * 1000);
						int attach_request_guti_counter = 10;

						if (result.contains("attach_request_guti") || result.contains("service_request") || result.contains("tau_request") ||result.contains("detach_request")||result.contains("DONE") ) {
							attach_request_guti_count++;
							flag = 1;

							if (attach_request_guti_count < attach_request_guti_counter) {
								System.out.println("Sending symbol: attach_reject to MME controller to delete the UE context in attach_request_guti");
								sleep((attach_request_guti_count*1)*10000);
								result = mme_in.readLine();
								flag = 2;
								mme_out.write("attach_reject\n");
								mme_out.flush();
							} else if (attach_request_guti_count % attach_request_guti_counter == 0) {
								handle_enb_epc_failure();
							} else if (attach_request_guti_count > attach_request_guti_counter) {
								System.out.println("Sending symbol: auth_reject to MME controller to delete the UE context");
								mme_out.write("auth_reject\n");
								mme_out.flush();
								TimeUnit.SECONDS.sleep(2);
								reboot_ue();
							}
						} else if (result.startsWith("attach_request")) {
							if (flag == 0) {
								flag = 1;
								continue;
							}
							attach_request_guti_count = 0;

							if (sqn_synchronized == false) {

								System.out.println("Sending symbol: auth_request to MME controller");
								mme_out.write("auth_request_plain_text\n");
								mme_out.flush();

								result = mme_in.readLine();
								result = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));

								System.out.println("RESULT FROM AUTH REQUEST: " + result);

								if (result.contains("auth")) {
									System.out.println("Received " + result + ". Synched the SQN value");
									sqn_synchronized = true;
									reset_done = true;
									break;
								}else{
									i++;
									System.out.println("Sleeping for some Seconds");
									TimeUnit.SECONDS.sleep(i);
								}
							} else if (sqn_synchronized == true) {
								reset_done = true;
								break;
							}

						}
					} catch (SocketTimeoutException e) {
						enable_attach_timeout_count++;
						System.out.println("Timeout occured for enable_attach");
						System.out.println("Sleeping for a while...");
						sleep(enable_attach_timeout_count * 1 * 1000);
						pre();
						return;
					}
				} while (reset_done == false);

				result = reset_mme();
				if (result.contains("attach_request_guti")) {
				}
				if(!config.device.equals(device_name)){
					result = reset_ue();
				}
				System.out.println("---- RESET DONE ----");

			}
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		}
	}

	public boolean post_query_check() throws InterruptedException {
		return true;
	}

	public void handle_timeout() {
		String result = new String("");
		try {
			ue_out.write("ue_reboot\n");
			ue_out.flush();
			System.out.println("Sleeping while UE reboots");
			TimeUnit.SECONDS.sleep(45);
			result = ue_in.readLine();
			System.out.println("Result for reboot: " + result);
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		System.out.println("TIMEOUT HANDLE DONE.");

	}

	public void is_adb_server_restart_required() {
		String result = new String("");
		if (enable_attach_count >= 50) {
			enable_attach_count = 0;
			try {
				ue_out.write("adb_server_restart\n");
				ue_out.flush();
				result = ue_in.readLine();
				System.out.println("Result for adb_server_restart: " + result);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

	}

	public void handle_enb_epc_failure() {
		System.out.println("ENB EPC FAILURE. PLEASE RESTART.");
		System.exit(1);
	}


	public void init_epc_enb_con() {
		try {
			// Initialize test service
			System.out.println("Connecting to srsEPC...");
			mme_socket = new Socket(config.mme_controller_ip_address, config.mme_port);
			mme_socket.setTcpNoDelay(true);
			mme_out = new BufferedWriter(new OutputStreamWriter(mme_socket.getOutputStream()));
			mme_in = new BufferedReader(new InputStreamReader(mme_socket.getInputStream()));
			System.out.println("Connected with srsEPC.");

			System.out.println("Connecting to srsENB...");
			enodeb_socket = new Socket(config.enodeb_controller_ip_address, config.enodeb_port);
			enodeb_socket.setTcpNoDelay(true);
			enodeb_out = new BufferedWriter(new OutputStreamWriter(enodeb_socket.getOutputStream()));
			enodeb_in = new BufferedReader(new InputStreamReader(enodeb_socket.getInputStream()));
			System.out.println("Connected with srsENB.");

			String result = new String();
			try {
				sleep(2 * 1000);
				enodeb_out.write("Hello\n");
				enodeb_out.flush();
				result = enodeb_in.readLine();
				System.out.println("Received = " + result);
			}
			catch (Exception e) {
				e.printStackTrace();
				System.out.println("ENB EPC FAILURE. PLEASE RESTART.");
				System.exit(1);
			}
			if (result.startsWith("ACK")) {
				System.out.println("PASSED: Testing the connection between the statelearner and the srsENB");
			}

		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("ENB EPC FAILURE. PLEASE RESTART.");
			System.exit(1);
		}
		System.out.println("Connected to srsLTE");
	}

	public void init_ue_con() {
		try {
			System.out.println("Connecting to UE...");
			System.out.println("UE controller IP Address: " + config.ue_controller_ip_address);
			ue_socket = new Socket(config.ue_controller_ip_address, config.ue_port);
			ue_socket.setTcpNoDelay(true);
			System.out.println("Connected to UE");

			System.out.println("Initializing Buffers for UE...");
			ue_out = new BufferedWriter(new OutputStreamWriter(ue_socket.getOutputStream()));
			ue_in = new BufferedReader(new InputStreamReader(ue_socket.getInputStream()));
			System.out.println("Initialized Buffers for UE");

		} catch (UnknownHostException e) {
			e.printStackTrace();
		}
		catch (SocketException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public String reset_mme() {

		String result = new String("");
		System.out.println("Sending symbol: RESET to MME controller");
		try {
			sleep(1 * 1000);
			mme_out.write("RESET " + reset_mme_count + "\n");
			mme_out.flush();
			result = mme_in.readLine();
			System.out.println("ACK for RESET_MME: " + result);
			reset_mme_count++;
			if (result == null) {
				return result;
			}
			String result1 = result.replaceAll("[^a-zA-Z]", "");
			System.out.println(result1);
			if (result1.equalsIgnoreCase("")) {
				sleep(2000);
				reset_mme();
			}
			if (result1.compareTo("DONE") != 0) {
				if (result1.compareTo("attachrequest") != 0 || result1.compareTo("attachrequestguti") != 0) {
					sleep(2000);
				}
			}
		} catch (SocketException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return result;
	}

	public String reset_ue() {
		String result = new String("");
		System.out.println("Sending symbol: RESET to UE controller");
		try {
			sleep(1 * 1000);
			ue_out.write("RESET\n");
			ue_out.flush();
			result = ue_in.readLine();
			System.out.println("ACK for RESET_UE: " + result);
		} catch (SocketException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return result;
	}


	public void send_enable_attach() {

		try {
			sleep(1000);
			String result = new String("");

			System.out.println("Sending symbol: enable_attach to UE controller");
			enable_attach_count++;
			ue_out.write("enable_attach\n");
			ue_out.flush();

			enable_attach_count++;
			result = ue_in.readLine();
			System.out.println("UE controller's ACK for enable_attach: " + result);
			if (!result.contains("DONE")) {
				send_enable_attach();

			}
		} catch (SocketException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	public String reboot_ue() {
		System.out.println("Sending REBOOT_UE command to UE_CONTROLLER");
		String result = new String("");
		try {
			ue_out.write("ue_reboot\n"); // reboot the UE and turn cellular network ON with 4G LTE
			ue_out.flush();
			System.out.println("Waiting for the response from UE .... ");
			result = ue_in.readLine();
			System.out.println("UE's ACK for REBOOT: " + result);

		} catch (SocketException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return result;
	}


	private static <T> T[] concat(T[] first, T[] second) {
		T[] result = Arrays.copyOf(first, first.length + second.length);
		System.arraycopy(second, 0, result, first.length, second.length);
		return result;
	}

	public int minimum(int a, int b, int c) {
		return Math.min(Math.min(a, b), c);
	}

	public int computeLevenshteinDistance(CharSequence lhs, CharSequence rhs) {
		int[][] distance = new int[lhs.length() + 1][rhs.length() + 1];

		for (int i = 0; i <= lhs.length(); i++)
			distance[i][0] = i;
		for (int j = 1; j <= rhs.length(); j++)
			distance[0][j] = j;

		for (int i = 1; i <= lhs.length(); i++)
			for (int j = 1; j <= rhs.length(); j++)
				distance[i][j] = minimum(
						distance[i - 1][j] + 1,
						distance[i][j - 1] + 1,
						distance[i - 1][j - 1] + ((lhs.charAt(i - 1) == rhs.charAt(j - 1)) ? 0 : 1));

		return distance[lhs.length()][rhs.length()];
	}


}