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

import net.automatalib.words.Word;
import net.automatalib.words.impl.SimpleAlphabet;
import lte.statelearner.StateLearnerSUL;
import de.learnlib.api.SUL;
import static java.lang.Thread.sleep;



public class LTEUESUL implements StateLearnerSUL<String, String> {
	LTEUEConfig config;
	SimpleAlphabet<String> alphabet;
	ArrayList<String> output_symbols;

	/// removed for connecting with the sample adapter in open-source version
	//Socket mme_socket, enodeb_socket, ue_socket;
	//BufferedWriter mme_out, enodeb_out, ue_out;
	//BufferedReader mme_in, enodeb_in, ue_in;

	Socket adapter_socket;
	BufferedWriter adapter_out;
	BufferedReader adapter_in;


	int enable_attach_count = 0;
	BufferedReader epc_br;
	BufferedReader enb_br;

	private static final String[] WIN_RUNTIME = {"cmd.exe", "/C"};
	private static final String[] OS_LINUX_RUNTIME = {"/bin/bash", "-l", "-c"};

	private static final List<String> expectedResults = Arrays.asList(
			"attach_request",
			"attach_request_guti",
			"detach_request",
			"auth_response",
			"sm_complete",
			"sm_reject",
			"emm_status",
			"attach_complete",
			"rrc_reconf_complete",
			"rrc_sm_complete",
			"rrc_connection_setup_complete",
			"identity_response",
			"auth_MAC_failure",
			"auth_seq_failure",
			"auth_failure_noneps",
			"tau_request",
			"service_request",
			"tau_complete",
			"UL_nas_transport",
			"null_action",
			"GUTI_reallocation_complete",
			"RRC_con_req",
			"RRC_connection_setup_complete",
			"RRC_sm_failure",
			"RRC_sm_complete",
			"RRC_reconf_complete",
			"RRC_con_reeest_req",
			"RRC_mea_report",
			"RRC_con_reest_complete",
			"RRC_con_reest_reject",
			"RRC_ue_info_req",
			"DONE");

	int unexpected = 0;
	public LTEUESUL(LTEUEConfig config) throws Exception {
		this.config = config;
		alphabet = new SimpleAlphabet<String>(Arrays.asList(config.alphabet.split(" ")));
		System.out.println(config.output_symbols);
		this.output_symbols = new ArrayList<String>(Arrays.asList(config.output_symbols.split(" ")));

		System.out.println("Starting EPC & eNodeB");
		System.out.println("Finished starting up EPC & eNodeB");

		/// removed for connecting with the sample adapter in open-source version
		// init_epc_enb_con();
		// init_ue_con();
		
		init_adapter_con();
		System.out.println("Done with initializing the connection with Adapter");

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
		how_many_enable_attach = 0;
		enable_attach_flag = 0;
		recevied_before_enable_attach = 0;
	}
	int recevied_before_enable_attach = 0;
	int how_many_enable_attach = 0;
	int enable_attach_flag = 0;


	public String step(String symbol) {
		try {
			sleep(50); //50 milliseconds
		} catch (Exception e) {
			e.printStackTrace();
		}

		String result = "";
		String result_mme = "";

		// removed for open-source
		// String attach_result = "";
		// String result_for_ue = "";
		try {
			if (symbol.contains("reject")) {
				adapter_socket.setSoTimeout(5 * 1000);
				adapter_out.write(symbol + "\n");
				adapter_out.flush();

				result = adapter_in.readLine();
				if (result.compareTo("") != 0 && result.toCharArray()[0] == ' ') {
					result = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
				}
				result = getClosests(result);

				System.out.println(symbol + "->" + result);
				return result;
			}
		} catch (SocketTimeoutException e) {
			System.out.println("Timeout occured for " + symbol);
			System.out.println("Restarting UE and marking following command as null action");
			// handle_timeout();
			return "timeout";
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("Attempting to restart device and reset srsEPC. Also restarting query.");
			// handle_enb_epc_failure();
			return "null_action";
		}
		try {
			adapter_socket.setSoTimeout(2 * 1000);
			adapter_out.write(symbol + "\n");
			adapter_out.flush();
			result = adapter_in.readLine();
			if (result.compareTo("") != 0 && result.toCharArray()[0] == ' ') {
					result = new String(Arrays.copyOfRange(result.getBytes(), 1, result.getBytes().length));
			}
			result = getClosests(result);
		} catch (SocketTimeoutException e) {
			System.out.println("Timeout occured for " + symbol);
			return "null_action";
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("Attempting to restart device and reset srsEPC. Also restarting query.");
			// handle_enb_epc_failure();
			return "null_action";
		}
		return result;
	}

	/// removed for connecting with the sample adapter in open-source version
	// private Boolean detect_failure(String log_file) {
	// 	try (BufferedReader br = new BufferedReader(new FileReader(log_file))) {
	// 		Boolean error_encountered = false;
	// 		String line = br.readLine();
	// 		while (line != null) {
	// 			line = br.readLine();
	// 			line = line.toLowerCase();
	// 			if (line.contains("error") || line.contains("fail")) {
	// 				System.out.println("ERROR found in log file");
	// 				System.out.println(line);
	// 				error_encountered = true;
	// 				break;
	// 			}
	// 		}

	// 		return error_encountered;
	// 	} catch (FileNotFoundException e) {
	// 		e.printStackTrace();
	// 		return true;
	// 	} catch (IOException e) {
	// 		e.printStackTrace();
	// 		return true;
	// 	}
	// }

	public void pre() {
		try {
			if (!config.combine_query) {
				// Reset test service
				System.out.println("Sending symbol: RESET");
				adapter_out.write("RESET\n");
				adapter_out.flush();

				// sleep(50);

				adapter_in.readLine();

				// String result = reset_ue();
			}
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		}
	}


	public boolean post_query_check() throws InterruptedException {
		return true;
	}

	/// removed for connecting with the sample adapter in open-source version
	// public void handle_timeout() {
	// 	String result = new String("");
	// 	/*
	// 	if(enb_alive() == false || mme_alive() == false){
	// 		if(enb_alive() == false || mme_alive() == false) {
	// 			handle_enb_epc_failure();
	// 			return;
	// 		}
	// 	}
	// 	*/
	// 	try {
	// 		ue_out.write("ue_reboot\n"); // reboot the UE and turn cellular network ON with 4G LTE
	// 		ue_out.flush();
	// 		System.out.println("Sleeping while UE reboots");
	// 		TimeUnit.SECONDS.sleep(45);
	// 		result = ue_in.readLine();
	// 		System.out.println("Result for reboot: " + result);
	// 	} catch (IOException e) {
	// 		e.printStackTrace();
	// 	} catch (InterruptedException e) {
	// 		e.printStackTrace();
	// 	}
	// 	System.out.println("TIMEOUT HANDLE DONE.");

	// }

	/// removed for connecting with the sample adapter in open-source version
	// public void is_adb_server_restart_required() {
	// 	String result = new String("");
	// 	if (enable_attach_count >= 50) {
	// 		//ue_socket.setSoTimeout(30*1000);
	// 		enable_attach_count = 0;
	// 		try {
	// 			ue_out.write("adb_server_restart\n");
	// 			ue_out.flush();
	// 			result = ue_in.readLine();
	// 			System.out.println("Result for adb_server_restart: " + result);
	// 		} catch (IOException e) {
	// 			e.printStackTrace();
	// 		}
	// 	}

	// }

	/// removed for connecting with the sample adapter in open-source version
	// public void handle_enb_epc_failure() {
	// 	String result = new String("");

	// 	try {
	// 		//reboot_ue();

	// 		restart_epc_enb();


	// 	} catch (Exception e) {
	// 		System.out.println("Exception caught while rebooting eNodeB and EPC");
	// 		System.out.println("Attempting again...");
	// 		handle_enb_epc_failure();
	// 	}
	// 	System.out.println("ENB EPC FAILURE HANDLING DONE.");

	// }

	/**
	 * Methods to kill and restart srsEPC and srsENB
	 */

	/// removed for connecting with the sample adapter in open-source version
	// public void start_epc_enb() {
	// 	// kill and start the processes
	// 	try {

	// 		kill_eNodeb();
	// 		sleep(2 * 1000);
	// 		kill_EPC();
	// 		sleep(2 * 1000);
	// 		start_EPC();
	// 		sleep(10 * 1000);
	// 		start_eNodeB();
	// 		sleep(30 * 1000);
	// 	} catch (InterruptedException e) {
	// 		start_epc_enb();
	// 		e.printStackTrace();
	// 	} catch (Exception e) {
	// 		start_epc_enb();
	// 		e.printStackTrace();
	// 	}
	// }

	/// removed for connecting with the sample adapter in open-source version
	// public void restart_epc_enb() {
	// 	try {

	// 		mme_out.close();
	// 		mme_in.close();
	// 		mme_socket.close();

	// 		enodeb_out.close();
	// 		enodeb_in.close();
	// 		enodeb_socket.close();

	// 		sleep(1000);

	// 		start_epc_enb();

	// 		init_epc_enb_con();

	// 		sqn_synchronized = false;

	// 	} catch (UnknownHostException e) {
	// 		e.printStackTrace();
	// 	} catch (SocketException e) {
	// 		e.printStackTrace();
	// 	} catch (Exception e) {
	// 		e.printStackTrace();
	// 	}
	// }


	public void init_adapter_con(){
		try{
			// Initialize adapter service
			System.out.println("Connecting to Adapter...");
			adapter_socket = new Socket(config.adapter_ip_address, config.adapter_port);
			adapter_socket.setTcpNoDelay(true);
			adapter_out = new BufferedWriter(new OutputStreamWriter(adapter_socket.getOutputStream()));
			adapter_in = new BufferedReader(new InputStreamReader(adapter_socket.getInputStream()));
			System.out.println("Connected with Adapter.");
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}


	/// removed for connecting with the sample adapter in open-source version

// 	public void init_epc_enb_con() {
// 		try {
// 			// Initialize test service
// 			System.out.println("Connecting to srsEPC...");
// 			mme_socket = new Socket(config.mme_controller_ip_address, config.mme_port);
// 			mme_socket.setTcpNoDelay(true);
// 			mme_out = new BufferedWriter(new OutputStreamWriter(mme_socket.getOutputStream()));
// 			mme_in = new BufferedReader(new InputStreamReader(mme_socket.getInputStream()));
// 			System.out.println("Connected with srsEPC.");

// 			System.out.println("Connecting to srsENB...");
// 			enodeb_socket = new Socket(config.enodeb_controller_ip_address, config.enodeb_port);
// 			enodeb_socket.setTcpNoDelay(true);
// 			enodeb_out = new BufferedWriter(new OutputStreamWriter(enodeb_socket.getOutputStream()));
// 			enodeb_in = new BufferedReader(new InputStreamReader(enodeb_socket.getInputStream()));
// 			System.out.println("Connected with srsENB.");

// 			String result = new String();
// 			try {
// 				sleep(2 * 1000);
// 				enodeb_out.write("Hello\n");
// 				enodeb_out.flush();
// 				result = enodeb_in.readLine();
// 				System.out.println("Received = " + result);
// 			}
// //			catch (ConnectException e){
// //				e.printStackTrace();
// //				start_epc_enb();
// //				init_epc_enb_con();
// //			}
// 			catch (SocketException e) {
// 				e.printStackTrace();
// 				start_epc_enb();
// 				init_epc_enb_con();
// 			} catch (IOException e) {
// 				e.printStackTrace();
// 				start_epc_enb();
// 				init_epc_enb_con();
// 			} catch (Exception e) {
// 				e.printStackTrace();
// 				start_epc_enb();
// 				init_epc_enb_con();
// 			}
// 			if (result.startsWith("ACK")) {
// 				System.out.println("PASSED: Testing the connection between the statelearner and the srsENB");
// 			}

// 		} catch (NullPointerException e) {
// 			e.printStackTrace();
// 			start_epc_enb();
// 			init_epc_enb_con();
// 		} catch (UnknownHostException e) {
// 			e.printStackTrace();
// 			start_epc_enb();
// 			init_epc_enb_con();
// 		} catch (ConnectException e) {
// 			e.printStackTrace();
// 			start_epc_enb();
// 			init_epc_enb_con();
// 		} catch (SocketException e) {
// 			e.printStackTrace();
// 			start_epc_enb();
// 			init_epc_enb_con();
// 		} catch (Exception e) {
// 			e.printStackTrace();
// 			start_epc_enb();
// 			init_epc_enb_con();
// 		}
// 		System.out.println("Connected to srsLTE");
// 	}

	/// removed for connecting with the sample adapter in open-source version

// 	public void init_ue_con() {
// 		try {
// 			System.out.println("Connecting to UE...");
// 			System.out.println("UE controller IP Address: " + config.ue_controller_ip_address);
// 			ue_socket = new Socket(config.ue_controller_ip_address, config.ue_port);
// 			ue_socket.setTcpNoDelay(true);
// 			//ue_socket.setSoTimeout(180*1000);
// 			System.out.println("Connected to UE");

// 			System.out.println("Initializing Buffers for UE...");
// 			ue_out = new BufferedWriter(new OutputStreamWriter(ue_socket.getOutputStream()));
// 			ue_in = new BufferedReader(new InputStreamReader(ue_socket.getInputStream()));
// 			System.out.println("Initialized Buffers for UE");

// 		} catch (UnknownHostException e) {
// 			e.printStackTrace();
// 		}
// //		catch (ConnectException e){
// //			e.printStackTrace();
// //		}
// 		catch (SocketException e) {
// 			e.printStackTrace();
// 		} catch (Exception e) {
// 			e.printStackTrace();
// 		}
// 	}

	/// removed for connecting with the sample adapter in open-source version
	// public boolean enb_alive() {
	// 	String result = "";
	// 	try {
	// 		enodeb_socket.setSoTimeout(5 * 1000);
	// 		enodeb_out.write("Hello\n");
	// 		enodeb_out.flush();
	// 		result = enodeb_in.readLine();
	// 		System.out.println("Received from Hello message in enb alive = " + result);
	// 		enodeb_socket.setSoTimeout(30 * 1000);
	// 	} catch (SocketTimeoutException e) {
	// 		e.printStackTrace();
	// 		return false;
	// 	} catch (Exception e) {
	// 		e.printStackTrace();
	// 		return false;
	// 	}

	// 	if (result.contains("ACK")) {
	// 		System.out.println("PASSED: Testing the connection between the statelearner and the srsENB");
	// 		return true;
	// 	} else {
	// 		System.out.println("FAILED: Testing the connection between the statelearner and the srsENB");
	// 		return false;
	// 	}
	// }

	/// removed for connecting with the sample adapter in open-source version
	// public boolean mme_alive() {
	// 	String result = "";
	// 	try {
	// 		mme_socket.setSoTimeout(5 * 1000);
	// 		mme_out.write("Hello\n");
	// 		mme_out.flush();
	// 		result = mme_in.readLine();
	// 		System.out.println("Received from Hello message in mme alive = " + result);
	// 		mme_socket.setSoTimeout(30 * 1000);

	// 	} catch (SocketTimeoutException e) {
	// 		e.printStackTrace();
	// 		return false;
	// 	} catch (Exception e) {
	// 		e.printStackTrace();
	// 		return false;
	// 	}

	// 	if (result.contains("ACK")) {
	// 		System.out.println("PASSED: Testing the connection between the statelearner and the srsEPC");
	// 		return true;
	// 	} else {
	// 		System.out.println("FAILED: Testing the connection between the statelearner and the srsEPC");
	// 		//return true;
	// 		return false;
	// 	}
	// }


	/// removed for connecting with the sample adapter in open-source version
	// public String reset_mme() {

	// 	String result = new String("");
	// 	System.out.println("Sending symbol: RESET to MME controller");
	// 	try {
	// 		sleep(1 * 1000);
	// 		mme_out.write("RESET " + reset_mme_count + "\n");
	// 		mme_out.flush();
	// 		result = mme_in.readLine();
	// 		System.out.println("ACK for RESET_MME: " + result);
	// 		reset_mme_count++;
	// 		if (result == null) {
	// 			return result;
	// 		}
	// 		String result1 = result.replaceAll("[^a-zA-Z]", "");
	// 		System.out.println(result1);
	// 		if (result == null) {
	// 			sleep(2000);
	// 			reset_mme();
	// 		}
	// 		if (result1.compareTo("DONE") != 0) {
	// 			//System.out.println(result.compareTo("DONE"));
	// 			System.out.println("$$$$$$$$$$$$$$$$IK$$$$$$$$$$$$$$$$$$$$");
	// 			if (result1.compareTo("attachrequest") != 0 || result1.compareTo("attachrequestguti") != 0) {
	// 				//send_enable_attach();
	// 				sleep(2000);
	// 			}
	// 			//sleep(1000);
	// 		}
	// 		//sleep(2*1000);
	// 	} catch (SocketException e) {
	// 		e.printStackTrace();
	// 	} catch (IOException e) {
	// 		e.printStackTrace();
	// 	}/*catch(InterruptedException e){
    //         e.printStackTrace();
    //     }*/ catch (Exception e) {
	// 		e.printStackTrace();
	// 	}
	// 	/*
	// 	try {
	// 		result = result.replaceAll("[^a-zA-Z]","");
	// 		System.out.println(result);
	// 		if (result.compareTo("DONE") != 0) {
	// 			//System.out.println(result.compareTo("DONE"));
	// 			System.out.println("$$$$$$$$$$$$$$$$IK$$$$$$$$$$$$$$$$$$$$");
	// 			//sleep(2000);
	// 		}
	// 	}catch (Exception e){
	// 		System.out.println("Howcome man!!");
	// 	}*/
	// 	return result;
	// }

	/// removed for connecting with the sample adapter in open-source version
	// public String reset_ue() {
	// 	String result = new String("");
	// 	System.out.println("Sending symbol: RESET to UE controller");
	// 	try {
	// 		sleep(1 * 1000);
	// 		adapter_out.write("RESET\n");
	// 		adapter_out.flush();
	// 		// result = adapter_in.readLine();
	// 		// System.out.println("ACK for RESET_UE: " + result);
	// 	} catch (SocketException e) {
	// 		e.printStackTrace();
	// 	} catch (IOException e) {
	// 		e.printStackTrace();
	// 	}/*catch(InterruptedException e){
    //         e.printStackTrace();
    //     }*/ catch (Exception e) {
	// 		e.printStackTrace();
	// 	}
	// 	return result;
	// }


	/// removed for connecting with the sample adapter in open-source version
	// public void send_sim_card_reset() {

	// 	try {
	// 		sleep(2000);
	// 		System.out.println("Sending symbol: SIM_CARD_RESET to UE controller");
	// 		enable_attach_count++;
	// 		ue_out.write("sim_card_reset\n");
	// 		ue_out.flush();
	// 		String result = new String("");
	// 		enable_attach_count++;
	// 		result = ue_in.readLine();
	// 		System.out.println("Result for sim_card_reset: " + result);
	// 		if (!result.contains("DONE")) {
	// 			send_sim_card_reset();
	// 		}


	// 	} /*catch (InterruptedException e) {
    //         e.printStackTrace();
    //     }*/ catch (SocketException e) {
	// 		e.printStackTrace();
	// 	} catch (IOException e) {
	// 		e.printStackTrace();
	// 	} catch (Exception e) {
	// 		e.printStackTrace();
	// 	}
	// }

	public void send_enable_attach() {

		try {
			// sleep(1000);
			// String result = new String("");
//            do {
//                mme_out.write("enable_attach\n");
//                mme_out.flush();
//                result = mme_in.readLine();
//                System.out.println("MME's ACK for enable_attach: " + result);
//            } while (!result.contains("DONE"));

			//sleep(1000);
			System.out.println("Sending symbol: enable_attach to UE controller");
			enable_attach_count++;
			adapter_out.write("enable_attach\n");
			adapter_out.flush();

			// enable_attach_count++;
			// result = ue_in.readLine();
			// System.out.println("UE controller's ACK for enable_attach: " + result);
			// if (!result.contains("DONE")) {
			// 	send_enable_attach();

			// }


		} catch (SocketException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	/// removed for connecting with the sample adapter in open-source version
	// public String reboot_ue() {
	// 	System.out.println("Sending REBOOT_UE command to UE_CONTROLLER");
	// 	String result = new String("");
	// 	try {
	// 		ue_out.write("ue_reboot\n"); // reboot the UE and turn cellular network ON with 4G LTE
	// 		ue_out.flush();
	// 		System.out.println("Waiting for the response from UE .... ");
	// 		result = ue_in.readLine();
	// 		System.out.println("UE's ACK for REBOOT: " + result);

	// 	} catch (SocketException e) {
	// 		e.printStackTrace();
	// 	} catch (IOException e) {
	// 		e.printStackTrace();
	// 	} catch (Exception e) {
	// 		e.printStackTrace();
	// 	}
	// 	return result;
	// }

	/// removed for connecting with the sample adapter in open-source version
//	public String restart_ue_adb_server() {
//		System.out.println("Sending adb restart-server command to UE_CONTROLLER");
//		String result = new String("");
//		try {
//			//sleep(2000);
//			ue_out.write("adb_server_restart\n");
//			ue_out.flush();
//			result = ue_in.readLine();
//			System.out.println("Result for adb_server_restart: " + result);
//		} catch (SocketException e) {
//			e.printStackTrace();
//		} catch (IOException e) {
//			e.printStackTrace();
//		} catch (Exception e) {
//			e.printStackTrace();
//		}
//		return result;
//	}

	/// removed for connecting with the sample adapter in open-source version
//	public static void start_eNodeB() {
//
//		runProcess(false, "src/start_enb.sh");
//	}

	/// removed for connecting with the sample adapter in open-source version
//	public static void start_EPC() {
//
//		runProcess(false, "src/start_epc.sh");
//
//	}

	/// removed for connecting with the sample adapter in open-source version
//	public static void kill_eNodeb() {
//		runProcess(false, "src/kill_enb.sh");
//	}

	/// removed for connecting with the sample adapter in open-source version
//	public static void kill_EPC() {
//		runProcess(false, "src/kill_epc.sh");
//	}

	/// removed for connecting with the sample adapter in open-source version
	
	// public void kill_process(String path, String nameOfProcess) {
	// 	ProcessBuilder pb = new ProcessBuilder(path);
	// 	Process p;
	// 	try {
	// 		p = pb.start();
	// 	} catch (IOException e) {
	// 		e.printStackTrace();
	// 	}

	// 	System.out.println("Killed " + nameOfProcess);
	// 	System.out.println("Waiting a second");
	// 	try {
	// 		TimeUnit.SECONDS.sleep(2);
	// 	} catch (InterruptedException e) {
	// 		e.printStackTrace();
	// 	}

	// 	String line;
	// 	try {
	// 		Process temp = Runtime.getRuntime().exec("pidof " + nameOfProcess);
	// 		BufferedReader input = new BufferedReader(new InputStreamReader(temp.getInputStream()));
	// 		line = input.readLine();
	// 		if (line != null) {
	// 			System.out.println("ERROR: " + nameOfProcess + " is still running after invoking kill script");
	// 			System.out.println("Attempting termination again...");
	// 			kill_process(path, nameOfProcess);
	// 		}
	// 	} catch (Exception e) {
	// 		e.printStackTrace();
	// 	}

	// 	System.out.println(nameOfProcess + " has been killed");
	// }

	/// removed for connecting with the sample adapter in open-source version
	// private void start_process(String path, String nameOfProcess) {
	// 	ProcessBuilder pb = new ProcessBuilder(path);
	// 	Process p;
	// 	try {
	// 		p = pb.start();
	// 		System.out.println(nameOfProcess + " process has started");
	// 		System.out.println("Waiting a second");
	// 		TimeUnit.SECONDS.sleep(2);
	// 	} catch (IOException e) {
	// 		System.out.println("IO Exception");
	// 		System.out.println("ERROR: " + nameOfProcess + " is not running after invoking script");
	// 		System.out.println("Attempting again...");
	// 		start_process(path, nameOfProcess);
	// 		e.printStackTrace();
	// 	} catch (InterruptedException e) {
	// 		System.out.println("Timer Exception");
	// 		System.out.println("ERROR: " + nameOfProcess + " is not running after invoking script");
	// 		System.out.println("Attempting again...");
	// 		start_process(path, nameOfProcess);
	// 		e.printStackTrace();
	// 	}


	// 	String line;
	// 	try {
	// 		Process temp = Runtime.getRuntime().exec("pidof " + nameOfProcess);
	// 		BufferedReader input = new BufferedReader(new InputStreamReader(temp.getInputStream()));

	// 		line = input.readLine();
	// 		if (line == null) {
	// 			System.out.println("ERROR: " + nameOfProcess + " is not running after invoking script");
	// 			System.out.println("Attempting again...");
	// 			start_process(path, nameOfProcess);
	// 		}
	// 	} catch (IOException e) {
	// 		e.printStackTrace();
	// 	}

	// 	System.out.println(nameOfProcess + " has started...");
	// }

	public static void runProcess(boolean isWin, String... command) {
		System.out.print("command to run: ");
		for (String s : command) {
			System.out.print(s);
		}
		System.out.print("\n");
		String[] allCommand = null;
		try {
			if (isWin) {
				allCommand = concat(WIN_RUNTIME, command);
			} else {
				allCommand = concat(OS_LINUX_RUNTIME, command);
			}
			ProcessBuilder pb = new ProcessBuilder(allCommand);
			pb.redirectErrorStream(true);

			Process p = pb.start();
			//			BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream()));
			//			String _temp = null;
			//			String line = new String("");
			//			while ((_temp = in.readLine()) != null) {
			//				System.out.println("temp line: " + _temp);
			//
			//				//line += _temp + "\n";
			//			}
			//            System.out.println("result after command: " + line);

			return;

		} catch (IOException e) {
			System.out.println("ERROR: " + command + " is not running after invoking script");
			System.out.println("Attempting again...");
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
			return;
		}

		System.out.println("SUCCESS: " + command + " is running");
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

	public String getClosests(String result) {
		if (expectedResults.contains(result)) {
			return result;
		}

		int minDistance = Integer.MAX_VALUE;
		String correctWord = null;


		for (String word : expectedResults) {
			int distance = computeLevenshteinDistance(result, word);

			if (distance < minDistance) {
				correctWord = word;
				minDistance = distance;
			}
		}
		return correctWord;
	}
}