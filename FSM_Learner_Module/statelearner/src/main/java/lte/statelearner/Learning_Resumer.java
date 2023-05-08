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

package lte.statelearner;

import java.io.*;
import java.util.*;
import java.util.HashMap;
import java.util.Map;
import java.sql.*;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;


public class Learning_Resumer {
    static final String url = "jdbc:sqlite:my_database.sqlite";
    String learning_log = "";
    String plain_replay_log = "";
    Map<String, String> learning_map = null;
    public LearningConfig config = null;
    Statement myStmt = null;

    public String getMD5(String password) throws Exception{
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hashInBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));

        StringBuilder sb = new StringBuilder();
        for (byte b : hashInBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();


    }


    public Learning_Resumer(String learning_log, String plain_replay_log){

        this.learning_log = learning_log;
        this.plain_replay_log = plain_replay_log;
        load_learning_log();
    }

    private void load_learning_log(){
        Connection myConn = null;
        try{
            if(myConn == null) {
                Class.forName("org.sqlite.JDBC");
                myConn = DriverManager.getConnection(url);
                 config = new LearningConfig("src/lteue.properties");
            }
        }catch(Exception e){
            System.out.println("DB Connection Error!");
            e.printStackTrace();
        }
        learning_map = new HashMap<>();
        try{

            String sql = "SELECT * FROM queryNew_"+ config.device ;
            Statement stmt = myConn.createStatement();
            ResultSet rs = stmt.executeQuery(sql);
        }catch (Exception e) {
            try {
                String create = "CREATE TABLE \"queryNew_"+config.device+"\""+"(\"id\"	TEXT,\"command\"	TEXT,\"resultHash\"	TEXT,\"result\"	TEXT,\"prefLen\"	INTEGER, PRIMARY KEY(\"id\"))";
                Statement stmt = myConn.createStatement();
                stmt.executeUpdate(create);
            }catch (Exception ex){
                System.out.println("Failed to create table");
            }
        }
        try{

            String sql = "SELECT * FROM query_"+ config.device ;
            Statement stmt = myConn.createStatement();
            ResultSet rs = stmt.executeQuery(sql);
        }catch (Exception e) {
            try {
                String create = "CREATE TABLE \"query_"+config.device+"\""+"(\"id\"	TEXT,\"command\"	TEXT,\"resultHash\"	TEXT,\"result\"	TEXT,\"prefLen\"	INTEGER, PRIMARY KEY(\"id\"))";
                Statement stmt = myConn.createStatement();
                stmt.executeUpdate(create);
            }catch (Exception ex){
                System.out.println("Failed to create table");
            }
        }
        try {

            //check query* is empty or not
            String sql = "SELECT * FROM queryNew_" + config.device;
            Statement stmt = myConn.createStatement();
            ResultSet rs = stmt.executeQuery(sql);
            if (rs.next()) {
                Statement st = myConn.createStatement();

                Statement st1 = myConn.createStatement();
                rs = st1.executeQuery("select * from queryNew_"+config.device);
                PreparedStatement ps = null;

                while (rs.next()) {
                    try {
                        ps = myConn.prepareStatement("insert into query_"+config.device+ " (id, command, resultHash, result, prefLen) values(?,?,?,?,?)");
                        ps.setString(1, rs.getString("id"));
                        ps.setString(2, rs.getString("command"));
                        ps.setString(3, rs.getString("resultHash"));
                        ps.setString(4, rs.getString("result"));
                        ps.setInt(5, rs.getInt("prefLen"));
                        ps.executeUpdate();
                        ps.close();
                    } catch (SQLException e) {
                        e.printStackTrace();
                    }
                }

                //Delete everything from query*
                sql = "delete from queryNew_" + config.device;
                st.executeUpdate(sql);
                System.out.println("Deleted all entries in queryNew");
                st1.close();
                stmt.close();
            }
            File f = new File(this.learning_log);
            File f1 = new File(this.plain_replay_log);
            if (f.createNewFile()) {

                System.out.println(this.learning_log + " file has been created.");
                System.out.println(this.plain_replay_log + " file has been created.");
            } else {

                System.out.println(this.learning_log + " file already exists.");
                System.out.println("Reading learning log: " + this.learning_log);
                System.out.println(this.plain_replay_log + " file already exists.");
                System.out.println("Reading learning log: " + this.plain_replay_log);
                PrintWriter writer = new PrintWriter(f);
                PrintWriter writer1 = new PrintWriter(f1);
                writer.print("");
                writer.close();
                writer1.print("");
                writer1.close();
            }
            myConn.close();

        }catch (IOException e){
            e.printStackTrace();
        }catch (SQLException e) {
            System.err.println("Duplicate Entry!");
            e.printStackTrace();
        }

    }

    public String query_resumer(String command, int prefLen) {
        Connection myConn = null;
        try{
            if(myConn == null) {
                Class.forName("org.sqlite.JDBC");
                myConn = DriverManager.getConnection(url);
            }
        }catch(Exception e){
            System.out.println("DB Connection Error!");
            e.printStackTrace();
        }
        System.out.println("In query resumer, looking for: " + command);
        String query = "select * from query_"+config.device+" where id = ? and prefLen = ?";
        command = command.replaceAll("\\|"," ");
        try{               
            PreparedStatement preparedstatement = myConn.prepareStatement(query);
            String commandPlusLen = command+prefLen;
            preparedstatement.setString (1, getMD5(commandPlusLen));
            preparedstatement.setInt (2, prefLen);
            ResultSet rs=preparedstatement.executeQuery();
            if(rs.next()){
                String fromDB = rs.getString("result");
                String[] splited = fromDB.split(" ");
                String prefix = "";
                String suffix = "";
                prefix = splited[0];
                for(int i=1;i <prefLen; i++){
                    prefix+= " "+ splited[i];
                }
                suffix = splited[prefLen];
                if(prefLen+1<fromDB.length()) {
                    for (int i = prefLen + 1; i < splited.length; i++) {
                        suffix += " " + splited[i];
                    }
                }
                System.out.println("found in log "+prefix+"|"+suffix);

                try{
                    String query2 = " insert into queryNew_"+config.device+ " (id, command, resultHash, result, suffLen)"
                            + " values (?, ?, ? ,?, ?)";
                    PreparedStatement preparedstatement2 = myConn.prepareStatement(query2);
                    preparedstatement2.setString(1, rs.getString("id"));
                    preparedstatement2.setString(2, rs.getString("command"));
                    preparedstatement2.setString(3, rs.getString("resultHash"));
                    preparedstatement2.setString(4, rs.getString("result"));
                    preparedstatement2.setInt(5, rs.getInt("suffLen"));
                    preparedstatement2.execute();
                    preparedstatement.close();
                    preparedstatement2.close();
                }catch (Exception e){
                    myConn.close();
                    System.out.println("Already exists in queryNew!");
                }
                myConn.close();
                return prefix+"|"+suffix;
            }else{
                return null;
            }
        }catch(Exception e){
            e.printStackTrace();
            return null;
        }
    }

    public void add_Entry(String entry, int prefLen) {
        Connection myConn = null;
        try{
            if(myConn == null) {
                Class.forName("org.sqlite.JDBC");
                myConn = DriverManager.getConnection(url);
            }
        }catch(Exception e){
            System.out.println("DB Connection Error!");
            e.printStackTrace();
        }
        System.out.println("In add!");
        try(BufferedWriter bw = new BufferedWriter(new FileWriter(this.learning_log, true))){
            bw.append(entry + '\n');
             
        } catch (Exception e){
            System.err.println("ERROR: Could not update learning log");

        }
        try(BufferedWriter bw1 = new BufferedWriter(new FileWriter(this.plain_replay_log, true))){
            String command = entry.split("/")[0].split("\\[")[1];
            String result = entry.split("/")[1].split("]")[0];
            command = String.join(" ", command.split("\\s+"));
            result = String.join(" ", result.split("\\s+"));
            command = command.replaceAll("\\|"," ");
            result = result.replaceAll("\\|"," ");
            String[] splited_command = command.split(" ");
            String[] splited_result = result.split(" ");
            for (int i=0;i<splited_command.length;i++){

                if(splited_command[i].startsWith("dl_nas_transport_plain")||
                        splited_command[i].startsWith("security_mode_command_replay") ||  splited_command[i].startsWith("GUTI_reallocation_replay")||
                        splited_command[i].startsWith("dl_nas_transport_replay") || splited_command[i].startsWith("rrc_reconf_replay") ||
                        splited_command[i].startsWith("rrc_security_mode_command_replay") || splited_command[i].startsWith("GUTI_reallocation_plain") ||
                        splited_command[i].startsWith("rrc_security_mode_command_downgraded") || splited_command[i].startsWith("rrc_reconf_downgraded") ||
                        splited_command[i].startsWith("attach_accept_no_integrity") || splited_command[i].contains("attach_accept_null_header") ||
                        splited_command[i].startsWith("security_mode_command_no_integrity") || splited_command[i].startsWith("security_mode_command_plain") ||
                        splited_command[i].startsWith("tau_accept_plain") || splited_command[i].startsWith("security_mode_command_ns_replay")
                ){
                    if(!splited_result[i].startsWith("null_action") && !splited_result[i].startsWith("security_mode_reject") && !splited_result[i].startsWith("auth_failure_seq") && !splited_result[i].startsWith("rrc_connection_reest_req")){
                        bw1.append(entry + '\n');
                    }
                }
            }

        } catch (Exception e){
            System.err.println("ERROR: Could not update learning log");

        }
        try{
            String command = entry.split("/")[0].split("\\[")[1];
            String result = entry.split("/")[1].split("]")[0];
            command = String.join(" ", command.split("\\s+"));
            result = String.join(" ", result.split("\\s+"));
            String query = " insert into queryNew_" +config.device+" (id, command, resultHash, result, prefLen)"
                    + " values (?, ?, ? ,?, ?)";
            command = command.replaceAll("\\|"," ");
            result = result.replaceAll("\\|"," ");
            result = result.replaceAll("attach_request_guti","attach_request");
            result = result.replaceAll("EXCEPTION","null_action");
            System.out.println("OUTPUT: "+ command+" "+result);

            PreparedStatement preparedStmt = myConn.prepareStatement(query);
            String commandPlusLen = command+prefLen;
            preparedStmt.setString(1, getMD5(commandPlusLen));
            preparedStmt.setString(2, command);
            preparedStmt.setString(3, getMD5(result));
            preparedStmt.setString(4, result);
            preparedStmt.setInt(5,prefLen);
            preparedStmt.execute();
            myConn.close();
            System.out.println("Added to DB! in Resumer");
        }catch (SQLException e) {
            System.out.println("history already exist in Add_Entry in QueryNew (Learning Resumer)!!");
        }catch(Exception e){
            System.out.println("DB add_Entry Error!");
        }
    }

}
