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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class Cache {

    String cache_log = "";
    Map<String, String> cache_map = null;
    static final String url = "jdbc:sqlite:my_database.sqlite";

    Statement myStmt = null;
    public LearningConfig config = null;


    public String getMD5(String password) throws Exception{
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hashInBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));

        StringBuilder sb = new StringBuilder();
        for (byte b : hashInBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();


    }
    public Cache(String cache_log){
        try{
            config = new LearningConfig("src/lteue.properties");
        }catch (Exception e){
            e.printStackTrace();
        }
        this.cache_log = cache_log;
    }


    public String query_cache(String command){
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
        if (command == null){
            return null;
        }
        String query = command.trim();
        String[] split = query.split("\\s+");
        int prefLen =  split.length - 1;
        String commandPlusLen = command+prefLen;
        String Myquery = "select * from queryNew_"+config.device+ " where id = ?";

        try{
            PreparedStatement preparedstatement = myConn.prepareStatement(Myquery);
            preparedstatement.setString (1, getMD5(commandPlusLen));
            ResultSet rs=preparedstatement.executeQuery();
            if(rs.next()){
                String saved_query = rs.getString("result");
                myConn.close();
                preparedstatement.close();
                return saved_query;
            }else{
                return null;
            }
        }catch(Exception e){
            return null;
        }
    }

    public void add_Entry(String entry) {
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
        try(BufferedWriter bw = new BufferedWriter(new FileWriter(this.cache_log, true))){
            bw.append(entry + '\n');
        } catch (Exception e){
            System.err.println("ERROR: Could not update learning log");

        }
        try{
            String query = " insert into queryNew_"+ config.device+ " (id, command, resultHash, result)"
                    + " values (?, ?, ? ,?)";
            String command = entry.split("/")[0].replaceAll("\\|"," ").split("\\[")[1];
            String result = entry.split("/")[1].replaceAll("\\|"," ").split("]")[0];
            command = String.join(" ", command.split("\\s+")).trim();
            result = String.join(" ", result.split("\\s+")).trim();
            PreparedStatement preparedStmt = myConn.prepareStatement(query);
            preparedStmt.setString(1, getMD5(command));
            preparedStmt.setString(2, command);
            preparedStmt.setString(3, getMD5(result));
            preparedStmt.setString(4, result);
            preparedStmt.execute();
            preparedStmt.close();
            myConn.close();
        }catch (SQLException e) {
            e.printStackTrace();
        }catch(Exception e){
            e.printStackTrace();
        }
    }

    public static void main(String[] args){
        Cache myCache = new Cache("src/cache.log");
        System.out.println(myCache.query_cache("enable_s1 identity_request"));
    }
}
