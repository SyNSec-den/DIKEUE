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
            System.out.println("Properties not found!");
        }
        this.cache_log = cache_log;
        //this.load_cache_log();
    }

    public Connection getCacheConnection(){
        return DBHelper.getConnection();
    }


    /*
    private void load_cache_log(){
        cache_map = new HashMap<>();

        //System.out.println("Reading cache log: " + this.cache_log);

        try(BufferedReader br = new BufferedReader(new FileReader(this.cache_log))){
            String line;
            while ((line = br.readLine()) != null) {
                //System.out.println("cache log: " + line);
                if (line.contains("INFO")) {
                    //line = line.replaceAll("ε"," ");
                    String command = line.split("/")[0].replaceAll("\\|"," ").split("\\[")[1];
                    String result = line.split("/")[1].replaceAll("\\|"," ").split("]")[0];
                    command = String.join(" ", command.split("\\s+")).trim();
                    result = String.join(" ", result.split("\\s+")).trim();
                    cache_map.put(command, result);
                    //System.out.println("IN CACHE: " + command + "/" + result);
                    try {
                        String query = " insert into query (id, command, resultHash, result)"
                                + " values (?, ?, ? ,?)";
                        PreparedStatement preparedStmt = myConn.prepareStatement(query);
                        preparedStmt.setString(1, getMD5(command));
                        preparedStmt.setString(2, command);
                        preparedStmt.setString(3, getMD5(result));
                        preparedStmt.setString(4, result);
                        preparedStmt.execute();
                    }catch (SQLException e){
                       // System.out.println("history already exist");
                    }
                }
            }
        } catch (Exception e){
            System.err.println("ERROR: Could not cache log.");
            e.printStackTrace();
        }
    }
`   */
    public String query_cache(String command){
        //System.out.println("IK in query cache!");
        //System.out.println(command);
        Connection myConn = this.getCacheConnection();
        if (myConn == null){
            System.out.println("*** IN Cache.query_cache(): Cache DB Connection not established ***");
        }

        if (command == null){
            return null;
        }
        String query = command.trim();
        //System.out.println("Searching for in Cache: " + query);
        //System.out.println("Query Array: " + Arrays.toString(query.split("\\s+")));
        String[] split = query.split("\\s+");
        int prefLen =  split.length - 1;
        String commandPlusLen = command+prefLen;
        String Myquery = "select * from queryNew_"+config.device+ " where id = ?";

        try{
            PreparedStatement preparedstatement = myConn.prepareStatement(Myquery);
            preparedstatement.setString (1, getMD5(commandPlusLen));
            ResultSet rs=preparedstatement.executeQuery();
            if(rs.next()){
                //System.out.println("##################################################################### in Cache!");
                String saved_query = rs.getString("result");
//                myConn.close();
                preparedstatement.close();
                return saved_query;
            }else{
                return null;
            }
        }catch(Exception e){
            return null;
        }



        /*
        if (cache_map.containsKey(query)){
            return cache_map.get(query);
        } else {
            return null;
        }
        */
    }

    public void add_Entry(String entry) {
        Connection myConn = this.getCacheConnection();
        if (myConn == null){
            System.out.println("*** IN Cache.add_Entry(): Cache DB Connection not established ***");
        }

        try(BufferedWriter bw = new BufferedWriter(new FileWriter(this.cache_log, true))){
            bw.append(entry + '\n');
            //load_cache_log();
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
//            myConn.close();
            //System.out.println("Added to DB! in Cache");
        }catch (SQLException e) {
            //System.out.println("history already exist in Add_Entry!! in QueryNew (Cache)");
            //e.printStackTrace();

        }catch(Exception e){
            //System.out.println("DB add_Entry Error!");
            e.printStackTrace();

        }
    }

    public static void main(String[] args){
        Cache myCache = new Cache("src/cache.log");
        System.out.println(myCache.query_cache("enable_attach identity_request"));
    }
}
