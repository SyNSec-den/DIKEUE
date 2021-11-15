/*
 *  Author: Abdullah Al Ishtiaq
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

import java.sql.Connection;
import java.sql.DriverManager;

public class DBHelper {
    static final String url = "jdbc:sqlite:my_database.sqlite";
    static Connection dbConnection = null;

    public static Connection getConnection(){
        if(DBHelper.dbConnection == null) {
            try {
                Class.forName("org.sqlite.JDBC");
                DBHelper.dbConnection = DriverManager.getConnection(url);

            } catch (Exception e) {
                System.out.println("DB Connection Error!");
                e.printStackTrace();
            }
        }
        if(DBHelper.dbConnection == null){
            System.out.println("***** IN DBHelper.getConnection(): CONNECTION NULL *****");
            System.exit(0); // for testing
        }
        return DBHelper.dbConnection;
    }
}
