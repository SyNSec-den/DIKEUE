/*
 *  Modified by Imtiaz Karim, Syed Rafiul Hussain, Abdullah Al Ishtiaq
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

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Configuration class used for learning parameters
 * 
 * @author Syed Rafiul Hussain, Imtiaz Karim, Abdullah Al Ishtiaq, Omar Chowdhury, and Elisa Bertino
 */
public class LearningConfig {
	static int TYPE_LTEUE = 4;
	
	protected Properties properties;
	
	int type = TYPE_LTEUE;
	
	String output_dir = "output";
	
	String learning_algorithm = "lstar";
	String eqtest = "randomwords";
	
	// Used for W-Method and Wp-method
	int max_depth = 5;
	
	// Used for Random words
	int min_length = 5;
	int max_length = 10;
	int nr_queries = 100;
	int seed = 1;

	public String device = null;

	boolean resume_learning_active = false;
	String path_to_resuming_log = "";
	String path_to_plain_replay = "";

	boolean cache_active = false;
	String path_to_cache_log = "";
	
	public LearningConfig(String filename) throws IOException {
		properties = new Properties();

		InputStream input = new FileInputStream(filename);
		properties.load(input);

		loadProperties();
	}
	
	public LearningConfig(LearningConfig config) {
		properties = config.getProperties();
		loadProperties();
	}
	
	public Properties getProperties() {
		return properties;
	}

	public void loadProperties() {
		if(properties.getProperty("output_dir") != null)
			output_dir = properties.getProperty("output_dir");
		
		if(properties.getProperty("type") != null) {
			if(properties.getProperty("type").equalsIgnoreCase("lteue"))
				type = TYPE_LTEUE;
		}
		
		if(properties.getProperty("learning_algorithm").equalsIgnoreCase("lstar") || properties.getProperty("learning_algorithm").equalsIgnoreCase("dhc") || properties.getProperty("learning_algorithm").equalsIgnoreCase("kv") || properties.getProperty("learning_algorithm").equalsIgnoreCase("ttt") || properties.getProperty("learning_algorithm").equalsIgnoreCase("mp") || properties.getProperty("learning_algorithm").equalsIgnoreCase("rs"))
			learning_algorithm = properties.getProperty("learning_algorithm").toLowerCase();
		
		if(properties.getProperty("eqtest") != null && (properties.getProperty("eqtest").equalsIgnoreCase("wmethod") || properties.getProperty("eqtest").equalsIgnoreCase("modifiedwmethod") || properties.getProperty("eqtest").equalsIgnoreCase("wpmethod") || properties.getProperty("eqtest").equalsIgnoreCase("randomwords")))
			eqtest = properties.getProperty("eqtest").toLowerCase();
		
		if(properties.getProperty("max_depth") != null)
			max_depth = Integer.parseInt(properties.getProperty("max_depth"));
		
		if(properties.getProperty("min_length") != null)
			min_length = Integer.parseInt(properties.getProperty("min_length"));


		if(properties.getProperty("device") != null)
			device = properties.getProperty("device");
		if(properties.getProperty("max_length") != null)
			max_length = Integer.parseInt(properties.getProperty("max_length"));
		
		if(properties.getProperty("nr_queries") != null)
			nr_queries = Integer.parseInt(properties.getProperty("nr_queries"));
		
		if(properties.getProperty("seed") != null)
			seed = Integer.parseInt(properties.getProperty("seed"));

		if(properties.getProperty("resume_learning") != null){
			String resume_learning = properties.getProperty("resume_learning");
			if (resume_learning.matches("true")){
				resume_learning_active = true;
			}
			else{
				resume_learning_active = false;
			}
		}

		if(properties.getProperty("path_to_resuming_log") != null){
			path_to_resuming_log = properties.getProperty("path_to_resuming_log");
		}
		if(properties.getProperty("path_to_plain_replay") != null){
			path_to_plain_replay = properties.getProperty("path_to_plain_replay");
		}
		if(properties.getProperty("cache_active") != null){
			String cache_active_str = properties.getProperty("cache_active");
			if (cache_active_str.matches("true")){
				cache_active = true;
			}
		}

		if(properties.getProperty("path_to_cache_log") != null){
			path_to_cache_log = properties.getProperty("path_to_cache_log");
		}

	}
}
