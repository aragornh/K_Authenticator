package com.cloudioh.k_anonymizer;

import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;

import com.agafua.syslog.SyslogHandler;

public class Authenticator {

	/**
	 * @param args
	 */

	static final Logger log = Logger.getLogger(Authenticator.class.getName());
	static final String AUTH_ERR = "ERR\n";
	static final String AUTH_OK = "OK\n";
	static SyslogHandler sh;
	
	public static void setupLog() {
		try {
			sh = new SyslogHandler();
			sh.setFormatter(new SimpleFormatter());
			log.addHandler(sh);
		} catch (SecurityException e) {
			e.printStackTrace();
		}
		
		log.setUseParentHandlers(false);
		log.setLevel(Level.INFO);
	}
	
	
	public static void main(String[] args) {		
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		OutputStreamWriter out = new OutputStreamWriter(System.out);
		setupLog();
		

		log.info("Authenticator Start...");
		try {
			EncryptionUtil.init();
			do {
				String user_info = in.readLine();
				if(user_info == null || user_info.isEmpty())
					break;
				
				String[] token = user_info.split(" ");
				if(token.length != 2){
					log.info("Incomplete user info");
					out.write(AUTH_ERR);
					out.flush();
					continue;
				}
				log.info(user_info);
				
				String certStr = token[1];
				log.info("cert:" + certStr);
				byte[] cert = Base64Coder.decode(certStr);
				try{
					if(EncryptionUtil.verifyCert(cert)){
						out.write(AUTH_OK);
						out.flush();
						log.info("Authentication OK");
					}else{
						out.write(AUTH_ERR);
						out.flush();
						log.info("Authentication FAILED");
					}
				}catch(Exception e){
					log.severe(e.toString());
				}
			} while (true);
		} catch (Exception e) {
			log.severe(e.toString());
		}
		
		try {
			in.close();
			out.close();
		} catch (Exception e){
		}

		log.info("Authenticator End...");
		System.exit(0);
	}
}
