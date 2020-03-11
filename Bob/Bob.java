//Done by: Aaron Lim
//Student ID: 5985171

import java.net.*;
import java.util.*;
import java.io.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// Java program to calculate SHA-1 hash value 
// https://www.geeksforgeeks.org/sha-1-hash-in-java/

// Java program to compute RC4
// Author: Siva
// https://github.com/sivasrinivas/NetSec/blob/master/RC4.java

public class Bob {   
    public static void main(String[] args)throws NoSuchAlgorithmException, SocketException, IOException {
    	readFile rf = new readFile();
    	rf.openFile();
    	
    	String pwPG[] = new String[3];
    	pwPG = rf.reading();
    	String password = pwPG[0];
    	String p = pwPG[1];
    	String g = pwPG[2];
    	boolean shutDownSystem = false;
    	String generated[] = new String[2];
    	String sessionKey = "";
    	
    	//sender and receiver buffer
	byte[] sendbuffer = new byte[1024];
	byte[] receivebuffer = new byte[1024];

	//IP and socket
	InetAddress IP = InetAddress.getByName("127.0.0.1");
	DatagramSocket clientSocket = new DatagramSocket();
	byte[] key = password.getBytes();
	testRC4 rc = new testRC4(new String(key));
	int portno = 9876;
    	
    	while(!shutDownSystem){
    		if(!shutDownSystem){
    			shutDownSystem = rf.checkPW(shutDownSystem, password, sendbuffer, receivebuffer, IP, clientSocket, key, rc, portno);
    		}
    		if(!shutDownSystem){
    			generated = rf.generateSessionKey(shutDownSystem, p, g, sendbuffer, receivebuffer, IP, clientSocket, key, rc, portno);
    			if(generated[0].equals("true")){
    				shutDownSystem = true;
    			}
    			else if(generated[0].equals("false")){
    				shutDownSystem = false;
    			}
    			sessionKey = generated[1];
    		}
    		GFG sha1 = new GFG();
		if(!shutDownSystem){
			/*
			clientServer ser = new clientServer();
			ser.getSessionKey(sessionKey, password);
			ser.run();
			shutDownSystem = true;
			*/
			shutDownSystem = rf.sha1Message(shutDownSystem, sha1, sendbuffer,  receivebuffer, IP, clientSocket, sessionKey, rc);
		}
    	}
    	clientSocket.close();
    }
}

//reading file
class readFile{
	private Scanner sc;
	public void openFile(){
		try{
			sc = new Scanner(new File("password.txt"));
		}
		catch(Exception e){
			System.out.println("File does not exist");
		}
	}
	
	
	public boolean sha1Message(boolean shutDownSystem, GFG sha1, byte[] sendbuffer, byte[] receivebuffer, InetAddress IP, DatagramSocket clientSocket,  String sessionKey, testRC4 rc) throws NoSuchAlgorithmException, SocketException, IOException{
		boolean ok = true;
		int portno = 9876;
		Scanner sc = new Scanner(System.in);
		int inside = 0;
		System.out.println("Enter: quit to exit the program");
		while(ok){
			if(inside == 1){
				//receive from server
				receivebuffer = new byte[1024];
				DatagramPacket receivePacket = new DatagramPacket(receivebuffer, receivebuffer.length);
				clientSocket.receive(receivePacket);
				//byte[] data = receivePacket.getData();
				
				byte[] storing = new byte[receivePacket.getLength()];
				for(int i = 0; i < receivePacket.getLength();i++){
					storing[i] = receivebuffer[i];
				}
				
				//byte[] passwordKey = password.getBytes();
				//testRC4 rc = new testRC4(new String(passwordKey));
				
				String printing = decryptMessage(storing, rc, sha1, sessionKey);
				System.out.println(printing);
				printing = "";
				inside = 0;
			}
			
			if(inside == 0){
				System.out.print("Client: ");
				String sendMsg = sc.nextLine();
	
				if(sendMsg.equals("exit")){
					System.out.println("Good bye, client shutting down");
					ok = false;
					shutDownSystem = true;
					
					//byte[] passwordKey = password.getBytes();
					//testRC4 rc = new testRC4(new String(passwordKey));
					
					byte[] enText = encryptMessage(sendMsg, rc, sha1, sessionKey);
					sendbuffer = enText;        
					DatagramPacket sendPacket = new DatagramPacket(sendbuffer, sendbuffer.length, IP, portno);
					clientSocket.send(sendPacket);
				
					break;
				}
				
				//byte[] passwordKey = password.getBytes();
				//testRC4 rc = new testRC4(new String(passwordKey));
				
				byte[] enText = encryptMessage(sendMsg, rc, sha1, sessionKey);
				sendbuffer = enText;        
				DatagramPacket sendPacket = new DatagramPacket(sendbuffer, sendbuffer.length, IP, portno);
				clientSocket.send(sendPacket);
				inside = 1;
				
			}
		}
		return shutDownSystem;
	}
	
	public synchronized byte[] encryptMessage(String serverMsg, testRC4 rc, GFG sha1, String sessionKey){
		byte[] cipherText = new byte[1];
		try{
			String H = serverMsg + "||" + sessionKey;
			String hashing = sha1.encryptThisString(H);
			String conHash = serverMsg + "||" + hashing;
			cipherText = rc.encrypt(conHash.getBytes());
		}
		catch(Exception e){
			e.printStackTrace();
			cipherText = new byte[1];
		}
		return cipherText;
	}
	
	public synchronized String decryptMessage(byte[] encrypted, testRC4 rc, GFG sha1, String sessionKey){
		String returnMsg = "";
		byte[] deText = rc.decrypt(encrypted);
		String[] splitText = new String(deText).split("\\|\\|");
		String hash = splitText[1];
		String msg = splitText[0];
		String hPrime = sha1.encryptThisString(msg + "||" + sessionKey);
		
		//hash = excludeGibberish(hash);
		
		if(hPrime.equalsIgnoreCase(hash)){
			returnMsg = "Server: " + msg;
		}
		else{
			returnMsg = "Someone tried to send a fake message";
		}
		return returnMsg;
	}
	
	
	public String excludeGibberish(String hashing){
		boolean check = true;
		String hashWord = "";
		char checkChar = 'a';
		int i = 0;
		while(check){
			checkChar = hashing.charAt(i);
			if(Character.isDigit(checkChar) || Character.isLetter(checkChar)){
				hashWord += checkChar;
				i++;
			}
			else{
				check = false;
			}
		}
		
		return hashWord;
	}
	
	public boolean checkPW(boolean shutDownSystem, String password, byte[] sendbuffer, byte[]receivebuffer, InetAddress IP, DatagramSocket clientSocket, byte[] key, testRC4 rc, int portno) throws SocketException, IOException{
		boolean ok = true;
		String pw = "";
		Scanner s = new Scanner(System.in);
		while(ok){
			System.out.println("To quit please enter: exit");
			System.out.println("Password: " + password);
			System.out.print("Please enter the password: ");
			pw = s.next();
			//check password with server
			String encrypted = "";
			byte[] enText = encrypted.getBytes();


			try{
				enText = rc.encrypt(pw.getBytes());
				//encrypted = new String(enText, "UTF-8");
				//System.out.println("Encrypter is " + encrypted);
				//byte[] deText = rc.decrypt(enText);
				//System.out.println("Decrypted is " + new String(deText));
			}
			catch(Exception e){
				e.printStackTrace();
			}
		
			//check if user typed exit
			if(pw.equals("exit")){
				System.out.println("Good bye, client shutting down");
				ok = false;
				shutDownSystem = true;
				sendbuffer = enText;        
				DatagramPacket sendPacket = new DatagramPacket(sendbuffer, sendbuffer.length, IP, portno);
				clientSocket.send(sendPacket);
				break;
			}
			
			//System.out.println("enText: " + enText);
		
			sendbuffer = enText;        
			DatagramPacket sendPacket = new DatagramPacket(sendbuffer, sendbuffer.length, IP, portno);
			clientSocket.send(sendPacket);
		
			//receive from server
			DatagramPacket receivePacket = new DatagramPacket(receivebuffer, receivebuffer.length);
			clientSocket.receive(receivePacket);
			byte[] data = receivePacket.getData();
		
			byte[] b = data;
		
			byte[] deText = rc.decrypt(b);
		
			String con = new String(deText);
			String trueOrFalse = con.substring(0, 4);
			String okOrNot = "true";
		
			if(trueOrFalse.equals(okOrNot)){
			
				System.out.println("Correct password, please proceed to enter your secret key...");
				ok = false;
			}
	
			else{
				System.out.println("Incorrect password, please try again");
			}
		}
		return shutDownSystem;
	}
	
	public String[] generateSessionKey(boolean shutDownSystem, String p, String g, byte[] sendbuffer, byte[]receivebuffer, InetAddress IP, DatagramSocket clientSocket, byte[] key, testRC4 rc, int portno) throws SocketException, IOException{
		Scanner sc = new Scanner(System.in);
		BigInteger bigG;
		BigInteger bigP;
		BigInteger sessionKey;
		BigInteger YB;
		BigInteger YA;
		BigInteger XB = new BigInteger("1");
		String s = "";
		boolean ok = true;	
		while(ok){
			int pp = Integer.parseInt(p);
			int gg = Integer.parseInt(g);
			
			bigG = BigInteger.valueOf(gg);
			bigP = BigInteger.valueOf(pp);

			
			String encrypted = "";
			byte[]enText = encrypted.getBytes();
			

			Random rand = new Random();
			int xb = rand.nextInt(pp-2)+1;
			//generate YB
			XB = BigInteger.valueOf(xb);
			YB = bigG.modPow(XB, bigP);
		
			String YBB = String.valueOf(YB);
		
			encrypted = "";
			enText = encrypted.getBytes();
			//encrypt YBB
			try{
				enText = rc.encrypt(YBB.getBytes());
				encrypted = new String(enText, "UTF-8");
				//System.out.println("Encrypter is " + encrypted);
				//byte[] deText = rc.decrypt(enText);
				//System.out.println("Decrypted is " + new String(deText));
			}
			catch(Exception e){
				e.printStackTrace();
			}
			
			System.out.println("Generating YB and communicating with server to develop session key...");
			System.out.println("Sending over YB to server...");
			sendbuffer = enText; 
			
			DatagramPacket sendPacket = new DatagramPacket(sendbuffer, sendbuffer.length, IP, portno);
			clientSocket.send(sendPacket);
			
			//receive from server
			DatagramPacket receivePacket = new DatagramPacket(receivebuffer, receivebuffer.length);
			clientSocket.receive(receivePacket);
			byte[] data = receivePacket.getData();
			
			byte[] b = data;
			//System.out.println("client data bytes: " + b);
			
			byte[] deText = rc.decrypt(b);
			
			String con = new String(deText);
			
			Pattern ppp = Pattern.compile("\\d+");
			Matcher m = ppp.matcher(con);
			int ya = 0;
			if(m.find()) {
		    		ya = Integer.parseInt(m.group(0));
			}
			
			YA = BigInteger.valueOf(ya);
			
			sessionKey = YA.modPow(XB, bigP);
			
			ok = false;
			shutDownSystem = false;
			s = sessionKey.toString();
			
			//System.out.println("Generated session key: " + s);
			
			break;
		}
		String generated[] = new String[2];
		if(shutDownSystem){
			generated[0] = "true";
		}
		else if(!shutDownSystem){
			generated[0] = "false";
		}

		generated[1] = s;
		return generated;
	}
	
	public boolean checkNumber(String keyB){
		boolean check = true;
		char checkChar = 'a';
		for(int i = 0; i < keyB.length(); i++){
			checkChar = keyB.charAt(i);
			if(Character.isDigit(checkChar) || Character.isLetter(checkChar)){
				i++;
			}
			else{
				check = false;
			}
		}
		return check;
	}
	
	public boolean checkP(String keyB, String p){
		if(keyB.length() > p.length()){
			return false;
		}
		return true;
	}
	
	public String[] reading() throws SocketException, IOException{
		//step 1: reading password p g
		String p = "";
		String password = "";
		String g = "";
		while(sc.hasNext()){
			password = sc.next();
			p = sc.next();
			g = sc.next();
		}
		sc.close();
		
		String pwPG[] = new String[3];
		pwPG[0] = password;
		pwPG[1] = p;
		pwPG[2] = g;
		
		return pwPG;
	}
}

class testRC4{
	static short[] S;
	static short[] T;

	public testRC4(String keyString) {
		if (keyString.length() < 1 && keyString.length() > 256) {
			throw new IllegalArgumentException("Key lenght should be in between 1 and 256");
		}

		byte[] tempKey = keyString.getBytes();
		short[] key = new short[tempKey.length];
		int keyLength = tempKey.length;

		for (int i = 0; i < keyLength; i++) {
			key[i] = (short) ((short) tempKey[i] & 0xff);
		}
		ksa(key);
	}
	
	public void ksa(short[] key) {
		short temp;
		S = new short[256];
		T = new short[256];

		for (int i = 0; i < 256; i++) {
			S[i] = (short) i;
		}

		int j = 0;
		for (int i = 0; i < 256; i++) {
			j = (j + S[i] + key[i % key.length]) % 256;

			temp = S[i];
			S[i] = S[j];
			S[j] = temp;
		}
		System.arraycopy(S, 0, T, 0, S.length);
	}

	public byte[] genPad(int length) {
		System.arraycopy(S, 0, T, 0, S.length);
		int i = 0, j = 0;
		short temp;
		byte[] tempPpad = new byte[length];
		for (int k = 0; k < length; k++) {
			i = (i + 1) % 256;
			j = (j + T[i]) % 256;

			temp = T[i];
			T[i] = T[j];
			T[j] = temp;

			tempPpad[k] = (byte) (T[(T[i] + T[j]) % 256]);
		}
		return tempPpad;
	}

	public byte[] encrypt(byte[] plain) {
		byte[] pad = genPad(plain.length);
		byte[] encrypt = new byte[plain.length];
		for (int i = 0; i < plain.length; i++) {
			encrypt[i] = (byte) (plain[i] ^ pad[i]);
		}
		return encrypt;
	}

	public byte[] decrypt(byte[] cipher) {
		byte[] plain = encrypt(cipher);
		return plain;
	}
}

class GFG { 
    public static String encryptThisString(String input) 
    { 
        try { 
            // getInstance() method is called with algorithm SHA-1 
            MessageDigest md = MessageDigest.getInstance("SHA-1"); 
  
            // digest() method is called 
            // to calculate message digest of the input string 
            // returned as array of byte 
            byte[] messageDigest = md.digest(input.getBytes()); 
  
            // Convert byte array into signum representation 
            BigInteger no = new BigInteger(1, messageDigest); 
  
            // Convert message digest into hex value 
            String hashtext = no.toString(16); 
  
            // Add preceding 0s to make it 32 bit 
            while (hashtext.length() < 32) { 
                hashtext = "0" + hashtext; 
            } 
  
            // return the HashText 
            return hashtext; 
        } 
  
        // For specifying wrong message digest algorithms 
        catch (NoSuchAlgorithmException e) { 
            throw new RuntimeException(e); 
        } 
    } 
}
