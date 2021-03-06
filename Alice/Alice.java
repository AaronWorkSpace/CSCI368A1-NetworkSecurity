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

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;

// Java program to calculate SHA-1 hash value 
// https://www.geeksforgeeks.org/sha-1-hash-in-java/

// Java program to compute RC4
// Author: Siva
// https://github.com/sivasrinivas/NetSec/blob/master/RC4.java

public class Alice{
	public static void main(String[] args) throws NoSuchAlgorithmException, SocketException, IOException {
		boolean shutDownSystem = false;
		//step 1: writing password p g xa (secret key for Alice) 
		readFile rf = new readFile();
		String pwPG[] = new String[3];
		rf.openFile();
		pwPG = rf.reading();
		
		int portno = 9876;
		
		String password = pwPG[0];
		BigInteger p = new BigInteger(pwPG[1]);
		BigInteger g = new BigInteger(pwPG[2]);
		Random rand = new Random();
		shutDownSystem = false;
		
		byte[] key = password.getBytes();
		testRC4 rc = new testRC4(new String(key));
		
		DatagramSocket serverSocket = new DatagramSocket(9876);
		
		String sessionKey = "";
		String generated[] = new String[2];
		while(!shutDownSystem){
			if(!shutDownSystem){
				shutDownSystem = rf.checkPW(shutDownSystem, password, key, rc, serverSocket);
			}
			//exchanging key with rc4
			if(!shutDownSystem){
				generated = rf.generateSessionKey(shutDownSystem, p, g, key, rc, serverSocket, rand);
				if(generated[0].equals("true")){
    				shutDownSystem = true;
	    			}
	    			else if(generated[0].equals("false")){
	    				shutDownSystem = false;
	    			}
	    			sessionKey = generated[1];
			}
			
			// Driver code for sha1, sha1.encryptThisString("message")
			GFG sha1 = new GFG();
			if(!shutDownSystem){
				/*
				server ser = new server();
				ser.getSessionKey(sessionKey, password);
				ser.run();
				shutDownSystem = true;
				*/
				shutDownSystem = rf.sha1Message(shutDownSystem, sha1, sessionKey, password, serverSocket, rc);
			}
		}
		serverSocket.close();
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

class testRC4 {

    /**
     * @param args
     */
    static short[] S;
    static short[] T;

    public testRC4(String keyString) {

        if (keyString.length() < 1 && keyString.length() > 256) {
            throw new IllegalArgumentException("Key length should be in between 1 and 256");
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

class readFile{
	private static int portno = 0;
	private static InetAddress IP = null;
	private Scanner sc;
	public void openFile(){
		try{
			sc = new Scanner(new File("password.txt"));
		}
		catch(Exception e){
			System.out.println("File does not exist");
		}
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
	
	public boolean sha1Message(boolean shutDownSystem, GFG sha1, String sessionKey, String password, DatagramSocket serverSocket, testRC4 rc) throws NoSuchAlgorithmException, SocketException, IOException{
		byte[] receivebuffer = new byte[1024];
		byte[] sendbuffer  = new byte[1024];
		boolean ok = true;
		System.out.println("Server awaiting message...");
		Scanner sc = new Scanner(System.in);
		int inside = 1;
		//int portno = 9876;
		String serverMsg;
		String printing;
		while(ok){
			if(inside == 1){
				try{
					printing = "";
					receivebuffer = new byte[1024];
					//DatagramSocket serverSocket = new DatagramSocket(9876);
					DatagramPacket recvdpkt = new DatagramPacket(receivebuffer, receivebuffer.length);
					serverSocket.receive(recvdpkt);
					//InetAddress IP = recvdpkt.getAddress();
					//byte[] clientData = recvdpkt.getData();
					
					byte[] storing = new byte[recvdpkt.getLength()];
					for(int i = 0; i < recvdpkt.getLength();i++){
						storing[i] = receivebuffer[i];
					}
					
					//byte[] passwordKey = password.getBytes();
					//testRC4 rc = new testRC4(new String(passwordKey));
					
					printing = decryptMessage(storing, rc, sha1, sessionKey);
					
					if(printing.equalsIgnoreCase("exit")){
						ok = false;
						shutDownSystem = true;
						System.out.println("Client had exited the program, server shutting down");
						break;
					}
					
					System.out.println("Client: " + printing);
					printing = "";
					inside = 0;
				}catch(Exception e){
				}
			}
			
			if(inside == 0){
				try{
					serverMsg = "";
					//DatagramSocket serverSocket = new DatagramSocket(9876);
					System.out.print("Server: ");
					serverMsg = sc.nextLine();
					//byte[] passwordKey = password.getBytes();
					//testRC4 rc = new testRC4(new String(passwordKey));
					byte[] enText = encryptMessage(serverMsg, rc, sha1, sessionKey);
					//InetAddress IP = InetAddress.getByName("127.0.0.1");
			
					BufferedReader serverRead = new BufferedReader(new InputStreamReader (System.in) );
					sendbuffer = enText;
					DatagramPacket sendPacket = new DatagramPacket(sendbuffer, sendbuffer.length, IP,portno);
					serverSocket.send(sendPacket);
					inside = 1;
			
				}catch(Exception e){
				}
			} 
		}
		
		return shutDownSystem;
	}
		
	public byte[] encryptMessage(String serverMsg, testRC4 rc, GFG sha1, String sessionKey){
		byte[] cipherText = new byte[1];
		try{
			String H = serverMsg + "||" +  sessionKey;
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
		
		//System.out.println("hash: " + hash);
		
		if(hPrime.equals(hash)){
			returnMsg = msg;
		}
		else{
			returnMsg = "Someone tried to send a fake message";
		}
		return returnMsg;
	}
	
	public synchronized String excludeGibberish(String hashing){
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
	
	public boolean checkPW(boolean shutDownSystem, String password, byte[] key, testRC4 rc, DatagramSocket serverSocket) throws NoSuchAlgorithmException, SocketException, IOException{
		
		byte[] receivebuffer = new byte[1024];
		byte[] sendbuffer  = new byte[1024];

		//int portno = 0;
	
		boolean ok = true;
		
		System.out.println("Awaiting client to key in password...");
		while(ok){
			//check password decrypt with rc4
			
		
			System.out.println("Computing password...");
			DatagramPacket recvdpkt = new DatagramPacket(receivebuffer, receivebuffer.length);
			serverSocket.receive(recvdpkt);
			IP = recvdpkt.getAddress();
			portno = recvdpkt.getPort();
			//byte[] clientData = recvdpkt.getData();
			//byte[] b = clientData;
			//System.out.println("client data bytes: " + b);
			
			//byte[] deText = rc.decrypt(b);
			
			byte[] storing = new byte[recvdpkt.getLength()];
			for(int i = 0; i < recvdpkt.getLength();i++){
				storing[i] = receivebuffer[i];
			}
			byte[] deText = rc.decrypt(storing);
		
			storing = rc.decrypt(storing);
			String con = new String(storing);
			
			//String quit = con.substring(0,4);
			//String pw = excludeGibberish(con);
			
			if(con.equalsIgnoreCase("exit")){
				System.out.println("Client had exited the program, server shutting down");
				shutDownSystem = true;
				ok = false;
				break;
			}
			
			if(con.equals(password)){
				System.out.println("Password correct..awaiting for YB...");
				ok = false;
				
				String encrypted = "";
				byte[] enText = encrypted.getBytes();
				String plainText = "true";
				try{
					enText = rc.encrypt(plainText.getBytes());
					encrypted = new String(enText, "UTF-8");
					//System.out.println("Encrypter is " + encrypted);
					//byte[] deText = rc.decrypt(enText);
					//System.out.println("Decrypted is " + new String(deText));
				}
				catch(Exception e){
					e.printStackTrace();
				}
				
				BufferedReader serverRead = new BufferedReader(new InputStreamReader (System.in) );
				sendbuffer = enText;
				DatagramPacket sendPacket = new DatagramPacket(sendbuffer, sendbuffer.length, IP,portno);
				serverSocket.send(sendPacket); 
			}
			
			else{
				System.out.println("Incorrect password..awaiting for correct password...");
				String plainText = "false";
				byte[] enText = "".getBytes();
				try{
					enText = rc.encrypt(plainText.getBytes());
				}
				catch(Exception e){
					e.printStackTrace();
				}
				
				BufferedReader serverRead = new BufferedReader(new InputStreamReader (System.in) );
				sendbuffer = enText;
				DatagramPacket sendPacket = new DatagramPacket(sendbuffer, sendbuffer.length, IP,portno);
				serverSocket.send(sendPacket); 
			}
		}
		
		return shutDownSystem;
	}
	
	public String[] generateSessionKey(boolean shutDownSystem, BigInteger p, BigInteger g, byte[] key, testRC4 rc, DatagramSocket serverSocket, Random rand) throws NoSuchAlgorithmException, SocketException, IOException {
		
		BigInteger sessionKey;
		BigInteger YB;
		BigInteger YA;
		BigInteger XA;
		String s = "";
		boolean ok = true;
		while(ok){
			byte[] receivebuffer = new byte[1024];
			byte[] sendbuffer  = new byte[1024];
			DatagramPacket recvdpkt = new DatagramPacket(receivebuffer, receivebuffer.length);
			serverSocket.receive(recvdpkt);
			//InetAddress IP = recvdpkt.getAddress();
			//int portno = recvdpkt.getPort();
			byte[] clientData = recvdpkt.getData();
			
			byte[] b = clientData;
			//System.out.println("client data bytes: " + b);
			
			byte[] deText = rc.decrypt(b);
			
			String con = new String(deText);
			
			String goodBye = excludeGibberish(con);
			
			/*
			if(goodBye.equals("exit")){
				System.out.println("Client had exited the program, server shutting down");
				shutDownSystem = true;
				ok = false;
				s = "";
				break;
			}
			*/
			
			System.out.println("Computing session key and sending session key part...");
			
			Pattern pp = Pattern.compile("\\d+");
			Matcher m = pp.matcher(con);
			int yb = 0;
			if(m.find()) {
		    		yb = Integer.parseInt(m.group(0));
			}
			
			int smallP = p.intValue();
			int xa = rand.nextInt(smallP-2)+1;
			
			//getting session key
			YB = BigInteger.valueOf(yb);
			XA = BigInteger.valueOf(xa);
			sessionKey = YB.modPow(XA, p);
			
			//send YA
			System.out.println("Generating YA and sending to client...");
			YA = g.modPow(XA, p);
			String YAA = String.valueOf(YA);
			
			String encrypted = "";
			byte[] enText = encrypted.getBytes();
			//encrypt YA
			try{
				enText = rc.encrypt(YAA.getBytes());
				encrypted = new String(enText, "UTF-8");
				//System.out.println("Encrypter is " + encrypted);
				//byte[] deText = rc.decrypt(enText);
				//System.out.println("Decrypted is " + new String(deText));
			}
			catch(Exception e){
				e.printStackTrace();
			}
			
			sendbuffer = enText; 
			System.out.println("YA sent to client and awaiting message from client...");
			
			DatagramPacket sendPacket = new DatagramPacket(sendbuffer, sendbuffer.length, IP, portno);
			serverSocket.send(sendPacket);
			
			shutDownSystem = false;
			s = sessionKey.toString();
			//System.out.println("Generated session key: " + s);
			break;
		}
		
		String generated[] = new String[4];
		if(shutDownSystem){
			generated[0] = "true";
		}
		else if(!shutDownSystem){
			generated[0] = "false";
		}

		generated[1] = s;
		return generated;
	}

}
