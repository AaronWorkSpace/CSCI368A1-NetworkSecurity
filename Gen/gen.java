//Done by: Aaron Lim
//Student ID: 5985171

import java.util.*;
import java.io.*;
import java.math.BigInteger;

// Code for getting prime number from BigInteger
// Author: Nam G VU
// https://stackoverflow.com/questions/32035259/fastest-algorithm-to-find-if-a-biginteger-is-a-prime-number-or-not

public class gen{
	public static void main(String[] args){
		fileWriting fw = new fileWriting();
		fw.writeFile();
	}
}

class fileWriting{
	private Scanner sc;
	
	/*
	public void openFile(){
		
		try{
			sc = new Scanner(new File("password.txt"));
			
		}
		catch(Exception e){
			System.out.println("File does not exist");
		}
	}
	*/
	public void writeFile(){
		/*
		String p = "";
		String password = "";
		while(sc.hasNext()){
			password = sc.next();
			p = sc.next();
		}
		closeFile();
		*/
		boolean ok = true;
		boolean okk = true;
		Random rand = new Random();
		int p = 0;
		
		String password = "";
		for(int i = 0; i < 6; i++){
			password += String.valueOf(rand.nextInt(10));
		}
		/*
		while(ok){
			ok = true;
			okk = true;
			p = rand.nextInt(500000) + 50000;
			okk = checkPrime(p);
			if(okk == true){
				p = (2 * p) + 1;
				okk = checkPrime(p);
				if(okk == true){
					if(p < 1000000){
						ok = false;
					}
				}
			}
		}
		
		int g = rand.nextInt(p - 2) + 1;
	
		while(g == 1 || g == p - 1){
			g = rand.nextInt(p - 1) + 1;
		}
	
		int k = p - 1;
		k /= 2;
	
    		if((Math.pow(g, k) % p) == 1){
    			g = p - g;
    		}
    		
    		*/
    		
    		BigInteger safe = new BigInteger("0");
		BigInteger q = new BigInteger("0");
		BigInteger one = new BigInteger("1");
		BigInteger two = new BigInteger("2");
		int randomize = 0;
		ok = false;
		while(!ok){
			randomize = rand.nextInt(1147483647) + 1000000000;
			BigInteger bigP = BigInteger.valueOf(randomize);
			safe = bigP.nextProbablePrime();
			q = safe.subtract(one);
			q = q.divide(two);
			ok = returnPrime(q);
		}
 
    		int safePInInt = safe.intValue();
    		randomize = rand.nextInt(safePInInt - 2) + 1;
    		
    		while(randomize == 1 || randomize == safePInInt - 1){
    			randomize = rand.nextInt(safePInInt - 2) + 1;
    		}
    		
    		BigInteger k = safe.subtract(one);
    		k = k.divide(two);
    		
    		BigInteger bigG = BigInteger.valueOf(randomize);
    		BigInteger gGen = bigG.modPow(k, safe);
    		int compareValue = gGen.compareTo(one);
    		if(compareValue == 0){
    			bigG = safe.subtract(bigG);
    		}
    		
    		String pp = safe.toString();
    		String gg = bigG.toString();
    		editFile(password, pp, gg);
    		
    		System.out.println("p: " + pp);
    		System.out.println("g: " + gg);
    		System.out.println("Password: " + password);
	}
	
	public static void editFile(String pw, String p, String g){
		try{
			File f = new File("/home/vmw_ubuntu/Desktop/Alice/password.txt");
			File bF = new File("/home/vmw_ubuntu/Desktop/Bob/password.txt");
			String s = pw + " " + p + " " + g;
			write(s, f);
			write(s, bF);
		}
		catch(Exception e){
			
		}
	}
	
	public static void write(String s, File f) throws IOException{
		FileWriter fw = new FileWriter(f);
		System.out.println("Writing of file commerces to server..");
		fw.write(s);
		System.out.println("Writing of file completed..");
		fw.close();
	}
	
	public boolean returnPrime(BigInteger number) {
		//check via BigInteger.isProbablePrime(certainty)
		if (!number.isProbablePrime(5))
			return false;

		//check if even
		BigInteger two = new BigInteger("2");
			if (!two.equals(number) && BigInteger.ZERO.equals(number.mod(two)))
				return false;

		//find divisor if any from 3 to 'number'
		for (BigInteger i = new BigInteger("3"); i.multiply(i).compareTo(number) < 1; i = i.add(two)) { //start from 3, 5, etc. the odd number, and look for a divisor if any
			if (BigInteger.ZERO.equals(number.mod(i))) //check if 'i' is divisor of 'number'
		   		return false;
		}
		return true;
	}
}
