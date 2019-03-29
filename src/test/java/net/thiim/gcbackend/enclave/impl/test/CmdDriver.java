/*
 * 
 * Copyright � 2019 Martin Thiim (martin@thiim.net).
 * 
 * This software was developed for participation in the Google Confidential Computing Challenge.
 * All rights necessary for entry into this Challenge (including what is necessary to evaluate it, publish results etc.)
 * are hereby granted.
 * 
 * With respect to any other use, this is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only (GPL-2.0) as published by
 * the Free Software Foundation.

 * GeneCrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with GeneCrypt.  If not, see <https://www.gnu.org/licenses/>.
 */
package net.thiim.gcbackend.enclave.impl.test;

import java.io.InputStreamReader;
import java.io.LineNumberReader;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bson.internal.Base64;



public class CmdDriver 
{
	private final static BouncyCastleProvider provider = new BouncyCastleProvider();

	public static void main(String[] args) throws Exception {
    	// Generate the public key we wish the result to be encrypted under
    	KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", provider);
    	kpg.initialize(2048);
    	KeyPair kp = kpg.generateKeyPair();
    	byte[] pubkenc = kp.getPublic().getEncoded();
    	
    	byte[] nonce = new byte[32];
    	SecureRandom sr = new SecureRandom();
    	sr.nextBytes(nonce);

    	String line = Base64.encode(nonce) + "|" + Base64.encode(pubkenc);
    	System.out.println(line);
    	
		LineNumberReader lnr = new LineNumberReader(new InputStreamReader(System.in));
		String ln = lnr.readLine();
		String[] x = ln.split(",");
		
		System.out.println("Array match: " + Arrays.areEqual(Base64.decode(x[1]),  nonce));
		System.out.println("Pubmatch: " + Base64.encode(pubkenc).equals(x[2]));
		
    	// We have now "verified" we are talking to a real enclave that produced the session public key
    	// Instantiate the enclave public key
    	KeyFactory kf = KeyFactory.getInstance("RSA", provider);
    	PublicKey sessionPublicKey = kf.generatePublic(new X509EncodedKeySpec(Base64.decode(x[0])));

    	byte[] genomeKey = new byte[32];
    	sr.nextBytes(genomeKey);
    	
    	Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", provider);
    	cipher.init(Cipher.ENCRYPT_MODE, sessionPublicKey);
    	byte[] encryptedGenomeKey = cipher.doFinal(genomeKey);
    	
    	System.out.println("The genome key is: " + Base64.encode(genomeKey));
    	String genome = "ABAT";
    	
    	// Encrypt the genome
		cipher = Cipher.getInstance("AES/GCM/NoPadding", provider);
		cipher.init(Cipher.ENCRYPT_MODE,  new SecretKeySpec(genomeKey, "AES"));
    	
		byte[] iv = cipher.getIV();
		System.out.println("IV length: " + iv.length);
		byte[] encryptedGenome = cipher.doFinal(genome.getBytes("UTF-8"));
		String b64EncryptedGenome = Base64.encode(encryptedGenome);

		System.out.println("Enc genome length: " + encryptedGenome.length);
		chk(encryptedGenome);
		chk(iv);
		chk(encryptedGenomeKey);
		String str = "" + b64EncryptedGenome;
		str += "|" + Base64.encode(iv);
		str += "|" + Base64.encode(encryptedGenomeKey);
		
		System.out.println(str);
		String k = lnr.readLine();
		byte[] recv = Base64.decode(k);
		
		cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", provider);
		cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
		byte[] decr = cipher.doFinal(recv);
		String decrstr = new String(decr, "UTF-8");
		System.out.println("Received value: " + decrstr);
	}

	private static void chk(byte[] encryptedGenomeKey) {
		int v = 0;
		for(int i = 0; i < encryptedGenomeKey.length; i++) {
			v += (encryptedGenomeKey[i] & 0xFF);
		}
		System.out.println("" + v);
	}
}
