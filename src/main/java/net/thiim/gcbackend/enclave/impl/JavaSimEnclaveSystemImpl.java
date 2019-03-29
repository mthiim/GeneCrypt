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
package net.thiim.gcbackend.enclave.impl;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import net.thiim.gcbackend.enclave.EnclaveException;
import net.thiim.gcbackend.enclave.EnclaveInstance;
import net.thiim.gcbackend.enclave.ExecuteQueryRequest;
import net.thiim.gcbackend.enclave.ExecuteQueryResponse;
import net.thiim.gcbackend.enclave.IEnclaveSystem;
import net.thiim.gcbackend.enclave.LaunchRequest;
import net.thiim.gcbackend.enclave.LaunchResponse;

@Component
@Profile("!asylo")
public class JavaSimEnclaveSystemImpl implements IEnclaveSystem
{
	private final static BouncyCastleProvider provider = new BouncyCastleProvider();
	
	static class JavaEnclaveInstance extends EnclaveInstance
	{
		private KeyPair kp;
		private String nonce;
		private String resultReceiverPublicKey;

		public JavaEnclaveInstance(String nonce, String resultReceiverPublicKey)
		{
			this.nonce = nonce;
			this.resultReceiverPublicKey = resultReceiverPublicKey;
		}
		
		public void launch() throws Exception
		{
	    	KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", provider);
			kpg.initialize(2048);
			this.kp = kpg.generateKeyPair();
		}

		public String getLaunchInfo() {
			// Enclave session public key
			String launchInfo = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
			// Requested nonce
			launchInfo += "," + nonce;
			launchInfo += "," + resultReceiverPublicKey;
			return launchInfo;
			
		}

		@Override
		public ExecuteQueryResponse executeQuery(ExecuteQueryRequest request) throws EnclaveException {
			try {
				Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", provider);
		    	cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
		    	
		    	byte[] genomeKey = cipher.doFinal(Base64.getDecoder().decode(request.encryptedGenomeKey));

		    	cipher = Cipher.getInstance("AES/GCM/NoPadding", provider);
		    	cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(genomeKey, "AES"), new IvParameterSpec(Base64.getDecoder().decode(request.encryptedGenomeIV)));
		    	byte[] genomeBytes = cipher.doFinal(Base64.getDecoder().decode(request.encryptedGenome));
		    	
		    	String genome = new String(genomeBytes, "UTF-8");
		    	ExecuteQueryResponse eqr = new ExecuteQueryResponse();
		    	
		    	String result = "" + (genome.charAt(3) != 'A'); 
		    	// encrypt result with receivers public key
		    	eqr.result = encryptResult(result, resultReceiverPublicKey);
		    	return eqr;
			}
			catch(Exception ex)
			{
				throw new EnclaveException(EnclaveException.GENERAL_ERROR, ex);
			}
		}
		
		private String encryptResult(String result, String pubkey) throws Exception
		{
			KeyFactory kf = KeyFactory.getInstance("RSA",provider);
			PublicKey pubk = kf.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(pubkey)));
			Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", provider);
			cipher.init(Cipher.ENCRYPT_MODE, pubk);
			byte[] bresult = cipher.doFinal(result.getBytes("UTF-8"));
			return Base64.getEncoder().encodeToString(bresult);
		}

		@Override
		public void forceQuit() {
			// No action necessary for this implementation
		}
	}
	
	@Override
	public LaunchResponse launch(LaunchRequest request) throws EnclaveException
	{
		try {
			JavaEnclaveInstance enclave = new JavaEnclaveInstance(request.nonce, request.receiverPublicKey);
			enclave.launch();
			
			
			LaunchResponse resp = new LaunchResponse();
			resp.instance = enclave;
			
			String launchInfo = enclave.getLaunchInfo();
			
			String[] quote = QuotingSimulator.quote(launchInfo);

			// Build up the quote string
			resp.quoteData = quote[0];
			resp.quoteSignature = quote[1];
			return resp;
		}
		catch(Exception ex)
		{
			throw new EnclaveException(EnclaveException.GENERAL_ERROR, ex);
		}
	}

}
