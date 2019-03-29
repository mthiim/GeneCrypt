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

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bson.internal.Base64;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import net.thiim.gcbackend.enclave.ExecuteQueryRequest;
import net.thiim.gcbackend.enclave.ExecuteQueryResponse;
import net.thiim.gcbackend.enclave.IEnclaveSystem;
import net.thiim.gcbackend.enclave.LaunchRequest;
import net.thiim.gcbackend.enclave.LaunchResponse;
import net.thiim.gcbackend.enclave.impl.AsyloEnclaveSystemImpl;
import net.thiim.gcbackend.enclave.impl.JavaSimEnclaveSystemImpl;
import net.thiim.gcbackend.enclave.impl.JavaSimKeys;

public class EnclaveSystemTest extends TestCase
{
	private final static BouncyCastleProvider provider = new BouncyCastleProvider();	/** 
	 * Used by 'testAsyloInterface' to test the stdio interface the Asylo enclaves
	 */
	private final static String CMDLINE = "java -classpath " + System.getProperty("java.class.path") + " net.thiim.gcbackend.enclave.impl.test.JavaEnclaveProcess";

    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public EnclaveSystemTest( String testName )
    {
        super( testName );
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
        return new TestSuite( EnclaveSystemTest.class );
    }

    public void testJavaEnclaveImpl() throws Exception
    {
    	internalTestEnclaveImpl(new JavaSimEnclaveSystemImpl());
    }

    /**
     * Tests the process-based interface to Asylo enclaves by launching JavaEnclaveProcess as a process, which simulates
     * the stdio interface of the Azylo enclave (but internally uses the Java-implementation).
     * @throws Exception In case of errors
     */
    public void testAsyloInterface() throws Exception
    {
    	internalTestEnclaveImpl(new AsyloEnclaveSystemImpl(".", CMDLINE));
    }
    
    public byte[] signatureToDer(byte[] signature) throws IOException
    {
    	BigInteger r = new BigInteger(1,subarray(signature,0,32));
    	BigInteger s = new BigInteger(1,subarray(signature,32,32));
    	ASN1Encodable[] enc = new ASN1Encodable[2];
    	enc[0] = new ASN1Integer(r);
    	enc[1] = new ASN1Integer(s);
    	DERSequence derSequence = new DERSequence(enc);
    	return derSequence.getEncoded();
    }

    private byte[] subarray(byte[] signature, int off, int len) {
    	byte[] b = new byte[len];
    	System.arraycopy(signature,  off,  b,  0,  len);
    	return b;
	}
    
    public void internalTestEnclaveImpl(IEnclaveSystem enclaveImpl, String genome, boolean expResult) throws Exception
    {
    	LaunchRequest lr = new LaunchRequest();

    	// Generate the public key we wish the result to be encrypted under
    	KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", provider);
    	kpg.initialize(2048);
    	KeyPair kp = kpg.generateKeyPair();
    	
    	byte[] nonce = new byte[32];
    	SecureRandom sr = new SecureRandom();
    	sr.nextBytes(nonce);
    	
    	lr.receiverPublicKey = Base64.encode(kp.getPublic().getEncoded());
    	lr.nonce = Base64.encode(nonce);
    	
    	LaunchResponse response = enclaveImpl.launch(lr);

    	// Verify signature
    	byte[] signature = Base64.decode(response.quoteSignature);
    	Signature sig = Signature.getInstance("SHA256withECDSA", provider);
    	sig.initVerify(JavaSimKeys.attestationPublicKey);
    	sig.update(response.quoteData.getBytes("UTF-8"));
    	
    	byte[] derSignature = signatureToDer(signature);
    	
    	assertTrue(sig.verify(derSignature));

    	String[] tokens = response.quoteData.split(",");
    	TestCase.assertEquals("JavaSimQuote", tokens[0]);
    	TestCase.assertEquals("TestEnclave", tokens[1]);

    	String nonceFromQuote = tokens[3];
    	String receiverPublicKeyFromQuote = tokens[4];
    	String enclavePublicKeyFromQuote = tokens[2];

    	// Verify data from quote matches what we want
    	assertTrue(Arrays.areEqual(nonce, Base64.decode(nonceFromQuote)));
    	assertTrue(Arrays.areEqual(kp.getPublic().getEncoded(), Base64.decode(receiverPublicKeyFromQuote)));
    	
    	// We have now "verified" we are talking to a real enclave that produced the session public key
    	// and that it is operating under the desired parameters
    	
    	// Instantiate the enclave's session public key
    	KeyFactory kf = KeyFactory.getInstance("RSA", provider);
    	PublicKey sessionPublicKey = kf.generatePublic(new X509EncodedKeySpec(Base64.decode(enclavePublicKeyFromQuote)));
    	
    	// Generate genome key
    	byte[] genomeKey = new byte[32];
    	sr.nextBytes(genomeKey);
    	
    	Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", provider);
    	cipher.init(Cipher.ENCRYPT_MODE, sessionPublicKey);
    	byte[] encryptedGenomeKey = cipher.doFinal(genomeKey);
    	
    	// Encrypt the genome
		cipher = Cipher.getInstance("AES/GCM/NoPadding", provider);
		cipher.init(Cipher.ENCRYPT_MODE,  new SecretKeySpec(genomeKey, "AES"));
		
		byte[] iv = cipher.getIV();
		byte[] encryptedGenome = cipher.doFinal(genome.getBytes("UTF-8"));
		String b64EncryptedGenome = Base64.encode(encryptedGenome);
		
		ExecuteQueryRequest executeQueryRequest = new ExecuteQueryRequest();
		executeQueryRequest.encryptedGenome = b64EncryptedGenome;
		executeQueryRequest.encryptedGenomeKey = Base64.encode(encryptedGenomeKey);
		executeQueryRequest.encryptedGenomeIV = Base64.encode(iv);
		
		ExecuteQueryResponse executeQueryResponse = response.instance.executeQuery(executeQueryRequest);
		
		// Decrypt the result
		cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", provider);
		cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
		byte[] ex = cipher.doFinal(Base64.decode(executeQueryResponse.result));
		String str = new String(ex, "UTF-8");
		boolean b = Boolean.parseBoolean(str);
		assertEquals(b, expResult);
    }
	public void internalTestEnclaveImpl(IEnclaveSystem enclaveImpl) throws Exception
    {
		this.internalTestEnclaveImpl(enclaveImpl, "ABCD", true);
		this.internalTestEnclaveImpl(enclaveImpl, "ABCA", false);
    }
}
