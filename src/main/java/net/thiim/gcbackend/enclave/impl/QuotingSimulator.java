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

import java.io.IOException;
import java.math.BigInteger;
import java.security.Signature;
import java.util.Base64;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Simple quoting simulator (used both by pure-Java and Asylo implementation)
 * that simply signs the quote data from the enclave. In real-life, this would be done
 * by the quoting enclave which would only do a quote if it could verify a local report.
 */
public class QuotingSimulator {
	private final static BouncyCastleProvider provider = new BouncyCastleProvider();
	public static String[] quote(String userdata) throws Exception
	{
		// Build up the quote string
		String quoteData = "JavaSimQuote,TestEnclave," + userdata; 
		byte[] quoteDataBytes = quoteData.getBytes("UTF-8");
		Signature sig = Signature.getInstance("SHA256withECDSA", provider);
		sig.initSign(JavaSimKeys.attestationPrivateKey);
		sig.update(quoteDataBytes, 0, quoteDataBytes.length);
		byte[] sigbytes = sig.sign();
		String signature = Base64.getEncoder().encodeToString(convertSignature(sigbytes));  
		return new String[] { quoteData, signature }; 
	}
	
	/**
	 * BouncyCastle returns ASN.1 DER encoded signatures whereas WebCrypto handles
	 * only the concatenated r,s format. So we can convert here.
	 * @param sigbytes Sig to convert
	 * @return Converted sig
	 * @throws IOException In case of errors
	 */
	private static byte[] convertSignature(byte[] sigbytes) throws IOException {
		try(ASN1InputStream sp = new ASN1InputStream(sigbytes)) {
			ASN1Sequence seq = ASN1Sequence.getInstance(sp.readObject()); // Initial sequence
			
			ASN1Integer r = (ASN1Integer)seq.getObjectAt(0);
			ASN1Integer s = (ASN1Integer)seq.getObjectAt(1);
			
			byte[] recodedsig = new byte[64];
			encode(r.getValue(), recodedsig, 0);
			encode(s.getValue(), recodedsig, 32);
			return recodedsig;
		}
	}

	/**
	 * For the concatenated format we need to provide only the positive value. BigInteger
	 * returns in signed, two-complement format so we need to strip any added leading 0x00.
	 * @param value The value to encode
	 * @param target Where to put the encoded value
	 * @param off The offset where to store the encoded sig
	 */
	private static void encode(BigInteger value, byte[] target, int off) {
		byte[] z = value.toByteArray();
		int idx = 0;
		if(z.length == 33 && z[0] == 0x0) {
			idx++;
		}
		System.arraycopy(z, idx, target, off, 32);
	}
}
