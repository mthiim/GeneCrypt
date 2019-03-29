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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/*
 * Key pair we use for attestation. 
 * 
 * Private: MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgIcVr051ut4U+QJ2xitSDcK/yLXCnmzzWl4qbkBLQD6ugCgYIKoZIzj0DAQehRANCAAQ0J2YNVx16fqIt5dBdal/ebuo9CEjA3kMSJv9CKMepb7aZwBX/UiP6UFqSxmQTx6nJCpk2c+Cb2qu8NBzj/Ltr
 * Public: MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENCdmDVcden6iLeXQXWpf3m7qPQhIwN5DEib/QijHqW+2mcAV/1Ij+lBaksZkE8epyQqZNnPgm9qrvDQc4/y7aw==
 * Note that for the Java-simulated quoting facility this is just hardcoded software keys so obviously insecure. 
 */
public class JavaSimKeys {
	private final static BouncyCastleProvider prov = new BouncyCastleProvider();

	private final static String b64attestationPublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENCdmDVcden6iLeXQXWpf3m7qPQhIwN5DEib/QijHqW+2mcAV/1Ij+lBaksZkE8epyQqZNnPgm9qrvDQc4/y7aw==";
	private final static String b64attestationPrivateKey = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgIcVr051ut4U+QJ2xitSDcK/yLXCnmzzWl4qbkBLQD6ugCgYIKoZIzj0DAQehRANCAAQ0J2YNVx16fqIt5dBdal/ebuo9CEjA3kMSJv9CKMepb7aZwBX/UiP6UFqSxmQTx6nJCpk2c+Cb2qu8NBzj/Ltr";

	public static PublicKey attestationPublicKey;
	public static PrivateKey attestationPrivateKey;

	static {
		try {
			KeyFactory kf = KeyFactory.getInstance("ECDSA", prov);
			attestationPublicKey = kf.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(b64attestationPublicKey)));
			attestationPrivateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(b64attestationPrivateKey)));
		}
		catch(Exception ex)
		{
			throw new RuntimeException(ex);
		}
	}
}
