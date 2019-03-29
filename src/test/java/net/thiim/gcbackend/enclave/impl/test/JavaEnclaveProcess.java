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

import net.thiim.gcbackend.enclave.ExecuteQueryRequest;
import net.thiim.gcbackend.enclave.ExecuteQueryResponse;
import net.thiim.gcbackend.enclave.LaunchRequest;
import net.thiim.gcbackend.enclave.LaunchResponse;
import net.thiim.gcbackend.enclave.impl.JavaSimEnclaveSystemImpl;

public class JavaEnclaveProcess {
	public static void main(String[] args) throws Exception {
		LineNumberReader lnr = new LineNumberReader(new InputStreamReader(System.in));
		String ln = lnr.readLine();
		String[] tok = ln.split("\\|");
		
		JavaSimEnclaveSystemImpl j = new JavaSimEnclaveSystemImpl();
		LaunchRequest lr = new LaunchRequest();
		lr.nonce = tok[0];
		lr.receiverPublicKey = tok[1];
		
		LaunchResponse resp = j.launch(lr);
		// Note we strip away the quoting related parts we will re-apply it later
		
		tok = resp.quoteData.split(",");
		System.out.println(tok[2] + "," + tok[3] + "," + tok[4]);
		System.out.flush();
		
		ln = lnr.readLine();
		tok = ln.split("\\|");
		
		ExecuteQueryRequest eqr = new ExecuteQueryRequest();
		eqr.encryptedGenome = tok[0];
		eqr.encryptedGenomeIV = tok[1];
		eqr.encryptedGenomeKey = tok[2];
		ExecuteQueryResponse executeQueryResponse = resp.instance.executeQuery(eqr);
		System.out.println(executeQueryResponse.result);
		System.out.flush();
	}
}
