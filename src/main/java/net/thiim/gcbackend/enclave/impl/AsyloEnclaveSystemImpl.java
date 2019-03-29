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

import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.LineNumberReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;

import org.springframework.beans.factory.annotation.Value;
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
@Profile("asylo")
/**
 * An implementation that uses Asylo enclaves by launching them as sub-processes and communicating with them using stdio.
 * In a production version, mechanisms like JNI could be used instead.
 */
public class AsyloEnclaveSystemImpl implements IEnclaveSystem
{
	
	private String enclaveDir;
	private String enclaveCmd;
	public AsyloEnclaveSystemImpl(@Value("${enclave.dir}")String enclaveDir, @Value("${enclave.cmd}")String enclaveCmd)
	{
		this.enclaveDir = enclaveDir;
		this.enclaveCmd = enclaveCmd;
	}

	class EnclaveProcess extends EnclaveInstance
	{
		private LineNumberReader lnr;
		private Process process;
		private PrintWriter pw;

		public EnclaveProcess() throws IOException
		{
			String[] cmdarray = enclaveCmd.split(" ");
			ProcessBuilder pb = new  ProcessBuilder(cmdarray);
			pb.directory(new File(enclaveDir));
			this.process = pb.start();
			this.lnr = new LineNumberReader(new InputStreamReader(process.getInputStream()));
			this.pw = new PrintWriter(new OutputStreamWriter(process.getOutputStream()));
		}
		
		public LaunchResponse launch(LaunchRequest request) throws Exception
		{
			// Communicate launch params to enclave
			String str = "";
			str += request.nonce;
			str += "|" + request.receiverPublicKey;
			System.out.println("Written to enclave: " + str);
			pw.println(str);
			pw.flush();
			
			String enclaveOutput = lnr.readLine();
			System.out.println("Read from enclave: " + enclaveOutput);
			LaunchResponse lr = new LaunchResponse();
			
			String[] quote = QuotingSimulator.quote(enclaveOutput);
			
			lr.quoteData = quote[0];
			lr.quoteSignature = quote[1];
			lr.instance = this;
			return lr;
		}
		
		public ExecuteQueryResponse executeQuery(ExecuteQueryRequest request) throws EnclaveException 
		{
			try {
				String str = "";
				str += request.encryptedGenome;
				str += "|" + request.encryptedGenomeIV;
				str += "|" + request.encryptedGenomeKey;
				pw.println(str);
				System.out.println("Written to enclave: " + str);
				pw.flush();
				String result = lnr.readLine();
				System.out.println("Read from enclave: " + result);
				ExecuteQueryResponse response = new ExecuteQueryResponse();
				response.result = result;
				return response;
			}
			catch(Exception ex)
			{
				throw new EnclaveException(EnclaveException.GENERAL_ERROR, ex);
			}
		}

		@Override
		public void forceQuit() {
			process.destroyForcibly();
		}
	}
	@Override
	public LaunchResponse launch(LaunchRequest request) throws EnclaveException {
		 try {
			EnclaveProcess ep = new EnclaveProcess();
			return ep.launch(request);
		} catch (Exception e) {
			throw new EnclaveException(EnclaveException.GENERAL_ERROR, e);
		}
	}
}
