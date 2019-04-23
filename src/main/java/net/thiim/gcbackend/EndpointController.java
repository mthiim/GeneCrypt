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
package net.thiim.gcbackend;

import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import net.thiim.gcbackend.enclave.EnclaveInstance;
import net.thiim.gcbackend.enclave.ExecuteQueryRequest;
import net.thiim.gcbackend.enclave.ExecuteQueryResponse;
import net.thiim.gcbackend.enclave.IEnclaveSystem;
import net.thiim.gcbackend.enclave.LaunchRequest;
import net.thiim.gcbackend.enclave.LaunchResponse;
import net.thiim.gcbackend.json.EnclaveLaunchData;
import net.thiim.gcbackend.persistence.User;
import net.thiim.gcbackend.persistence.UserRepository;
import net.thiim.gcbackend.sessions.Session;
import net.thiim.gcbackend.sessions.SessionControl;
@RestController
public class EndpointController {
	private static BouncyCastleProvider prov = new BouncyCastleProvider();
	@Autowired
	private UserRepository repository;
	@Autowired
	private IEnclaveSystem enclaveSystem;
	@Autowired
	private SessionControl sessionControl;
	
	static {
		// Warm the provider
		// Now encrypt genomic data with the key
		try {
			@SuppressWarnings("unused")
			Cipher cipher = Cipher.getInstance("AES", prov);
		} catch (Exception e) {
			throw new RuntimeException(e);
		} 
	}
	
	
	@RequestMapping(value = "/users", method = RequestMethod.PUT)
    public String newUser(String pubkey) {
        User u = new User(pubkey);
        repository.save(u);
        return u.getID();
    }

    @RequestMapping(value = "/users/{id}/genome", method = RequestMethod.PUT)
    public ResponseEntity<String> storeGenome(@PathVariable String id, @RequestParam String encryptedGenome,
    		@RequestParam String encryptedGenomeEncryptionKey,
    		@RequestParam String encryptedGenomeIV) {
    	try {
        	Optional<User> u = repository.findById(id);
        	if(u.isPresent()) {
        		User user = u.get();
        		
        		user.setEncryptedGenomeKey(encryptedGenomeEncryptionKey);
        		user.setEncryptedGenomeIV(encryptedGenomeIV);
        		user.setEncryptedGenome(encryptedGenome);
        		repository.save(user);
        		return ResponseEntity.ok(null);
        	}
        	else {
        		return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Entity not found");
        	}
    	}
    	catch(Exception ex)
    	{
    		ex.printStackTrace();
    		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
    	}
    }
    
    @RequestMapping(value = "/users/{id}/launchenclave", method = RequestMethod.POST)
    public ResponseEntity<EnclaveLaunchData> launchEnclave(@PathVariable String id, @RequestParam String nonce, @RequestParam String receiverPublicKey) {
    	try {
        	Optional<User> u = repository.findById(id);
        	if(u.isPresent()) {
        		User user = u.get();
        		LaunchRequest lr = new LaunchRequest();
        		lr.nonce = nonce;
        		lr.receiverPublicKey = receiverPublicKey;
        		LaunchResponse response = enclaveSystem.launch(lr);
        		Session session = sessionControl.createSession();
        		session.setEnclaveInstance(response.instance);
        		session.setUser(user);
        		EnclaveLaunchData eld = new EnclaveLaunchData(response.quoteData, response.quoteSignature, user.getEncryptedGenomeKey(), session.getID());
        		return ResponseEntity.ok(eld);
        	}
        	else {
        		return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
        	}
    	}
    	catch(Exception ex)
    	{
    		ex.printStackTrace();
    		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
    	}
    }
    
    @RequestMapping(value = "/sessions/{sessionID}/executeQuery", method = RequestMethod.POST)
    public ResponseEntity<String> executeQuery(@PathVariable String sessionID, @RequestParam String reencryptedGenomeEncryptionKey) {
    	try {
    		Session session = sessionControl.getSession(sessionID);
    		if(session == null) {
    			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
    		}
    		EnclaveInstance enclaveInstance = session.getEnclaveInstance();
    		
    		ExecuteQueryRequest eqr = new ExecuteQueryRequest();
    		eqr.encryptedGenome = session.getUser().getEncryptedGenome();
    		eqr.encryptedGenomeIV = session.getUser().getEncryptedGenomeIV();
    		eqr.encryptedGenomeKey = reencryptedGenomeEncryptionKey;
    		ExecuteQueryResponse resp = enclaveInstance.executeQuery(eqr);
    		return ResponseEntity.ok("" + resp.result);
    	}
    	catch(Exception ex)
    	{
    		ex.printStackTrace();
    		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
    	}
    }
    
}