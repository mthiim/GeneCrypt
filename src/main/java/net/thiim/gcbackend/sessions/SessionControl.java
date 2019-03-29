/*
 *
 * Copyright 2019 Martin Thiim
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package net.thiim.gcbackend.sessions;

import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * Very quick and dirty, poor man's session control for the REST interface (we need to hit the same running enclave for launch and executeQuery states) 
 * and for ensuring we kill the processes etc.
 * Not suitable for production :-)
 *
 */
public class SessionControl {
	private Map<String, Session> sessions = Collections.synchronizedMap(new HashMap<String, Session>());
	
	{
		Runnable r = new Runnable() {
			@Override
			public void run() {
				while(true) {
					try {
						Thread.sleep(30000);
						Iterator<String> it = sessions.keySet().iterator();
						while(it.hasNext()) {
							String x = it.next();
							Session sess = sessions.get(x);
							long age = System.currentTimeMillis() - sess.creationTime;
							if(age > 300000) {
								System.out.println("Purging: " + x);
								it.remove(); 
								try {
									sess.kill();
								}
								catch(Exception ex)
								{
									ex.printStackTrace();
								}
							}
						}
					} catch (InterruptedException e) {
					}
				}
			}
		};
		Thread t = new Thread(r);
		t.start();
	}
	
	private static SessionControl instance = new SessionControl();
	
	public static SessionControl getInstance()
	{
		return instance;
	}
	
	public Session createSession()
	{
		Session session = new Session();
		sessions.put(session.uuid.toString(), session);
		return session;
	}
	
	public Session getSession(String x)
	{
		return sessions.get(x);
	}
}
