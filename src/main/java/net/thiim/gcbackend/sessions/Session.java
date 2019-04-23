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

import java.util.UUID;

import net.thiim.gcbackend.enclave.EnclaveInstance;
import net.thiim.gcbackend.persistence.User;

public class Session
{
	UUID uuid;
	long creationTime;
	private EnclaveInstance enclaveInstance;
	private User user;

	public Session(long creationTime) {
		this.uuid = UUID.randomUUID();
		this.creationTime = creationTime;
	}

	public String getID() {
		return uuid.toString();
	}

	public void setEnclaveInstance(EnclaveInstance enclaveInstance) {
		this.enclaveInstance = enclaveInstance;
	}
	
	public EnclaveInstance getEnclaveInstance()
	{
		return enclaveInstance;
	}

	public void setUser(User user) {
		this.user = user;
	}
	
	public User getUser()
	{
		return user;
	}

	public void kill() {
		this.enclaveInstance.forceQuit();
	}
}