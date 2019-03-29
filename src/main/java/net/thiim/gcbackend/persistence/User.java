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
package net.thiim.gcbackend.persistence;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;


@Document
public class User {
	@Id
	public String id;
	private String pubkey;
	private String encryptedGenomeKey;
	private String encryptedGenome;
	private String encryptedGenomeIV;

	@Override
	public String toString() {
		return "User [id=" + id + ", pubkey=" + pubkey + ", encryptedGenomeKey=" + encryptedGenomeKey
				+ ", encryptedGenome=" + encryptedGenome + ", encryptedGenomeIV=" + encryptedGenomeIV + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((encryptedGenome == null) ? 0 : encryptedGenome.hashCode());
		result = prime * result + ((encryptedGenomeIV == null) ? 0 : encryptedGenomeIV.hashCode());
		result = prime * result + ((encryptedGenomeKey == null) ? 0 : encryptedGenomeKey.hashCode());
		result = prime * result + ((id == null) ? 0 : id.hashCode());
		result = prime * result + ((pubkey == null) ? 0 : pubkey.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		User other = (User) obj;
		if (encryptedGenome == null) {
			if (other.encryptedGenome != null)
				return false;
		} else if (!encryptedGenome.equals(other.encryptedGenome))
			return false;
		if (encryptedGenomeIV == null) {
			if (other.encryptedGenomeIV != null)
				return false;
		} else if (!encryptedGenomeIV.equals(other.encryptedGenomeIV))
			return false;
		if (encryptedGenomeKey == null) {
			if (other.encryptedGenomeKey != null)
				return false;
		} else if (!encryptedGenomeKey.equals(other.encryptedGenomeKey))
			return false;
		if (id == null) {
			if (other.id != null)
				return false;
		} else if (!id.equals(other.id))
			return false;
		if (pubkey == null) {
			if (other.pubkey != null)
				return false;
		} else if (!pubkey.equals(other.pubkey))
			return false;
		return true;
	}

	public User() {}

	public User(String pubkey) {
		this.pubkey = pubkey;
	}

	public String getPubkey() {
		return pubkey;
	}

	public String getEncryptedGenomeKey() {
		return encryptedGenomeKey;
	}

	public String getEncryptedGenome() {
		return encryptedGenome;
	}

	public void setEncryptedGenomeKey(String encryptedGenomeKey) {
		this.encryptedGenomeKey = encryptedGenomeKey;
	}
	
	public void setEncryptedGenome(String encryptedGenome) {
		this.encryptedGenome = encryptedGenome;
	}

	public String getEncryptedGenomeIV() {
		return encryptedGenomeIV;
	}

	public String getID() {
		return id;
	}

	public void setEncryptedGenomeIV(String encryptedGenomeIV) {
		this.encryptedGenomeIV = encryptedGenomeIV;
	}
}