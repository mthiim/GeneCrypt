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
package net.thiim.gcbackend.json;

public class EnclaveLaunchData {
	public String quoteData;
	public String quoteSignature;
	public String sessionID;
	public String getEncryptedGenomeEncryptionKey() {
		return encryptedGenomeEncryptionKey;
	}
	public void setEncryptedGenomeEncryptionKey(String encryptedGenomeEncryptionKey) {
		this.encryptedGenomeEncryptionKey = encryptedGenomeEncryptionKey;
	}
	public String encryptedGenomeEncryptionKey;
	
	public String getSessionID() {
		return sessionID;
	}
	public void setSessionID(String sessionID) {
		this.sessionID = sessionID;
	}
	public EnclaveLaunchData(String quoteData, String quoteSignature, String encryptedGenomeEncryptionKey, String sessionID) {
		this.quoteData = quoteData;
		this.quoteSignature = quoteSignature;
		this.sessionID = sessionID;
		this.encryptedGenomeEncryptionKey = encryptedGenomeEncryptionKey;
	}
	public String getQuoteData() {
		return quoteData;
	}
	public void setQuoteData(String quoteData) {
		this.quoteData = quoteData;
	}
	public String getQuoteSignature() {
		return quoteSignature;
	}
	public void setQuoteSignature(String quoteSignature) {
		this.quoteSignature = quoteSignature;
	}
}
