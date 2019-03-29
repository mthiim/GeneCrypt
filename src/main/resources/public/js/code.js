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
var lowriskvariant = "ACGATTACCACATGGGGTTTTTTG";
var highriskvariant = "ACGTTTACCACATGGGGTTTTTTG";

var quotingPubKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENCdmDVcden6iLeXQXWpf3m7qPQhIwN5DEib/QijHqW+2mcAV/1Ij+lBaksZkE8epyQqZNnPgm9qrvDQc4/y7aw==";
if(!window.crypto.subtle) {
	alert("Web Crypto API is not supported by your browser - the PoC likely won't work (this could be caused by hosting the page from a server without TLS/SSL");
}

var stepper1 = null;

document.addEventListener('DOMContentLoaded', function () {
	let x = document.querySelector('#stepper1');
	stepper1 = new Stepper(x);

	// Disable function
	jQuery.fn.extend({
		disable: function(state) {
			return this.each(function() {
				this.disabled = state;
			});
		}
	});

	jQuery.fn.extend({
		hidden: function(state) {
			return this.each(function() {
				this.hidden = state;
			});
		}
	});

	document.getElementById("genedata").value = lowriskvariant;


})

var keyPair = null;
var userID = null;
var receivedEncryptedGenomeEncryptionKey = null; // When initiating processing we encrypt the encrypted (under end-user pub key) encryption key and put it here
var enclavePubKey = null;
var sessionID = null;
var nonce = null;
var encodedPublicKey = null;
var encryptedresponsetxt = null;
var decryptedresponsetxt = null;
var hashpubkey = null;
function restCall(url, method, inp)
{
	return new Promise((resolve, reject) => {
		var oReq = new XMLHttpRequest();
		oReq.onreadystatechange = function() {
			if (this.readyState == 4) {
				if(this.status == 200) {
					resolve(this.responseText);
				}
				else {
					reject("Error");
				}
			}
		};
		oReq.open(method, url, true);
		oReq.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
		oReq.send(inp);
	});
}


async function registerUser() {
	keyPair = await window.crypto.subtle.generateKey({
		name : "RSA-OAEP",
		modulusLength : 2048,
		publicExponent : new Uint8Array([ 1, 0, 1 ]),
		hash : "SHA-1",
	}, false, [ "encrypt", "decrypt" ]);

	let exportedPublicKey = await crypto.subtle.exportKey("spki", keyPair.publicKey);
	hashpubkey = await window.crypto.subtle.digest('SHA-256', exportedPublicKey);
	encodedPublicKey = arrayBufferToBase64(new Uint8Array(exportedPublicKey));
	console.log("Encoded: " + encodedPublicKey);

	try {
		userID = await restCall("/users", "PUT", "username=name&pubkey=" + encodeURIComponent(encodedPublicKey));
		console.log("UserID: " + userID);
	}
	catch(e)
	{
		console.log("Error when calling rest: " + e);
	}

	var txt = $('#rsakeytext').html();
	txt = txt.replace("XXX", arrayBufferToBase64(hashpubkey));
	$('#rsakeytext').html(txt);
	$('#next1').disable(false); 
	$('#rsakeycontent').hidden(false);
	$('#rsaspinner').hidden(true); 
};

async function encryptAndUpload() {
	let genome = document.getElementById("genedata").value;	
	let encoded = stringToUint(genome);

	let key = await window.crypto.subtle.generateKey(
			{
				name: "AES-GCM",
				length: 256, // can be 128, 192, or 256
			},
			true, 
			["encrypt", "decrypt"] // can "encrypt", "decrypt", "wrapKey", or
			// "unwrapKey"
	);

	// iv will be needed for decryption
	let iv = window.crypto.getRandomValues(new Uint8Array(16));
	let encrypted = await window.crypto.subtle.encrypt(
			{
				name: "AES-GCM",
				iv: iv
			},
			key,
			encoded
	);

	// Export key bytes
	let genomeKeyBytes = await crypto.subtle.exportKey("raw", key);

	// Encrypt key with RSA public key
	let encryptedGenomeEncryptionKey = await window.crypto.subtle.encrypt(
			{
				name: "RSA-OAEP",
			},
			keyPair.publicKey,
			genomeKeyBytes
	);
	
	let params = "encryptedGenome=" + encodeURIComponent(arrayBufferToBase64(encrypted));
	params += "&encryptedGenomeEncryptionKey=" + encodeURIComponent(arrayBufferToBase64(encryptedGenomeEncryptionKey));
	params += "&encryptedGenomeIV=" + encodeURIComponent(arrayBufferToBase64(iv));

	try {
		await restCall("/users/" + userID + "/genome", "PUT", params);
	}
	catch(e)
	{
		console.log("Error");
	}
	$('#next2').disable(false); 
	$('#uploadspinner').hidden(true);
	$('#uploadcontent').hidden(false);
};

function b64tobytes(x)
{
	var b = atob(x);
	var array = new Uint8Array(new ArrayBuffer(b.length));
	for(i = 0; i < b.length; i++) {
		array[i] = b.charCodeAt(i);
	}
	return array;
}

function arrayBufferToBase64(buffer) {
	var binary = '';
	var bytes = new Uint8Array(buffer);
	var len = bytes.byteLength;
	for (var i = 0; i < len; i++) {
		binary += String.fromCharCode(bytes[i]);
	}
	return window.btoa(binary);
}

function stringToUint(string) {
	return new TextEncoder("utf-8").encode(string);
}

function uintToString(uintArray) {
	return new TextDecoder().decode(uintArray);
}

function comparearr(a,b)
{
    if (a.length != b.length) return false;
    for(var i = 0; i < a.length; i++)
    {
        if (a[i] != b[i]) return false;
    }
    return true;
}
async function doInitiateRequest() {
	try {
		// Generate nonce
		nonce = new Uint8Array(32);
		window.crypto.getRandomValues(nonce);
		
		var params = "nonce=" + encodeURIComponent(arrayBufferToBase64(nonce));
		
		// For the public key we simply use the public key also used for local genome key storage
		params += "&receiverPublicKey=" + encodeURIComponent(encodedPublicKey);
		
		var response = await restCall("/users/" + userID + "/launchenclave", "POST", params);
		var jsonResponse = JSON.parse(response);
		console.log(jsonResponse);

		// Instantiate key
		var pubk = b64tobytes(quotingPubKey);
		var key = await window.crypto.subtle.importKey(
				"spki",
				pubk,
				{
					name: "ECDSA",
					namedCurve: "P-256"
				},
				false,
				["verify"]
		);
		var quoteData = stringToUint(jsonResponse.quoteData);
		var quoteSignature = b64tobytes(jsonResponse.quoteSignature);
		let result = await window.crypto.subtle.verify(
				{
					name: "ECDSA",
					hash: {name: "SHA-256"},
				},
				key,
				quoteSignature,
				quoteData
		);

		if(!result) {
			alert("Invalid signature!");
			return;
		}

		var splits = jsonResponse.quoteData.split(",");
		var quoter = splits[0];
		var enclave = splits[1];
		var sessKey = splits[2];
		var nonceFromQuote = splits[3];
		var receiverPublicKeyFromQuote = splits[4];
		
		if(receiverPublicKeyFromQuote !== encodedPublicKey) {
			alert("Mismatch on received public key!");
		}
		if(!comparearr(b64tobytes(nonceFromQuote),nonce)) {
			alert("Mismatch on received nonce");
		}
		
		// Ok ready to roll - import enclave session public key
		enclavePubKey = await window.crypto.subtle.importKey(
				"spki",
				b64tobytes(sessKey),
				{
					name: "RSA-OAEP",
					hash: "SHA-1"
				},
				false,
				["encrypt"]
		);
		receivedEncryptedGenomeEncryptionKey = jsonResponse.encryptedGenomeEncryptionKey;
		sessionID = jsonResponse.sessionID;
	}
	catch(e)
	{
		console.log("Error");
	}
	var txt = $('#requesttext').html();
	txt = txt.replace("XXX", enclave);
	txt = txt.replace("YYY", quoter);
	let h = await window.crypto.subtle.digest('SHA-256', b64tobytes(sessKey));
	txt = txt.replace("ZZZ", arrayBufferToBase64(h));
	txt = txt.replace("AAA", arrayBufferToBase64(nonce));
	txt = txt.replace("BBB", arrayBufferToBase64(hashpubkey));
	$('#requesttext').html(txt);


	$('#next3').disable(false); 
	$('#requestspinner').hidden(true);
	$('#requestcontent').hidden(false);
};

async function doProcessing() {
	try {
		// Decrypt the genome encryption key
		var data = b64tobytes(receivedEncryptedGenomeEncryptionKey);
		let genomeEncryptionKey = await window.crypto.subtle.decrypt(
				{
					name: "RSA-OAEP",
					hash: "SHA-1"
				},
				keyPair.privateKey,
				data
		);

		// We now re-encrypt the genome key under the Enclave's session public key
		let reencryptedGenomeEncryptionKey = await window.crypto.subtle.encrypt(
				{
					name: "RSA-OAEP"
				},
				enclavePubKey,
				genomeEncryptionKey
		);
		
		let params = "reencryptedGenomeEncryptionKey=" + encodeURIComponent(arrayBufferToBase64(reencryptedGenomeEncryptionKey));
		
		encryptedresponsetxt = await restCall("/sessions/" + sessionID + "/executeQuery", "POST", params);
		
		console.log("Encrypted response: " + encryptedresponsetxt);
		// Now we need to decrypt the response
		let decryptedresponse = await window.crypto.subtle.decrypt(
				{
					name: "RSA-OAEP",
				},
				keyPair.privateKey,
				b64tobytes(encryptedresponsetxt)
		);
		
		decryptedresponsetxt = uintToString(decryptedresponse);
	}
	catch(e)
	{
		console.log("Error");
	}
	var txt = $('#processingtext').html();
	txt = txt.replace("XXX", encryptedresponsetxt);
	txt = txt.replace("YYY", decryptedresponsetxt);
	$('#processingtext').html(txt);
	$('#processingspinner').hidden(true);
	$('#processingcontent').hidden(false);
};

function generatersa()
{
	$('#rsaspinner').hidden(false); 
	$('#generatersa').disable(true);
	registerUser();
}

function uploadgenome()
{
	$('#uploadspinner').hidden(false); 
	$('#uploadgenome').disable(true);
	encryptAndUpload();
}

function lowerrisk()
{
	document.getElementById("genedata").value = lowriskvariant;
}

function higherrisk()
{
	document.getElementById("genedata").value = highriskvariant;
}

function initiaterequest()
{
	$('#requestspinner').hidden(false); 
	$('#requestbutton').disable(true);
	doInitiateRequest();
}

function processing()
{
	$('#processingspinner').hidden(false); 
	$('#processingbutton').disable(true);
	doProcessing();
}