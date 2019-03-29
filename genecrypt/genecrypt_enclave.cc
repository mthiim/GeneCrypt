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

#include <string>

#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "asylo/crypto/aes_gcm_siv.h"
#include "asylo/trusted_application.h"
#include "asylo/util/cleansing_types.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"
#include "genecrypt/genecrypt.pb.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

namespace asylo {
	enum EnclaveState {
		ENCLAVE_INIT,
		ENCLAVE_LAUNCHED,
		ENCLAVE_FINISHED
	};

	const int RSA_KEY_SIZE = 256;

	class GCException : public std::exception
	{
	private:
		std::string msg;
		asylo::error::GoogleError err;
	public:
		GCException(asylo::error::GoogleError err, std::string msg)
		{
			this->msg = msg;
			this->err = err;
		}
		const char* what() const throw() {
			return msg.c_str();
		}
		asylo::error::GoogleError getError() const {
			return err;
		}
	};

	// std::unique_ptr specialisation for OpenSSL's RSA* - uses OpenSSL's RSA_free() as the deleter.
	class RSAPtr : public std::unique_ptr<RSA, decltype(&RSA_free)>
	{
	public:
		RSAPtr() : std::unique_ptr<RSA, decltype(&RSA_free)>(NULL, &RSA_free)
		{

		}
	};

	// std::unique_ptr specialisation for OpenSSL's BIGNUM* - uses OpenSSL's BN_free() as the deleter.
	class BNPtr : public std::unique_ptr<BIGNUM, decltype(&BN_free)>
	{
	public:
		BNPtr(BIGNUM *x) : std::unique_ptr<BIGNUM, decltype(&BN_free)>(x, &BN_free)
		{

		}
	};

	// std::unique_ptr specialisation for OpenSSL's CTX* - uses OpenSSL's EVP_CIPHER_CTX_free() as the deleter.
	class CTXPtr : public std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>
	{
	public:
		CTXPtr(EVP_CIPHER_CTX *x) : std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(x, &EVP_CIPHER_CTX_free)
		{

		}
	};

	class EnclaveGeneCrypt : public TrustedApplication {
	private:
		EnclaveState state = ENCLAVE_INIT;
		RSAPtr pSessionKeyPair;
		RSAPtr pReceiverPublicKey;
		std::string nonce;

	public:
		EnclaveGeneCrypt() = default;

		Status Run(const EnclaveInput &input, EnclaveOutput *output) {
			try {
				std::string inputString = GetEnclaveUserMessage(input);

				// Split string into tokens based on '|' character
				std::vector<std::string> tokens = SplitString(inputString);

				std::string res; // Holds the result in case of succ. execution

								 // Dispatch to function based on enclave state
				if (state == ENCLAVE_INIT) {
					res = Launch(tokens);
					state = ENCLAVE_LAUNCHED;

				}
				else if (state == ENCLAVE_LAUNCHED) {
					res = ExecuteQuery(tokens);
					state = ENCLAVE_FINISHED;
				}
				else {
					throw GCException(asylo::error::GoogleError::FAILED_PRECONDITION, "Invalid state");
				}
				SetEnclaveOutputMessage(output, res);
				return Status::OkStatus();
			}
			catch (GCException &err)
			{
				return asylo::Status(err.getError(), err.what());
			}
		}
	private:
		std::string Launch(std::vector<std::string> &tokens)
		{
			if (tokens.size() != 2) {
				throw GCException(asylo::error::GoogleError::INVALID_ARGUMENT, "Invalid number of arguments");
			}
			this->nonce = tokens[0];

			std::string recvPubKey = tokens[1];

			// Import the receiver public key - first we b64 decode it
			std::string recvKeyDecoded;
			absl::Base64Unescape(recvPubKey, &recvKeyDecoded);

			// We take a copy of the ptr since OpenSSL moves it (takes ptr-to-ptr as arg).
			const unsigned char *pDecodedPubKeyTmp = (unsigned char*)recvKeyDecoded.data();

			// Import the public key
			this->pReceiverPublicKey.reset(d2i_RSA_PUBKEY(NULL, &pDecodedPubKeyTmp, recvKeyDecoded.size()));
			if (this->pReceiverPublicKey.get() == NULL) {
				throw GCException(asylo::error::GoogleError::INTERNAL, "Error importing receiver public key");
			}


			if (RSA_size(this->pReceiverPublicKey.get()) != RSA_KEY_SIZE) {
				throw GCException(asylo::error::GoogleError::INVALID_ARGUMENT, "Invalid bit size");
			}

			// Import went OK
			// Prepare public exponent for key generation
			unsigned long e = RSA_F4;
			BNPtr bne(BN_new());
			if (bne.get() == NULL) {
				throw GCException(asylo::error::GoogleError::INTERNAL, "Couldn't allocate RSA");
			}
			BN_set_word(bne.get(), e); // This function just returns the digit we set - not an error code, so not worth checking

			// Create RSA object
			this->pSessionKeyPair.reset(RSA_new());
			if (this->pSessionKeyPair.get() == NULL) {
				throw GCException(asylo::error::GoogleError::INTERNAL, "Couldn't allocate RSA object");
			}

			// Generate the key
			if(RSA_generate_key_ex(this->pSessionKeyPair.get(), 8*RSA_KEY_SIZE, bne.get(), NULL) != 1) {
				throw GCException(asylo::error::GoogleError::INTERNAL, "Key generation error");
			}

			unsigned char *pOut = NULL;
			// Since pOut is NULL, i2d will allocate space itself and return the length
			int keyLen = i2d_RSA_PUBKEY(this->pSessionKeyPair.get(), &pOut);
			if (keyLen < 1) {
				throw GCException(asylo::error::GoogleError::INTERNAL, "Export error");
			}

			// Ret now holds the length of the data - turn it into a string
			std::string keydata((char*)pOut, keyLen);

			// We can now free the buffer
			OPENSSL_free(pOut);

			// Base64 encode it
			std::string base64_out;
			absl::Base64Escape(keydata, &base64_out);

			// Note the return value below is what critically needs to be quoted so it can be remotely attested that they come from a trusted enclave
			// running on a secure setup.
			return base64_out + "," + nonce + "," + recvPubKey;
		}

		std::string ExecuteQuery(std::vector<std::string> &tokens)
		{
			if (tokens.size() != 3) {
				throw GCException(asylo::error::GoogleError::INVALID_ARGUMENT, "Invalid number of arguments");
			}

			// Base64 decode the input
			std::string encGenome, encGenomeKey, encGenomeIV;
			absl::Base64Unescape(tokens[0], &encGenome);
			absl::Base64Unescape(tokens[1], &encGenomeIV);
			absl::Base64Unescape(tokens[2], &encGenomeKey);

			std::unique_ptr<uint8_t[]> pDecGenomeKey(new uint8_t[encGenomeKey.size()]);

			int lDecGenomeKey = RSA_private_decrypt(encGenomeKey.size(), (uint8_t*)encGenomeKey.data(), pDecGenomeKey.get(), this->pSessionKeyPair.get(), RSA_PKCS1_OAEP_PADDING);
			if (lDecGenomeKey <= 0) {
				throw GCException(asylo::error::GoogleError::INTERNAL, "Genome key decryption error");
			}

			// Allocate cipher CTX with custom deleter
			CTXPtr ctx(EVP_CIPHER_CTX_new());
			if (ctx.get() == NULL) {
				throw GCException(asylo::error::GoogleError::INTERNAL, "Couldn't allocate cipher CTX");
			}

			// Initialize cipher
			if (1 != EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), NULL, NULL, NULL))
			{
				throw GCException(asylo::error::GoogleError::INTERNAL, "Genome decryption init error");
			}

			// Set IV length (function returns 'int' but no return value documented)
			EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, 16, NULL);
			if (1 != EVP_DecryptInit_ex(ctx.get(), NULL, NULL, pDecGenomeKey.get(), (uint8_t*)encGenomeIV.data()))
			{
				throw GCException(asylo::error::GoogleError::INTERNAL, "Genome decryption init error (2)");

			}

			// Set tag length (function returns 'int' but no return value documented)
			EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16, (uint8_t*)(encGenome.data() + encGenome.size() - 16));

			// Allocate space for decrypted genome (zeroized)
			std::unique_ptr<char[]> pPlain(new char[encGenome.size() + 1]());

			// Length of encrypted genome (is updated by func call below)
			int len = encGenome.size();
			if (1 != EVP_DecryptUpdate(ctx.get(), (uint8_t*)pPlain.get(), &len, (uint8_t*)encGenome.data(), encGenome.size() - 16)) {
				throw GCException(asylo::error::GoogleError::INTERNAL, "Genome decryption update error");
			}

			int plaintext_len = len;
			if (1 != EVP_DecryptFinal_ex(ctx.get(), NULL, &len)) {
				throw GCException(asylo::error::GoogleError::INTERNAL, "Genome decryption finalization error");

			}

			// Final length of plaintext (if anything was added during the step above)
			plaintext_len += len;


			// Will hold the value we return encrypted under the receiver public key
			std::string rval;

			// Below is the actual genome "analysis" part :-)
			if (plaintext_len < 4) {
				// If genome is too short, simply report "false"
				rval = "false";
			}
			else {
				// Report risk variant (!= A at position 3 is high-risk, e.g. true);
				rval = (pPlain[3] == 'A') ? "false" : "true";
			}


			std::unique_ptr<unsigned char[]> outresult(new unsigned char[RSA_KEY_SIZE]);
			int lEncResult = RSA_public_encrypt(rval.length(), (uint8_t*)rval.c_str(), outresult.get(), pReceiverPublicKey.get(), RSA_PKCS1_OAEP_PADDING);
			if (lEncResult <= 0) {
				throw GCException(asylo::error::GoogleError::INTERNAL, "Error encrypting under public key");
			}
			// Base64-encode the result
			std::string base64_out;
			std::string encdata((char*)outresult.get(), lEncResult);
			absl::Base64Escape(encdata, &base64_out);
			return base64_out;
		}

		// Retrieves user message from |input|.
		const std::string GetEnclaveUserMessage(const EnclaveInput &input) {
			return input.GetExtension(genecrypt::asylo::genecrypt_input).value();
		}

		// Populates |enclave_output|->value() with |output_message|. Intended to be
		// used by the reader for completing the exercise.
		void SetEnclaveOutputMessage(EnclaveOutput *enclave_output,
			const std::string &output_message) {
			genecrypt::asylo::GeneCryptMessage *output =
				enclave_output->MutableExtension(genecrypt::asylo::genecrypt_output);
			output->set_value(output_message);
		}

		std::vector<std::string> SplitString(std::string s) const
		{
			size_t pos = 0;
			std::vector<std::string> tokens;
			while ((pos = s.find("|")) != std::string::npos) {
				std::string token = s.substr(0, pos);
				tokens.push_back(token);
				s.erase(0, pos + 1);
			}
			tokens.push_back(s);
			return tokens;
		}
	};

	TrustedApplication *BuildTrustedApplication() { return new EnclaveGeneCrypt; }
} // namespace asylo
