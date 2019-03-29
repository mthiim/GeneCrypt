/*
*
* Copyright 2018 Asylo authors
* Copyright 2019 Martin Thiim
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

#include <iostream>
#include <string>

#include "asylo/client.h"
#include "asylo/util/logging.h"
#include "gflags/gflags.h"
#include "genecrypt/genecrypt.pb.h"

DEFINE_string(enclave_path, "", "Path to enclave binary image to load");
DEFINE_string(message, "", "Message to encrypt");

// Populates |enclave_input|->value() with |user_message|.
void SetEnclaveUserMessage(asylo::EnclaveInput *enclave_input,
	const std::string &user_message) {
	genecrypt::asylo::GeneCryptMessage *user_input =
		enclave_input->MutableExtension(genecrypt::asylo::genecrypt_input);
	user_input->set_value(user_message);
}

// Retrieves encrypted message from |output|. Intended to be used by the reader
// for completing the exercise.
const std::string GetEnclaveOutputMessage(const asylo::EnclaveOutput &output) {
	return output.GetExtension(genecrypt::asylo::genecrypt_output).value();
}

int main(int argc, char *argv[]) {
	::google::ParseCommandLineFlags(&argc, &argv,
		/*remove_flags=*/true);
	// Part 1: Initialization

	asylo::EnclaveManager::Configure(asylo::EnclaveManagerOptions());
	auto manager_result = asylo::EnclaveManager::Instance();
	LOG_IF(QFATAL, !manager_result.ok()) << "Could not obtain EnclaveManager";

	asylo::EnclaveManager *manager = manager_result.ValueOrDie();
	asylo::SimLoader loader(FLAGS_enclave_path, /*debug=*/true);
	asylo::Status status = manager->LoadEnclave("genecrypt_enclave", loader);
	LOG_IF(QFATAL, !status.ok()) << "LoadEnclave failed with: " << status;

	// Part 2: Secure execution
	// Get first parameter line
	std::string str;
	std::getline(std::cin, str);

	asylo::EnclaveClient *client = manager->GetClient("genecrypt_enclave");
	asylo::EnclaveInput input;
	SetEnclaveUserMessage(&input, str);

	asylo::EnclaveOutput output;
	status = client->EnterAndRun(input, &output);
	LOG_IF(QFATAL, !status.ok()) << "EnterAndRun failed with: " << status;

	std::string outp = GetEnclaveOutputMessage(output);
	std::cout << outp << std::endl;
	std::cout.flush();

	// Read line from console
	std::getline(std::cin, str);
	SetEnclaveUserMessage(&input, str);

	status = client->EnterAndRun(input, &output);
	LOG_IF(QFATAL, !status.ok()) << "Second EnterAndRun failed with: " << status;

	outp = GetEnclaveOutputMessage(output);
	std::cout << outp << std::endl;
	std::cout.flush();

	// Part 3: Finalization
	asylo::EnclaveFinal empty_final_input;
	status = manager->DestroyEnclave(client, empty_final_input);
	LOG_IF(QFATAL, !status.ok()) << "DestroyEnclave failed with: " << status;

	return 0;
}
