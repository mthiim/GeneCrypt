#
# Copyright 2018 Asylo authors
# Copyright 2019 Martin Thiim
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

licenses(["notice"])  # Apache v2.0

package(
    default_visibility = ["//visibility:public"],
)

load(
    "@com_google_asylo//asylo/bazel:asylo.bzl",
    "enclave_loader",
    "sim_enclave"
)
load("@com_google_asylo//asylo/bazel:proto.bzl", "asylo_proto_library")

asylo_proto_library(
    name = "genecrypt_proto",
    srcs = ["genecrypt.proto"],
    deps = ["@com_google_asylo//asylo:enclave_proto"],
)

sim_enclave(
    name = "genecrypt_enclave",
    srcs = ["genecrypt_enclave.cc"],
    deps = [
        ":genecrypt_proto_cc",
        "@com_google_absl//absl/strings",
        "@com_google_asylo//asylo:enclave_runtime",
        "@com_google_asylo//asylo/crypto:aes_gcm_siv",
        "@com_google_asylo//asylo/util:cleansing_types",
        "@com_google_asylo//asylo/util:status",
    ],
)

enclave_loader(
    name = "genecrypt",
    srcs = ["genecrypt_driver.cc"],
    enclaves = {"enclave": ":genecrypt_enclave"},
    loader_args = ["--enclave_path='{enclave}'"],
    deps = [
        ":genecrypt_proto_cc",
        "@com_github_gflags_gflags//:gflags_nothreads",
        "@com_google_asylo//asylo:enclave_client",
        "@com_google_asylo//asylo/util:logging",
    ],
)

