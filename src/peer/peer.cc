// SPDX-License-Identifier: MIT
#include "peer/peer.h"
#include <openssl/sha.h>

namespace Candy {

int Peer::updateKey(const std::string &password) {
    std::string data;
    data.append(password);
    data.append((char *)&this->tunIp, sizeof(this->tunIp));
    this->key.resize(SHA256_DIGEST_LENGTH);
    SHA256((unsigned char *)data.data(), data.size(), (unsigned char *)this->key.data());
    return 0;
}

}; // namespace Candy
