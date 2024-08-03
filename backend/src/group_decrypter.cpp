/*
 * Parts of this file come from
 * https://github.com/mfontanini/libtins/blob/master/src/crypto.cpp
 * hence the following copyright notice
 *
 * Copyright
 * (c) 2017, Matias Fontanini All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following disclaimer
 *   in the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "decrypter.h"
#include <algorithm>
#include <cstdint>
#include <fmt/format.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <spdlog/spdlog.h>
#include <tins/dot11.h>
#include <tins/rawpdu.h>
#include <tins/snap.h>
#include <vector>

namespace yarilo {

template <typename InputIterator1, typename InputIterator2,
          typename OutputIterator>
void xor_range(InputIterator1 src1, InputIterator2 src2, OutputIterator dst,
               size_t sz) {
  for (size_t i = 0; i < sz; ++i)
    *dst++ = *src1++ ^ *src2++;
}

Tins::SNAP *WPA2Decrypter::decrypt_group_data(const Tins::Dot11Data &data,
                                              Tins::RawPDU &raw,
                                              const gtk_type &gtk) const {
  Tins::RawPDU::payload_type &payload = raw.payload();
  uint8_t AAD[32] = {0}; // additional auth data
  AAD[0] = 0;
  AAD[1] = 22 + 6 * int(data.from_ds() && data.to_ds());
  if (data.subtype() == Tins::Dot11::QOS_DATA_DATA)
    AAD[1] += 2;
  AAD[2] =
      data.protocol() | (data.type() << 2) | ((data.subtype() << 4) & 0x80);
  AAD[3] = 0x40 | data.to_ds() | (data.from_ds() << 1) |
           (data.more_frag() << 2) | (data.order() << 7);
  data.addr1().copy(AAD + 4);
  data.addr2().copy(AAD + 10);
  data.addr3().copy(AAD + 16);

  AAD[22] = data.frag_num();
  AAD[23] = 0;

  if (data.from_ds() && data.to_ds()) {
    data.addr4().copy(AAD + 24);
  }

  AES_KEY ctx;
  AES_set_encrypt_key(&gtk[0], 128, &ctx);
  uint8_t crypted_block[16];
  size_t total_sz = raw.payload_size() - 16, offset = 8,
         blocks = (total_sz + 15) / 16;

  uint8_t counter[16];
  counter[0] = 0x59;
  counter[1] = 0;
  data.addr2().copy(counter + 2);
  uint8_t PN[6] = {payload[7], payload[6], payload[5],
                   payload[4], payload[1], payload[0]}; // packet nubmer
  std::copy(PN, PN + 6, counter + 8);
  counter[14] = (total_sz >> 8) & 0xff;
  counter[15] = total_sz & 0xff;

  if (data.subtype() == Tins::Dot11::QOS_DATA_DATA) {
    const uint32_t offset = (data.from_ds() && data.to_ds()) ? 30 : 24;
    AAD[offset] =
        static_cast<const Tins::Dot11QoSData &>(data).qos_control() & 0x0f;
    counter[1] = AAD[offset];
  }

  uint8_t MIC[16] = {0}; // message integrity code
  AES_encrypt(counter, MIC, &ctx);
  xor_range(MIC, AAD, MIC, 16);
  AES_encrypt(MIC, MIC, &ctx);
  xor_range(MIC, AAD + 16, MIC, 16);
  AES_encrypt(MIC, MIC, &ctx);

  counter[0] = 1;
  counter[14] = counter[15] = 0;
  AES_encrypt(counter, crypted_block, &ctx);
  uint8_t nice_MIC[8];
  copy(payload.begin() + payload.size() - 8, payload.end(), nice_MIC);
  xor_range(crypted_block, nice_MIC, nice_MIC, 8);
  for (size_t i = 1; i <= blocks; ++i) {
    size_t block_sz = (i == blocks) ? (total_sz % 16) : 16;
    if (block_sz == 0)
      block_sz = 16;
    counter[14] = (i >> 8) & 0xff;
    counter[15] = i & 0xff;
    AES_encrypt(counter, crypted_block, &ctx);
    xor_range(crypted_block, &payload[offset], &payload[(i - 1) * 16],
              block_sz);
    xor_range(MIC, &payload[(i - 1) * 16], MIC, block_sz);
    AES_encrypt(MIC, MIC, &ctx);
    offset += block_sz;
  }

  if (std::equal(nice_MIC, nice_MIC + sizeof(nice_MIC), MIC)) {
    return new Tins::SNAP(&payload[0], total_sz);
  } else {
    return 0;
  }
}

std::optional<std::vector<uint8_t>>
WPA2Decrypter::exctract_key_data(const Tins::RSNEAPOL &eapol,
                                 const ptk_type &ptk) const {
  AES_KEY aeskey;
  std::vector<uint8_t> kek(ptk.begin() + 16, ptk.begin() + 32);
  if (AES_set_decrypt_key(kek.data(), 128, &aeskey) != 0) {
    fprintf(stderr, "%s: AES_set_decrypt_key failed\n", __FUNCTION__);
    return std::nullopt;
  }

  std::vector<uint8_t> result(2304);
  int outlen = AES_unwrap_key(&aeskey, NULL, result.data(), eapol.key().data(),
                              eapol.wpa_length());
  if (outlen <= 0) {
    fprintf(stderr, "%s: AES_unwrap_key failed: %d\n", __FUNCTION__, outlen);
    return std::nullopt;
  }

  // Decrypted key data is a tagged list
  for (uint8_t i = 0; i < outlen; i++) {
    uint8_t tag_number = result[i];
    uint8_t tag_length = result[i + 1];
    if (tag_number != 221) {
      // Jump over this tag
      i += tag_length + 1;
      continue;
    }

    // Last 16 bytes are the GTK
    gtk_type gtk(16);
    for (int j = 0; j < 16; j++)
      gtk[j] = result[i + tag_length - 14 + j];
    return gtk;
  }

  return std::nullopt;
}

} // namespace yarilo
