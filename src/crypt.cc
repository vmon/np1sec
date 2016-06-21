/**
 * Multiparty Off-the-Record Messaging library
 * Copyright (C) 2014, eQualit.ie
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of version 3 of the GNU Lesser General
 * Public License as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/*
 * For debug reason use
 * gcryp_sexp_dump and gcry_mpi_dump
 */
#ifndef SRC_CRYPT_CC_
#define SRC_CRYPT_CC_

#include <iostream>
#include <cstdio>
#include <string>
#include <gcrypt.h>

#include "src/crypt.h"
#include "src/exceptions.h"
#include "src/logger.h"
#include "common.h"
#include "crypt.h"
#include "exceptions.h"

namespace np1sec
{

/**
 * Hash an array of HashBlocks.
 * @param {HashBlock*} superblob - A pointer to the first HashBlock in an array
 * @param {size_t} num_blocks - The number of HashBlocks in the array (not the number of bytes!)
 * @param {HashBlock} to_write - A HashBlock to write the result of the hash to
 * @param {bool} secure - Whether the hash needs to be performed securely or not
 */
gcry_error_t hash(const HashBlock* superblob, size_t num_blocks, HashBlock to_write, bool secure)
{
    // Treat an array of HashBlocks as one giant blob to hash
    return hash(superblob, c_hash_length * num_blocks, to_write, secure);
}

gcry_error_t hash(const void* buffer, size_t buffer_len, HashBlock hb)
{
    return hash(buffer, buffer_len, hb, true);
}

gcry_error_t hash(const std::string string_buffer, HashBlock hb)
{
    return hash(string_buffer, hb, true);
}

HashStdBlock hash(const std::string string_buffer)
{
    return hash(string_buffer, true);
}

gcry_error_t hash(const void* buffer, size_t buffer_len, HashBlock hb, bool secure)
{
    gcry_error_t err = 0;
    gcry_md_hd_t digest = nullptr;
    unsigned int flags = 0;
    unsigned char* hash_str = nullptr;

    if (secure)
        flags |= GCRY_MD_FLAG_SECURE;

    err = gcry_md_open(&digest, c_np1sec_hash, flags);
    if (err)
        goto done;

    gcry_md_write(digest, buffer, buffer_len);
    hash_str = gcry_md_read(digest, c_np1sec_hash);
    assert(hash_str);
    memcpy(hb, hash_str, sizeof(HashBlock));

done:
    gcry_md_close(digest);
    return err;
}

Cryptic::Cryptic()
{
    memset(session_key, 0, c_hash_length);
}

bool generate_key_pair(AsymmetricKey* generated_key)
{
    /* Generate a new Ed25519 key pair. */
    gcry_error_t err = 0;
    gcry_sexp_t ed25519_params = nullptr;

    err = gcry_sexp_build(&ed25519_params, NULL, "(genkey (ecc (curve Ed25519) (flags eddsa)))");
    if (err)
        goto err;

    err = gcry_pk_genkey(generated_key, ed25519_params);
    gcry_sexp_release(ed25519_params);

    if (err)
        goto err;

    return true;

err:
    logger.error(std::string("Key failure: ") + gcry_strsource(err) + "/" + gcry_strerror(err), __FUNCTION__);
    throw CryptoException();
    return false;
}

bool Cryptic::init()
{
    /* Generate a new Ed25519 key pair. */
    gcry_error_t err = 0;
    gcry_sexp_t ed25519_params = nullptr;

    err = gcry_sexp_build(&ed25519_params, NULL, "(genkey (ecc (curve Ed25519) (flags eddsa)))");
    if (err)
        goto err;

    err = gcry_pk_genkey(&ephemeral_key, ed25519_params);
    gcry_sexp_release(ed25519_params);
    if (err) {
        goto err;
    }

    ephemeral_pub_key = gcry_sexp_find_token(ephemeral_key, "public-key", 0);
    if (!ephemeral_pub_key) {
        gcry_sexp_release(ephemeral_key);
        logger.error("failed to retrieve public key", __FUNCTION__);
        throw CryptoException();
        return false;
    }

    ephemeral_prv_key = gcry_sexp_find_token(ephemeral_key, "private-key", 0);
    if (!ephemeral_prv_key) {
        gcry_sexp_release(ephemeral_key);
        gcry_sexp_release(ephemeral_pub_key);
        logger.error("failed to retrieve private key", __FUNCTION__);
        throw CryptoException();
        return false;
    }

    return true;

err:
    logger.error(std::string("Key failure: ") + gcry_strsource(err) + "/" + gcry_strerror(err), __FUNCTION__);
    throw CryptoException();
}

std::string hash_to_string_buff(const HashBlock hash_block)
{
    return std::string(reinterpret_cast<const char*>(hash_block), sizeof(HashBlock));
}

/**
 * cast the string hash to unit8_t* dies if the size isn't correct
 * the buffer is only valid as long as the HashStdBlock is valid
 */
const uint8_t* strbuff_to_hash(const std::string& hash_block_buffer)
{
    logger.assert_or_die(hash_block_buffer.size() == sizeof(HashBlock), "Hash block doesn't have std size");
    return reinterpret_cast<const uint8_t*>(hash_block_buffer.c_str());
}

/**
 * the given public key need to be explicitly released
 */
PublicKey extract_public_key(const AsymmetricKey complete_key)
{
    return gcry_sexp_find_token(complete_key, "public-key", 0);
}

/**
 * Compares two hashblocks, returning 0 if the two are equal, to be consistent with
 * memcmp, or 1 if they are unequal.
 * @param {HashBlock} lhs - The first hashblock
 * @param {HashBlock} rhs - The hashblock to compare the first against
 * @return 0 if the two hashblocks are equal, else 1
 */
int compare_hash(const HashBlock rhs, const HashBlock lhs)
{
    char equal = 0;
    size_t to_compare = sizeof(HashBlock);
    for (unsigned int i = 0; i < to_compare; i++) {
        equal |= lhs[i] ^ rhs[i];
    }
    return equal;
}


HashStdBlock hash(const std::string string_buffer, bool secure = true)
{
    HashBlock hb;
    gcry_error_t err = hash(string_buffer.c_str(), string_buffer.size(), hb, secure);
    if (err) {
        throw CryptoException();
    }
    return hash_to_string_buff(hb);
}

gcry_error_t hash(const std::string string_buffer, HashBlock hb, bool secure = true)
{
    return hash(string_buffer.c_str(), string_buffer.size(), hb, secure);
}

gcry_sexp_t get_public_key(AsymmetricKey key_pair)
{
    return gcry_sexp_find_token(key_pair, "public-key", 0);
}

std::string public_key_to_stringbuff(AsymmetricKey public_key)
{
    gcry_sexp_t q_of_pub_key = gcry_sexp_find_token(public_key, "q", 0);
    if (!q_of_pub_key)
        throw CryptoException();

    std::string pubkey_blob = retrieve_result(q_of_pub_key);
    gcry_sexp_release(q_of_pub_key);

    return pubkey_blob;
}

std::string retrieve_result(gcry_sexp_t text_sexp)
{

    size_t buffer_size;
    const char* buffer;
    buffer = gcry_sexp_nth_data(text_sexp, 1, &buffer_size);

    if (!buffer_size) {
        logger.error("failed to convert s-expression to string", __FUNCTION__);
        throw CryptoException();
    }

    std::string result(buffer, buffer_size);
    return result;
}
gcry_sexp_t convert_to_sexp(std::string text)
{
    gcry_error_t err = 0;
    gcry_sexp_t new_sexp;

    err = gcry_sexp_new(&new_sexp, text.c_str(), text.size(), 1);
    if (err) {
        logger.error("convert_to_sexp failed to convert plain_text to gcry_sexp_t", __FUNCTION__);
        logger.error(std::string("Failure: ") + gcry_strsource(err) + "/" + gcry_strerror(err), __FUNCTION__);
        throw CryptoException();
    }
    return new_sexp;
}

/**
 * This function gets the value for q section of public-key and
 * reconstruct the whole sexp to be used in libgcrypt functions
 *
[open]
[data="public-key"]
[open]
  [data="ecc"]
  [open]
    [data="curve"]
    [data="Ed25519"]
  [close]
  [open]
    [data="flags"]
    [data="eddsa"]
  [close]
  [open]
    [data="q"]
    [data="\xb83jR\xea\xebtI\xab\\x91E\xda\xff|Y\x94\xe1\xeck\xa8I<d\x804+\x18\x9b\xe5\x7f!"]
  [close]
[close]
[close]
 */
AsymmetricKey reconstruct_public_key_sexp(const std::string pub_key_block)
{
    gcry_error_t err = 0;
    AsymmetricKey public_key_sexp = nullptr;

    err = gcry_sexp_build(&public_key_sexp, NULL, "(public-key (ecc (curve Ed25519) (flags eddsa) (q %b)))",
                          pub_key_block.size(), pub_key_block.data());
    if (err)
        goto err;

    return public_key_sexp;

err:
    logger.error(std::string("failed to construct public key: ") + gcry_strsource(err) + "/" + gcry_strerror(err),
                 __FUNCTION__);
    throw CryptoException();
    return nullptr;
}

void release_crypto_resource(gcry_sexp_t crypto_resource)
{
    if (crypto_resource) {
        gcry_sexp_release(crypto_resource);
    }
}

gcry_sexp_t copy_crypto_resource(gcry_sexp_t crypto_resource)
{
    gcry_sexp_t copied_resource;
    gcry_error_t err = gcry_sexp_build(&copied_resource, NULL, "%S", crypto_resource);
    if (err) {
        logger.abort(std::string("failed to copy crypto resource: ") + gcry_strsource(err) + "/" + gcry_strerror(err),
                     __FUNCTION__);
        throw CryptoException();
        return nullptr;
    }

    return copied_resource;
};

/**
 * Given the peer's long term and ephemeral public key AP and ap, and ours
 * BP, bP, all points on ed25519 curve, this
 * compute the triple dh value.
 *
 * @param peer_ephemeral_key the ephemeral public key of peer i.e. aP
 *                           in grcypt eddsa public key format
 * @param peer_long_term_key the long term public key of the peer i.e AP
 *                            in gcrypt eddsa public key format
 * @param my_long_term_key   our longterm key in eddsa format
 * @param order
 * @param teddh_token        a pointer to hash block to store
 *        hash(bAP|BaP|baP) if AP.X|AP.Y < BP.X|BP.Y other wise
 *        hash(BaP|bAP|baP) in GCRYMPI_FMT_USG format if the pointer is null
 *         , necessary space will be allocated.
 *
 * @return true if succeeds otherwise false
 */
void Cryptic::triple_ed_dh(PublicKey peer_ephemeral_key, PublicKey peer_long_term_key,
                           AsymmetricKey my_long_term_key, bool peer_is_first, Token* teddh_token)
{
    gcry_error_t err = 0;
    bool failed = true;
    // we need to call
    // static gcry_err_code_t ecc_decrypt_raw (gcry_sexp_t *r_plain, gcry_sexp_t s_data, gcry_sexp_t keyparms)
    // which is ecdh function of gcryp (what a weird name?) such that:
    // gcrypt:
    // give the secret key as a key pair in keyparams
    // extract the point of  public key of the peer as s_data
    // this is quite a complicated opertaion so
    // we use ecc_encrypt_raw(the_public_point, 1, key);
    // initiating the to be encrypted 1

    gcry_sexp_t triple_dh_sexp[3] = {};
    std::string token_concat;

    gcry_sexp_t my_long_term_secret_scaler = gcry_sexp_nth(gcry_sexp_find_token(my_long_term_key, "a", 0), 1);
    gcry_sexp_t my_ephemeral_secret_scaler = gcry_sexp_nth(gcry_sexp_find_token(ephemeral_key, "a", 0), 1);

    if (!(my_long_term_secret_scaler && my_ephemeral_secret_scaler)) {
        logger.error(
            "teddh: failed to retreive long or ephemeral secret scaler, possibly using a wrong version of gcryp",
            __FUNCTION__);
        goto leave;
    }

    // bAP
    err = gcry_pk_encrypt(triple_dh_sexp + (peer_is_first ? 0 : 1), my_ephemeral_secret_scaler, peer_long_term_key);

    if (err) {
        logger.error("teddh: failed to compute dh token\n", __FUNCTION__);
        logger.error(std::string("Failure: ") + gcry_strsource(err) + "/" + gcry_strerror(err), __FUNCTION__);
        goto leave;
    }

    // BaP
    err = gcry_pk_encrypt(triple_dh_sexp + (peer_is_first ? 1 : 0), my_long_term_secret_scaler, peer_ephemeral_key);
    if (err) {
        logger.error("teddh: failed to compute dh token\n", __FUNCTION__);
        logger.error(std::string("Failure: ") + gcry_strsource(err) + "/" + gcry_strerror(err), __FUNCTION__);
        goto leave;
    }

    // abP
    err = gcry_pk_encrypt(triple_dh_sexp + 2, my_ephemeral_secret_scaler, peer_ephemeral_key);

    if (err) {
        logger.error("teddh: failed to compute dh token\n", __FUNCTION__);
        logger.error(std::string("Failure: ") + gcry_strsource(err) + "/" + gcry_strerror(err), __FUNCTION__);
        goto leave;
    }

    uint8_t buffer[c_tdh_point_length * 3]; // 65 bytes are written in our call to gcry_sexp_nth_data
    for (int i = 0; i < 3; i++) {
        gcry_sexp_t cur_tdh_point = gcry_sexp_find_token(triple_dh_sexp[i], "s", 0);
        if (!cur_tdh_point) {
            logger.error("teddh: failed to extract tdh token\n", __FUNCTION__);
            goto leave;
        }
        size_t buffer_len;
        const char* tmp_buffer;
        tmp_buffer = gcry_sexp_nth_data(cur_tdh_point, 1, &buffer_len);
        memcpy(buffer + (sizeof(uint8_t) * i * c_tdh_point_length), tmp_buffer, c_tdh_point_length);
        gcry_sexp_release(cur_tdh_point);
    }

    if (teddh_token == NULL)
        teddh_token = new Token[1]; // so stupid!!!

    hash(buffer, c_tdh_point_length * 3, *teddh_token, true);
    secure_wipe(buffer, c_tdh_point_length * 3);

    failed = false;

leave:
    gcry_sexp_release(my_long_term_secret_scaler);
    gcry_sexp_release(my_ephemeral_secret_scaler);
    for (int i = 0; i < 3; i++)
        gcry_sexp_release(triple_dh_sexp[i]);

    if (failed)
        throw CryptoException();
};

void Cryptic::sign(unsigned char** sigp, size_t* siglenp, std::string plain_text)
{
    const char *r, *s;
    gcry_error_t err = 0;
    gcry_sexp_t plain_sexp = nullptr, sigs = nullptr, eddsa = nullptr, rs = nullptr, ss = nullptr;
    size_t nr, ns;
    const uint32_t magic_number = 64, half_magic_number = 32;

    *sigp = new unsigned char[magic_number];
    if (*sigp == nullptr) {
        logger.abort("Failed to allocate memory.");
    }

    err = gcry_sexp_build(&plain_sexp, NULL, "(data"
                                             " (flags eddsa)"
                                             " (hash-algo sha512)"
                                             " (value %b))",
                          plain_text.size(), plain_text.c_str());

    if (err) {
        logger.error("failed to build gcry_sexp_t for signing", __FUNCTION__);
        goto err;
    }

    err = gcry_pk_sign(&sigs, plain_sexp, ephemeral_prv_key);

    if (err) {
        gcry_sexp_release(plain_sexp);
        logger.error("failed to sign plain_text", __FUNCTION__);
        goto err;
    }

    gcry_sexp_release(plain_sexp);
    eddsa = gcry_sexp_find_token(sigs, "eddsa", 0);

    gcry_sexp_release(sigs);
    if (!(eddsa)) {
        logger.error("signature doens't contain eddsa token", __FUNCTION__);
        goto err;
    }

    rs = gcry_sexp_find_token(eddsa, "r", 0);
    if (!(rs)) {
        gcry_sexp_release(eddsa);
        logger.error("no r in eddsa signature", __FUNCTION__);
        goto err;
    }

    ss = gcry_sexp_find_token(eddsa, "s", 0);
    if (!(ss)) {
        gcry_sexp_release(eddsa);
        gcry_sexp_release(rs);
        logger.error("no s in eddsa signature", __FUNCTION__);
        goto err;
    }

    r = gcry_sexp_nth_data(rs, 1, &nr);

    s = gcry_sexp_nth_data(ss, 1, &ns);
    memset(*sigp, 0, magic_number);

    logger.assert_or_die(nr == 32 && ns == 32, "wrong signature length");

    memcpy(*sigp, r, nr);
    memcpy((*sigp) + half_magic_number, s, ns);

    gcry_sexp_release(rs);
    gcry_sexp_release(ss);

    // it seems that we have assumed this
    logger.assert_or_die(magic_number == nr + ns, "signature length is wrong", __FUNCTION__);
    *siglenp = magic_number;

    return;

err:
    if (*sigp)
        delete[] * sigp;
    logger.error("Failure: " + (std::string)gcry_strsource(err) + ": " + (std::string)gcry_strerror(err));
    throw CryptoException();
}

bool Cryptic::verify(std::string plain_text, const unsigned char* sigbuf, PublicKey signer_ephemeral_pub_key)
{
    gcry_error_t err;
    gcry_sexp_t datas = nullptr, sigs = nullptr;
    static const uint32_t nr = 32, ns = 32;

    err = gcry_sexp_build(&sigs, NULL, "(sig-val (eddsa (r %b)(s %b)))", nr, sigbuf, ns, sigbuf + nr);

    if (err) {
        logger.error("failed to construct gcry_sexp_t for the signature", __FUNCTION__);
        goto err;
    }

    err = gcry_sexp_build(&datas, NULL, "(data"
                                        " (flags eddsa)"
                                        " (hash-algo sha512)"
                                        " (value %b))",
                          plain_text.size(), plain_text.c_str());

    if (err) {
        gcry_sexp_release(sigs);
        logger.error("failed to build gcry_sexp_t for the signed blob", __FUNCTION__);
        goto err;
    }

    err = gcry_pk_verify(sigs, datas, signer_ephemeral_pub_key);

    gcry_sexp_release(sigs);
    gcry_sexp_release(datas);
    if (err == GPG_ERR_NO_ERROR) {
        logger.debug("good signature", __FUNCTION__);
        return true;

    } else if (err == GPG_ERR_BAD_SIGNATURE) {
        logger.warn("failed to verify signed blobed", __FUNCTION__);
        logger.warn("Failure: " + (std::string)gcry_strsource(err) + "/" + (std::string)gcry_strerror(err),
                    __FUNCTION__);
        return false;
    } else {
        logger.error("verification computation failed", __FUNCTION__);
        goto err;
    }

err:
    logger.error(plain_text, __FUNCTION__);
    logger.error("Failure: " + (std::string)gcry_strsource(err) + ": " + (std::string)gcry_strerror(err), __FUNCTION__);
    throw CryptoException();
}

gcry_cipher_hd_t Cryptic::OpenCipher()
{
    gcry_error_t err = 0;
    gcry_cipher_hd_t hd = nullptr;
    int algo = GCRY_CIPHER_AES256, mode = GCRY_CIPHER_MODE_GCM;

    err = gcry_cipher_open(&hd, algo, mode, 0);
    if (err) {
        logger.error("Failed to create GCMb Block cipher", __FUNCTION__);
        goto err;
    }

    err = gcry_cipher_setkey(hd, session_key, sizeof(np1secSymmetricKey));
    if (err) {
        logger.error("Failed to set the block cipher key", __FUNCTION__);
        goto err;
    }

    return hd;

err:
    if (hd)
        gcry_cipher_close(hd);
    logger.error("Failure: " + (std::string)gcry_strsource(err) + ": " + (std::string)gcry_strerror(err), __FUNCTION__);
    throw CryptoException();
}

std::string Cryptic::Encrypt(std::string plain_text)
{
    std::string crypt_text = plain_text;
    gcry_error_t err = 0;
    gcry_cipher_hd_t hd = OpenCipher(); // TODO: we shouldn't need to open cipher all the time

    IVBlock buffer;

    gcry_randomize(buffer, c_iv_length, GCRY_STRONG_RANDOM);
    err = gcry_cipher_setiv(hd, buffer, c_iv_length);

    if (err) {
        logger.error("Failed to set the block cipher iv", __FUNCTION__);
        goto err;
    }

    err = gcry_cipher_encrypt(hd, const_cast<char*>(crypt_text.c_str()), crypt_text.size(), NULL, 0);
    if (err) {
        logger.error("Encryption of message failed", __FUNCTION__);
        goto err;
    }

    crypt_text = std::string(reinterpret_cast<char*>(buffer), c_iv_length) + crypt_text;

    gcry_cipher_close(hd);
    return crypt_text;

err:
    if (hd)
        gcry_cipher_close(hd);
    logger.error("Failure: " + (std::string)gcry_strsource(err) + ": " + (std::string)gcry_strerror(err));
    throw CryptoException();
}

std::string Cryptic::Decrypt(std::string encrypted_text)
{
    gcry_error_t err = 0;
    gcry_cipher_hd_t hd = OpenCipher();

    // The first 16bytes of encrypted text is the iv
    err = gcry_cipher_setiv(hd, encrypted_text.data(), c_iv_length);

    if (err) {
        logger.error("Failed to set the block cipher iv");
        goto err;
    } else {
        std::string decrypted_text = encrypted_text.substr(c_iv_length);

        err = gcry_cipher_decrypt(hd, const_cast<char*>(decrypted_text.c_str()), decrypted_text.size(), NULL, 0);
        if (err) {
            logger.error("failed to decrypt message");
            goto err;
        }

        gcry_cipher_close(hd);
        return decrypted_text;
    }

err:
    if (hd)
        gcry_cipher_close(hd);
    logger.error("Failure: " + (std::string)gcry_strsource(err) + ": " + (std::string)gcry_strerror(err));
    throw CryptoException();
}

Cryptic::~Cryptic()
{
    gcry_sexp_release(ephemeral_key);
    gcry_sexp_release(ephemeral_pub_key);
    gcry_sexp_release(ephemeral_prv_key);
    secure_wipe(session_key, c_hash_length);

    ephemeral_key = nullptr;
    ephemeral_pub_key = nullptr;
    ephemeral_prv_key = nullptr;
    
    logger.debug("Wiped session_key from Cryptic instance");
}

} // namespace np1sec

#endif // SRC_CRYPT_CC_
