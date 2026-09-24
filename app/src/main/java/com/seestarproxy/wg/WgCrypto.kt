package com.seestarproxy.wg

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.Blake2sDigest
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.security.SecureRandom
import java.util.Base64

/** Cryptographic primitives used by WireGuard (see the WireGuard whitepaper, §5.4). */
object WgCrypto {
    val random = SecureRandom()

    /** HASH(input): BLAKE2s-256. */
    fun hash(vararg parts: ByteArray): ByteArray {
        val d = Blake2sDigest(256)
        for (p in parts) d.update(p, 0, p.size)
        return ByteArray(32).also { d.doFinal(it, 0) }
    }

    /** MAC(key, input): keyed BLAKE2s with a 16-byte output. */
    fun mac(key: ByteArray, input: ByteArray, len: Int = input.size): ByteArray {
        val d = Blake2sDigest(key, 16, null, null)
        d.update(input, 0, len)
        return ByteArray(16).also { d.doFinal(it, 0) }
    }

    /** HMAC(key, input) with BLAKE2s-256 (block size 64). */
    fun hmac(key: ByteArray, vararg parts: ByteArray): ByteArray {
        val h = HMac(Blake2sDigest(256))
        h.init(KeyParameter(key))
        for (p in parts) h.update(p, 0, p.size)
        return ByteArray(32).also { h.doFinal(it, 0) }
    }

    /** KDFn(key, input): HKDF over HMAC-BLAKE2s, returning [n] 32-byte outputs. */
    fun kdf(n: Int, key: ByteArray, input: ByteArray): List<ByteArray> {
        val prk = hmac(key, input)
        val out = ArrayList<ByteArray>(n)
        var prev = ByteArray(0)
        for (i in 1..n) {
            prev = hmac(prk, prev, byteArrayOf(i.toByte()))
            out.add(prev)
        }
        return out
    }

    private fun nonce(counter: Long): ByteArray {
        val n = ByteArray(12)
        for (i in 0 until 8) n[4 + i] = (counter ushr (8 * i)).toByte()
        return n
    }

    /** AEAD(key, counter, plain, aad): ChaCha20-Poly1305, nonce = 32 zero bits ‖ 64-bit LE counter. */
    fun aeadEncrypt(key: ByteArray, counter: Long, plain: ByteArray, aad: ByteArray?, pOff: Int = 0, pLen: Int = plain.size): ByteArray {
        val c = ChaCha20Poly1305()
        c.init(true, AEADParameters(KeyParameter(key), 128, nonce(counter), aad))
        val out = ByteArray(c.getOutputSize(pLen))
        val n = c.processBytes(plain, pOff, pLen, out, 0)
        c.doFinal(out, n)
        return out
    }

    /** Decrypts or returns null when authentication fails. */
    fun aeadDecrypt(key: ByteArray, counter: Long, cipher: ByteArray, aad: ByteArray?, cOff: Int = 0, cLen: Int = cipher.size): ByteArray? {
        if (cLen < 16) return null
        return try {
            val c = ChaCha20Poly1305()
            c.init(false, AEADParameters(KeyParameter(key), 128, nonce(counter), aad))
            val out = ByteArray(c.getOutputSize(cLen))
            val n = c.processBytes(cipher, cOff, cLen, out, 0)
            c.doFinal(out, n)
            out
        } catch (_: Exception) {
            null
        }
    }

    /** DH(private, public): X25519. */
    fun dh(priv: ByteArray, pub: ByteArray): ByteArray {
        val a = X25519Agreement()
        a.init(X25519PrivateKeyParameters(priv, 0))
        return ByteArray(32).also { a.calculateAgreement(X25519PublicKeyParameters(pub, 0), it, 0) }
    }

    fun generatePrivateKey(): ByteArray {
        val k = X25519PrivateKeyParameters(random).encoded
        // Clamp like `wg genkey` so the stored key is canonical.
        k[0] = (k[0].toInt() and 248).toByte()
        k[31] = ((k[31].toInt() and 127) or 64).toByte()
        return k
    }

    fun publicKey(priv: ByteArray): ByteArray = X25519PrivateKeyParameters(priv, 0).generatePublicKey().encoded

    fun b64(b: ByteArray): String = Base64.getEncoder().encodeToString(b)
    fun unb64(s: String): ByteArray = Base64.getDecoder().decode(s.trim())
}

/** A persisted X25519 keypair. */
class WgKeyPair(val privateKey: ByteArray) {
    val publicKey: ByteArray = WgCrypto.publicKey(privateKey)

    companion object {
        fun generate() = WgKeyPair(WgCrypto.generatePrivateKey())

        /** Loads a base64 private key from [file], generating and saving one if missing. */
        fun loadOrGenerate(file: java.io.File): WgKeyPair {
            if (file.exists()) {
                val k = WgCrypto.unb64(file.readText())
                require(k.size == 32) { "Nieprawidłowy plik klucza ${file.name}" }
                return WgKeyPair(k)
            }
            val kp = generate()
            file.parentFile?.mkdirs()
            file.writeText(WgCrypto.b64(kp.privateKey) + "\n")
            return kp
        }
    }
}
