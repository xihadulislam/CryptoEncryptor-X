package com.xihadulislam.cryptoencryptor

import android.util.Base64
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 *
 * @Ziad {xihadulislam}
 * gihub: https://github.com/xihadulislam?tab=repositories
 *
 */
object CryptoEncryptor {

    private const val KEY_SIZE = 256
    private const val IV_SIZE = 128
    private const val HASH_CIPHER = "AES/CBC/PKCS7Padding"
    private const val AES = "AES"

    private const val APPEND = "Salted__"

    /**
     * Encrypt
     * @param password passphrase
     * @param plainText plain string
     */
    fun encrypt(password: String, plainText: String): String? {
        try {
            val saltBytes = CryptoAES.generateSalt(8)
            val key = ByteArray(KEY_SIZE / 8)
            val iv = ByteArray(IV_SIZE / 8)
            CryptoAES.cryptoEvpKDF(password.toByteArray(), KEY_SIZE, IV_SIZE, saltBytes, key, iv)
            val keyS = SecretKeySpec(key, AES)
            val cipher = Cipher.getInstance(HASH_CIPHER)
            val ivSpec = IvParameterSpec(iv)
            cipher.init(Cipher.ENCRYPT_MODE, keyS, ivSpec)
            val cipherText = cipher.doFinal(plainText.toByteArray())
            val sBytes = APPEND.toByteArray()
            val b = ByteArray(sBytes.size + saltBytes.size + cipherText.size)
            System.arraycopy(sBytes, 0, b, 0, sBytes.size)
            System.arraycopy(saltBytes, 0, b, sBytes.size, saltBytes.size)
            System.arraycopy(cipherText, 0, b, sBytes.size + saltBytes.size, cipherText.size)
            val bEncode = Base64.encode(b, Base64.NO_WRAP)
            return String(bEncode)
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

    /**
     * Decrypt
     * @param password passphrase
     * @param cipherText encrypted string
     */
    fun decrypt(password: String, cipherText: String): String? {
        try {
            val ctBytes = Base64.decode(cipherText.toByteArray(), Base64.NO_WRAP)
            val saltBytes = Arrays.copyOfRange(ctBytes, 8, 16)
            val cipherTextBytes = Arrays.copyOfRange(ctBytes, 16, ctBytes.size)
            val key = ByteArray(KEY_SIZE / 8)
            val iv = ByteArray(IV_SIZE / 8)
            CryptoAES.cryptoEvpKDF(password.toByteArray(), KEY_SIZE, IV_SIZE, saltBytes, key, iv)
            val cipher = Cipher.getInstance(HASH_CIPHER)
            val keyS = SecretKeySpec(key, AES)
            cipher.init(Cipher.DECRYPT_MODE, keyS, IvParameterSpec(iv))
            val plainText = cipher.doFinal(cipherTextBytes)
            return String(plainText)
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return null
    }

}