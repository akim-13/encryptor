package com.example.encryptor.crypto

import android.security.keystore.KeyProperties
import android.util.Log
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

object CryptoUtils {
    const val KEY_SIZE = 256
    const val ALGORITHM = KeyProperties.KEY_ALGORITHM_AES
    const val BLOCK_MODE = KeyProperties.BLOCK_MODE_GCM
    const val PADDING = KeyProperties.ENCRYPTION_PADDING_NONE
    const val TRANSFORMATION = "$ALGORITHM/$BLOCK_MODE/$PADDING"

    fun initCipher(mode: String, secretKey: SecretKey, iv: ByteArray? = null): Cipher {
        val cipherInstance = Cipher.getInstance(TRANSFORMATION)

        return if (mode == "ENCRYPT") {
            cipherInstance.apply{ init(Cipher.ENCRYPT_MODE, secretKey) }
        } else if (mode == "DECRYPT" && iv != null) {
            cipherInstance.apply{ init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv)) }
        } else {
            throw Exception("C'mon, just choose the right mode and iv if necessary")
        }
    }


    fun encryptBytesUsingPassword(bytes: ByteArray, password: String): PasswordEncryptionResult? {
        return try {
            if (password.isBlank()) {
                error("Empty password supplied.")
            }

            val passwordSalt = generateRandomSalt()
            val passwordDerivedSecretKey = deriveKeyFromPassword(password, passwordSalt)
            val keyCipher = initCipher("ENCRYPT", passwordDerivedSecretKey)

            PasswordEncryptionResult(
                encryptedBytes = keyCipher.doFinal(bytes),
                iv = keyCipher.iv,
                passwordSalt = passwordSalt,
            )
        } catch (e: Exception) {
            Log.e("PasswordEncryption", "Failed to encrypt the given bytes with the password.")
            null
        }
    }


    fun decryptMasterKeyBytesUsingPassword(encryptionHeader: EncryptionHeader, password: String): ByteArray? {
        return try {
            val secretKeyForMasterKey =
                deriveKeyFromPassword(password, encryptionHeader.passwordSalt)

            val keyCipher =
                initCipher("DECRYPT", secretKeyForMasterKey, encryptionHeader.masterKeyPasswordCipherIv)

            keyCipher.doFinal(encryptionHeader.passwordEncryptedMasterKey)
        } catch (e: Exception) {
            Log.e("Decryption", "Password decryption failed.", e)
            null
        }
    }


    fun generateSoftwareKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(ALGORITHM)
        keyGenerator.init(KEY_SIZE)
        return keyGenerator.generateKey()
    }


    private fun deriveKeyFromPassword(
        password: String,
        salt: ByteArray,
        iterations: Int = 100_000,
        keySize: Int = KEY_SIZE
    ): SecretKeySpec {
        val keySpec = PBEKeySpec(password.toCharArray(), salt, iterations, keySize)
        val secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val secretKey = secretKeyFactory.generateSecret(keySpec)
        return SecretKeySpec(secretKey.encoded, ALGORITHM)
    }


    private fun generateRandomSalt(size: Int = 16): ByteArray {
        val salt = ByteArray(size)
        SecureRandom().nextBytes(salt)
        return salt
    }
}
