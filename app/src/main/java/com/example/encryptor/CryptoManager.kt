package com.example.encryptor

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class CryptoManager {
    // Static properties, pertain to the class rather than its instances.
    companion object {
        private const val ALGORITHM = KeyProperties.KEY_ALGORITHM_AES
        private const val BLOCK_MODE = KeyProperties.BLOCK_MODE_GCM
        private const val PADDING = KeyProperties.ENCRYPTION_PADDING_NONE
        private const val TRANSFORMATION = "$ALGORITHM/$BLOCK_MODE/$PADDING"
    }

    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }

    private fun initCipher(mode: String, secretKey: SecretKey, iv: ByteArray? = null): Cipher {
        val cipherInstance = Cipher.getInstance(TRANSFORMATION)

        return if (mode == "ENCRYPT") {
            cipherInstance.apply{ init(Cipher.ENCRYPT_MODE, secretKey) }
        } else if (mode == "DECRYPT" && iv != null) {
            cipherInstance.apply{ init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv)) }
        } else {
            throw Exception("C'mon, just choose the right mode and iv if necessary")
        }
    }

    private fun retrieveOrCreateKey(keyAlias: String): SecretKey {
        try {
            val entry = keyStore.getEntry(keyAlias, null) as? KeyStore.SecretKeyEntry

            return if (entry != null) {
                entry.secretKey
            } else {
                createKey(keyAlias)
            }

        } catch (e: KeyStoreException) {
            // If the key is invalid (e.g., locked due to authentication), delete it.
            keyStore.deleteEntry(keyAlias)
            return createKey(keyAlias)
        } catch (e: Exception) {
            throw ErrorRetrievingKeyException("Error retrieving key: \"$keyAlias\"", e)
        }
    }

    private fun createKey(keyAlias: String): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(ALGORITHM, "AndroidKeyStore")

        keyGenerator.init(
            KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(BLOCK_MODE)
                .setEncryptionPaddings(PADDING)
                .setUserAuthenticationRequired(false) // TODO: Change to true.
                .build()
        )

        return keyGenerator.generateKey()
    }

    fun extractIvFromInputStream(inputStream: InputStream): ByteArray {
        val ivSize = inputStream.read()
        val iv = ByteArray(ivSize)
        var totalRead = 0

        while (totalRead < ivSize) {
            val bytesRead = inputStream.read(iv, totalRead, ivSize - totalRead)
            if (bytesRead == -1) throw IOException("Unexpected EOF while reading IV")
            totalRead += bytesRead
        }

        return iv
    }

    fun deriveKeyFromPassword(
        password: String,
        salt: ByteArray,
        iterations: Int = 100_000,
        keyLength: Int = 256
    ): SecretKeySpec {
        val keySpec = PBEKeySpec(password.toCharArray(), salt, iterations, keyLength)
        val secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val secretKey = secretKeyFactory.generateSecret(keySpec)
        return SecretKeySpec(secretKey.encoded, "AES")
    }

    fun generateRandomSalt(size: Int = 16): ByteArray {
        val salt = ByteArray(size)
        SecureRandom().nextBytes(salt)
        return salt
    }

    fun encryptStream(
        unencryptedInputStream: InputStream,
        password: String,
        keyAlias: String,
        unencryptedOutputStream: OutputStream
    ): Boolean {
        return try {
            val streamSecretKey = retrieveOrCreateKey(keyAlias)
            val contentCipher = initCipher("ENCRYPT", streamSecretKey)

            val saltForSecretKey = generateRandomSalt()
            val secretKeyForSecretKey = deriveKeyFromPassword(password, saltForSecretKey)
            val keyCipher = initCipher("ENCRYPT", secretKeyForSecretKey)

            // Create a header.
            // Sizes.
            // TODO: Use multiple bytes for everything.
            unencryptedOutputStream.write(contentCipher.iv.size)
            unencryptedOutputStream.write(keyCipher.iv.size)
            unencryptedOutputStream.write(saltForSecretKey.size)
            // Contents.
            unencryptedOutputStream.write(contentCipher.iv)
            unencryptedOutputStream.write(keyCipher.iv)
            unencryptedOutputStream.write(saltForSecretKey)

            // TODO: Generate and append a public key to the header.

            CipherOutputStream(unencryptedOutputStream, contentCipher).use { encryptedOutputStream ->
                // WARNING: Overflows if iv.size > 255. Modern iv size is up
                // to 24 bytes, so might only become an issue in the future.
                unencryptedInputStream.copyTo(encryptedOutputStream)
            }
            true
        } catch (e: Exception) {
            Log.e("EncryptionError", "Encryption failed (key: \"${keyAlias}\")", e)
            false
        }
    }

    fun decryptStream(
        encryptedInputStream: InputStream,
        iv: ByteArray,
        keyAlias: String,
        decryptedOutputStream: OutputStream
    ): Boolean {
        return try {
            val cipher = initCipher("DECRYPT", retrieveOrCreateKey(keyAlias), iv)

            CipherInputStream(encryptedInputStream, cipher).use { decryptedInputStream ->
                decryptedInputStream.copyTo(decryptedOutputStream)
            }
            true
        } catch(e: Exception) {
            Log.e("DecryptionError", "Decryption failed (key: \"${keyAlias}\")", e)
            false
        }
    }

    fun isIntegrityCheckPassed(encryptedFile: File, keyAlias: String): Boolean {
        try {
            FileInputStream(encryptedFile).use { encryptedInputStream ->
                val iv = extractIvFromInputStream(encryptedInputStream)
                val cipher = initCipher("DECRYPT", retrieveOrCreateKey(keyAlias), iv)

                CipherInputStream(encryptedInputStream, cipher).use { decryptedInputStream ->
                    // Reduces the number of IO calls, making it faster.
                    val buffer = ByteArray(4096)
                    while (decryptedInputStream.read(buffer) != -1) {
                        // Just read through the file to force decryption/authentication
                    }
                }
            }
            return true
        } catch (e: Exception) {
            Log.e("IntegrityCheck", "ERROR: Unexpected failure during integrity verification")
            Log.e("IntegrityCheck", e.toString())
        }

        return false
    }
}

class ErrorRetrievingKeyException(message: String, cause: Throwable? = null) : Exception(message, cause)