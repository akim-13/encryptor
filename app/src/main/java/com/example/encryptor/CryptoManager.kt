package com.example.encryptor

import android.content.Context
import android.net.Uri
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
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

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

    private fun initCipher(mode: String, keyAlias: String, iv: ByteArray? = null): Cipher {
        val cipherInstance = Cipher.getInstance(TRANSFORMATION)

        return if (mode == "ENCRYPT") {
            cipherInstance.apply{ init(Cipher.ENCRYPT_MODE, retrieveOrCreateKey(keyAlias)) }
        } else if (mode == "DECRYPT" && iv != null) {
            cipherInstance.apply{ init(Cipher.DECRYPT_MODE, retrieveOrCreateKey(keyAlias), GCMParameterSpec(128, iv)) }
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

    // TODO: Refactor in the same way as decryptFile().
    fun encryptFile(uri: Uri, context: Context, keyAlias: String, outputFile: File): File {
        val contentResolver = context.contentResolver
        val fileInputStream = contentResolver.openInputStream(uri) ?: throw IOException("Failed to open input stream")
        val cipher = initCipher("ENCRYPT", keyAlias)

        outputFile.outputStream().use { unencryptedOutputStream ->
            unencryptedOutputStream.write(cipher.iv.size)
            unencryptedOutputStream.write(cipher.iv)
            CipherOutputStream(unencryptedOutputStream, cipher).use { encryptedOutputStream ->
                fileInputStream.use { input ->
                    // WARNING: Overflows if iv.size > 255. Modern iv size is up
                    // to 24 bytes, so might only become an issue in the future.
                    input.copyTo(encryptedOutputStream)
                }
            }
        }
        return outputFile
    }

    private fun extractIvFromInputStream(inputStream: InputStream): ByteArray {
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

    fun decryptFile(
        encryptedInputStream: InputStream,
        keyAlias: String,
        decryptedOutputStream: OutputStream
    ): Boolean {
        return try {
            val iv = extractIvFromInputStream(encryptedInputStream)
            val cipher = initCipher("DECRYPT", keyAlias, iv)

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
                val cipher = initCipher("DECRYPT", keyAlias, iv)

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