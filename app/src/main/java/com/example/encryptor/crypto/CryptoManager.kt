package com.example.encryptor.crypto

import android.util.Log
import com.example.encryptor.crypto.CryptoUtils.ALGORITHM
import com.example.encryptor.crypto.CryptoUtils.decryptMasterKeyBytesUsingPassword
import com.example.encryptor.crypto.CryptoUtils.encryptBytesUsingPassword
import com.example.encryptor.crypto.CryptoUtils.generateSoftwareKey
import com.example.encryptor.crypto.CryptoUtils.initCipher
import com.example.encryptor.crypto.serialisers.HeaderSerialiser.readEncryptionHeader
import com.example.encryptor.crypto.serialisers.HeaderSerialiser.writeEncryptionHeader
import com.example.encryptor.io.IOStreams
import javax.crypto.CipherInputStream
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

class CryptoManager {
    private val biometricsManager = BiometricsManager()

    // TODO: Consider what happens when you have to encrypt a dir
    //       that's already been encrypted previously using biometrics.
    fun encryptStream(
        fileIOStreams: IOStreams,
        metadataIOStreams: IOStreams,
        password: String,  // TODO: Make `String?`. See TODO above.
    ): Boolean {
        return try {
            val masterKey = generateSoftwareKey()
            val masterKeyBytes = masterKey.encoded

            val biometricEncryptionSuccessful = biometricsManager.handleMetadata(metadataIOStreams, masterKeyBytes)
            if (!biometricEncryptionSuccessful) {
                Log.e("Encryption", "Failed to encrypt the master key biometrically.")
            }

            val passwordEncryptionResult = encryptBytesUsingPassword(
                masterKeyBytes,
                password,
            ) ?: error("Failed to encrypt the master key using password.")

            val contentCipher = initCipher("ENCRYPT", masterKey)

            val encryptionHeader = EncryptionHeader(
                contentCipherIv = contentCipher.iv,
                masterKeyPasswordCipherIv = passwordEncryptionResult.iv,
                passwordSalt = passwordEncryptionResult.passwordSalt,
                passwordEncryptedMasterKey = passwordEncryptionResult.encryptedBytes
            )

            writeEncryptionHeader(encryptionHeader, fileIOStreams.output)

            val unencryptedInputStream = fileIOStreams.input
            val encryptedOutputStream = fileIOStreams.output

            // Encrypt main content.
            CipherInputStream(unencryptedInputStream, contentCipher).use { encryptedInputStream ->
                encryptedInputStream.copyTo(encryptedOutputStream)
                encryptedOutputStream.flush()
            }

            true
        } catch (e: Exception) {
            Log.e("EncryptionError", "Encryption failed.", e)
            false
        }
    }


    fun decryptStream(
        fileIOStreams: IOStreams,
        metadataIOStreams: IOStreams? = null,
        password: String? = null,
        isIntegrityCheck: Boolean = false,
    ): Boolean {
        return try {
            val encryptedInputStream = fileIOStreams.input
            val decryptedOutputStream = fileIOStreams.output

            val encryptionHeader = readEncryptionHeader(encryptedInputStream)
                ?: error("Failed to extract data from the header. The file may be corrupted.")

            val masterKey = decryptMasterKey(metadataIOStreams, password, encryptionHeader)
            val streamCipher = initCipher("DECRYPT", masterKey, encryptionHeader.contentCipherIv)

            CipherInputStream(encryptedInputStream, streamCipher).use { decryptedInputStream ->
                if (!isIntegrityCheck) {
                    decryptedInputStream.copyTo(decryptedOutputStream)
                } else {
                    // Reduces the number of IO calls, making it faster.
                    val buffer = ByteArray(4096)
                    while (decryptedInputStream.read(buffer) != -1) {
                        // Just read through the file to force decryption/authentication.
                    }
                }
            }

            true

        } catch(e: Exception) {
            if (isIntegrityCheck) {
                Log.e("IntegrityCheck", "Unexpected failure during integrity verification.", e)
            } else {
                Log.e("DecryptionError", "Decryption failed.", e)
            }

            false

        }
    }


    private fun decryptMasterKey(
        metadataIOStreams: IOStreams?,
        password: String?,
        encryptionHeader: EncryptionHeader
    ): SecretKey {
        val isBiometricUnlock = metadataIOStreams != null
        val isPasswordUnlock = password != null

        if (!isBiometricUnlock && !isPasswordUnlock) {
            error("Neither password nor biometric data supplied.")
        }

        var masterKeyBytes: ByteArray? = null

        if (isBiometricUnlock) {
            masterKeyBytes = biometricsManager.decryptMasterKeyBytesUsingBiometrics(metadataIOStreams!!.input)
        }

        val isBiometricUnlockSuccessful = masterKeyBytes != null

        if (isPasswordUnlock && !isBiometricUnlockSuccessful) {
            masterKeyBytes = decryptMasterKeyBytesUsingPassword(encryptionHeader, password!!)
        }

        return SecretKeySpec(masterKeyBytes, ALGORITHM)
    }
}
