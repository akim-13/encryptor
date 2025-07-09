package com.example.encryptor.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import com.example.encryptor.io.IOStreams
import java.io.EOFException
import java.io.InputStream
import java.nio.ByteBuffer
import java.security.KeyStore
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class CryptoManager {
    // Static properties, pertain to the class rather than its instances.
    companion object {
        private const val KEY_SIZE = 256
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


    private fun retrieveHardwareBackedKey(keyAlias: UUID): SecretKey? {
        return try {
            val keyAliasStr = keyAlias.toString()
            val entry = keyStore.getEntry(keyAliasStr, null) as? KeyStore.SecretKeyEntry
            entry?.secretKey
        } catch (e: Exception) {
            Log.i("retrievingHardwareKey", "Cannot retrieve key: \"$keyAlias\"")
            return null
        }
    }


    private fun generateSoftwareKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(ALGORITHM)
        keyGenerator.init(KEY_SIZE)
        return keyGenerator.generateKey()
    }


    private fun generateHardwareBackedKey(keyAlias: UUID): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(ALGORITHM, "AndroidKeyStore")

        keyGenerator.init(
            KeyGenParameterSpec.Builder(
                keyAlias.toString(),
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(BLOCK_MODE)
                .setEncryptionPaddings(PADDING)
                .setUserAuthenticationRequired(false)  // TODO: Set to true.
                .build()
        )

        return keyGenerator.generateKey()
    }


    private fun readFully(input: InputStream, buffer: ByteArray) {
        var bytesRead = 0
        while (bytesRead < buffer.size) {
            val read = input.read(buffer, bytesRead, buffer.size - bytesRead)
            if (read == -1) {
                throw EOFException("Unexpected end of stream while reading header data.")
            }
            bytesRead += read
        }
    }


    private fun extractBiometricMetadata(input: InputStream): BiometricMetadata? {
        return try {
            val keyAliasSize = readTwoBytesToInt(input)
            val encryptedKeyIvSize = readTwoBytesToInt(input)
            val encryptedKeySize = readTwoBytesToInt(input)

            val keyAliasBytes = ByteArray(keyAliasSize)
            val encryptedKeyIv = ByteArray(encryptedKeyIvSize)
            val encryptedKey = ByteArray(encryptedKeySize)

            readFully(input, keyAliasBytes)
            readFully(input, encryptedKeyIv)
            readFully(input, encryptedKey)

            val buffer = ByteBuffer.wrap(keyAliasBytes)
            val keyAlias = UUID(buffer.long, buffer.long)

            BiometricMetadata(
                keyAlias = keyAlias,
                encryptedKeyIv = encryptedKeyIv,
                encryptedKey = encryptedKey
            )
        } catch (e: Exception) {
            Log.i("MetadataExtraction", "Metadata file is either empty or corrupted.")
            return null
        }
    }


    // TODO: Wrap in try-catch.
    private fun extractDataFromHeader(input: InputStream): EncryptionHeader {
        val contentCipherIvSize = readTwoBytesToInt(input)
        val keyCipherIvSize = readTwoBytesToInt(input)
        val passwordSaltSize = readTwoBytesToInt(input)
        val encryptedStreamSecretKeySize = readTwoBytesToInt(input)

        val contentCipherIv = ByteArray(contentCipherIvSize)
        val keyCipherIv = ByteArray(keyCipherIvSize)
        val passwordSalt = ByteArray(passwordSaltSize)
        val encryptedStreamSecretKey = ByteArray(encryptedStreamSecretKeySize)

        readFully(input, contentCipherIv)
        readFully(input, keyCipherIv)
        readFully(input, passwordSalt)
        readFully(input, encryptedStreamSecretKey)

        return EncryptionHeader(
            contentCipherIv = contentCipherIv,
            keyCipherIv = keyCipherIv,
            passwordSalt = passwordSalt,
            encryptedStreamSecretKey = encryptedStreamSecretKey
        )
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


    private fun readTwoBytesToInt(input: InputStream): Int {
        val leftByte = input.read()
        val rightByte = input.read()

        if (leftByte == -1 || rightByte == -1) {
            throw EOFException("Unexpected end of stream while reading 2-byte integer")
        }

        return (leftByte shl 8) or rightByte
    }


    private fun convertIntToTwoBytes(num: Int): ByteArray {
        return byteArrayOf(
            ((num shr 8) and 0xFF).toByte(),   // Leftmost byte first.
            (num and 0xFF).toByte()            // Rightmost byte second.
        )
    }


    // TODO: Consider what happens when you have to encrypt a dir
    //       that's already been encrypted previously using biometrics.
    fun encryptStream(
        fileIOStreams: IOStreams,
        metadataIOStreams: IOStreams,
        password: String,
    ): Boolean {
        return try {
            val unencryptedInputStream = fileIOStreams.input
            val encryptedOutputStream = fileIOStreams.output
            val metadataInputStream = metadataIOStreams.input
            val metadataOutputStream = metadataIOStreams.output

            val masterKey = generateSoftwareKey()
            val contentCipher = initCipher("ENCRYPT", masterKey)

            if (password.isBlank()) {
                error("Empty password supplied.")
            }

            val passwordSalt = generateRandomSalt()
            val secretKeyForMasterKey = deriveKeyFromPassword(password, passwordSalt)
            val keyCipher = initCipher("ENCRYPT", secretKeyForMasterKey)

            val masterKeyBytes = masterKey.encoded
                ?: error("Idk, the key should've been set by now.")

            val encryptedStreamSecretKey = keyCipher.doFinal(masterKeyBytes)

            val biometricMetadata = extractBiometricMetadata(metadataInputStream)

            val keyAliasExists = biometricMetadata != null
            val biometricSecretKey: SecretKey
            val keyAlias: UUID

            if (keyAliasExists) {
                keyAlias = biometricMetadata!!.keyAlias
                biometricSecretKey = retrieveHardwareBackedKey(keyAlias)
                    ?: run {
                        keyStore.deleteEntry(keyAlias.toString())
                        generateHardwareBackedKey(keyAlias)
                    }
            } else {
                keyAlias = UUID.randomUUID()
                biometricSecretKey = generateHardwareBackedKey(keyAlias)
            }

            val biometricCipher = initCipher("ENCRYPT", biometricSecretKey)
            val biometricallyEncryptedMasterKey = biometricCipher.doFinal(masterKeyBytes)

            val keyAliasSize = 16  // UUIDs are 16 bytes long.
            val keyAliasBytes = ByteBuffer
                .allocate(keyAliasSize)
                .putLong(keyAlias.mostSignificantBits)
                .putLong(keyAlias.leastSignificantBits)
                .array()

            // Write to the metadata file.
            // Sizes (the number of bytes).
            metadataOutputStream.write(convertIntToTwoBytes(keyAliasSize))
            metadataOutputStream.write(convertIntToTwoBytes(biometricCipher.iv.size))
            metadataOutputStream.write(convertIntToTwoBytes(biometricallyEncryptedMasterKey.size))
            // Metadata file contents.
            metadataOutputStream.write(keyAliasBytes)
            metadataOutputStream.write(biometricCipher.iv)
            metadataOutputStream.write(biometricallyEncryptedMasterKey)

            // Create a header.
            // Sizes (the number of bytes).
            encryptedOutputStream.write(convertIntToTwoBytes(contentCipher.iv.size))
            encryptedOutputStream.write(convertIntToTwoBytes(keyCipher.iv.size))
            encryptedOutputStream.write(convertIntToTwoBytes(passwordSalt.size))
            encryptedOutputStream.write(convertIntToTwoBytes(encryptedStreamSecretKey.size))
            // Header contents.
            encryptedOutputStream.write(contentCipher.iv)
            encryptedOutputStream.write(keyCipher.iv)
            encryptedOutputStream.write(passwordSalt)
            encryptedOutputStream.write(encryptedStreamSecretKey)

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

            val isBiometricUnlock = metadataIOStreams != null
            val isPasswordUnlock = password != null

            if (!isBiometricUnlock && !isPasswordUnlock) {
                error("Neither password nor biometric data supplied.")
            }

            val encryptionHeader = extractDataFromHeader(encryptedInputStream)
            val contentCipherIv = encryptionHeader.contentCipherIv

            var masterKeyBytes: ByteArray? = null

            if (isBiometricUnlock) {
                try {
                    val metadataInputStream = metadataIOStreams!!.input
                    val biometricMetadata = extractBiometricMetadata(metadataInputStream)
                        ?: error("Invalid biometric metadata supplied.")

                    val biometricKey = retrieveHardwareBackedKey(biometricMetadata.keyAlias)
                        ?: error(
                            "Could not retrieve the key " + "with alias: \"${biometricMetadata.keyAlias}\"."
                        )

                    val keyCipher = initCipher("DECRYPT", biometricKey, biometricMetadata.encryptedKeyIv)

                    masterKeyBytes = keyCipher.doFinal(biometricMetadata.encryptedKey)
                } catch (e: Exception) {
                    Log.e("Decryption", "Biometric decryption failed", e)
                }
            }

            val isBiometricUnlockSuccessful = masterKeyBytes != null

            if (isPasswordUnlock && !isBiometricUnlockSuccessful) {
                val secretKeyForMasterKey =
                    deriveKeyFromPassword(password!!, encryptionHeader.passwordSalt)
                val keyCipher =
                    initCipher("DECRYPT", secretKeyForMasterKey, encryptionHeader.keyCipherIv)

                masterKeyBytes = keyCipher.doFinal(encryptionHeader.encryptedStreamSecretKey)
            }

            val masterKey = SecretKeySpec(masterKeyBytes, ALGORITHM)
            val streamCipher = initCipher("DECRYPT", masterKey, contentCipherIv)

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
            if (!isIntegrityCheck) {
                Log.e("DecryptionError", "Decryption failed.", e)
            } else {
                Log.e("IntegrityCheck", "Unexpected failure during integrity verification.", e)
            }

            false
        }
    }
}
