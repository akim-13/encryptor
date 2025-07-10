package com.example.encryptor.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import com.example.encryptor.io.IOStreams
import com.example.encryptor.util.BYTES_FOR_SIZE_FIELD_IN_HEADER
import com.example.encryptor.util.ENCRYPTION_HEADER_FIELDS
import com.example.encryptor.util.BIOMETRIC_METADATA_FIELDS
import com.example.encryptor.util.BYTES_FOR_SIZE_FIELD_IN_METADATA
import com.example.encryptor.util.ENCRYPTOR_CHARSET
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
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


    private fun retrieveHardwareBackedKey(keyAliasStringBytes: ByteArray): SecretKey? {
        return try {
            val keyAliasStr = keyAliasStringBytes.toString(ENCRYPTOR_CHARSET)
            val entry = keyStore.getEntry(keyAliasStr, null) as? KeyStore.SecretKeyEntry
            entry?.secretKey
        } catch (e: Exception) {
            Log.i("retrievingHardwareKey", "Cannot retrieve key: " +
                    "\"${keyAliasStringBytes.toString(ENCRYPTOR_CHARSET)}\"")
            null
        }
    }


    private fun generateSoftwareKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(ALGORITHM)
        keyGenerator.init(KEY_SIZE)
        return keyGenerator.generateKey()
    }


    private fun generateHardwareBackedKey(keyAlias: ByteArray): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(ALGORITHM, "AndroidKeyStore")

        keyGenerator.init(
            KeyGenParameterSpec.Builder(
                keyAlias.toString(ENCRYPTOR_CHARSET),
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

            BiometricMetadata(
                keyAliasStringBytes = keyAliasBytes,
                masterKeyBiometricCipherIv = encryptedKeyIv,
                biometricallyEncryptedMasterKey = encryptedKey
            )
        } catch (e: Exception) {
            Log.i("MetadataExtraction", "Metadata file is either empty or corrupted.")
            null
        }
    }


    private fun extractDataFromHeader(input: InputStream): EncryptionHeader? {
        return try {
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

            EncryptionHeader(
                contentCipherIv = contentCipherIv,
                masterKeyPasswordCipherIv = keyCipherIv,
                passwordSalt = passwordSalt,
                passwordEncryptedMasterKey = encryptedStreamSecretKey
            )
        } catch (e: Exception) {
            Log.e("HeaderExtraction", "Failed to extract data from the header.")
            null
        }
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


    fun convertIntToBytes(num: Int, byteCount: Int): ByteArray {
        require(byteCount in 1..4) {
            "byteCount must be between 1 and 4 for Int values (was $byteCount)."
        }
        require(num >= 0) {
            "num must be non-negative, but was $num."
        }

        // Calculates \[ numOfBits^2 - 1 \].
        val maxValue = (1 shl (byteCount * 8)) - 1

        require(num <= maxValue) {
            "num $num cannot fit in $byteCount bytes (max is $maxValue)."
        }

        // Allocate 4 bytes for the Int value.
        val buffer = ByteBuffer.allocate(Int.SIZE_BYTES)

        // Write the number into the buffer in big-endian order.
        buffer.putInt(num)
        val fullArray = buffer.array()

        // Extract only the rightmost `byteCount` bytes.
        return fullArray.copyOfRange(
            Int.SIZE_BYTES - byteCount,
            Int.SIZE_BYTES
        )
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


    fun writeEncryptionHeader(encryptionHeader: EncryptionHeader, outputStream: OutputStream): Boolean {
        return try {
            val blocks = ENCRYPTION_HEADER_FIELDS.map { it.property(encryptionHeader) }
            writeBinaryBlocksWithSizes(blocks, outputStream, BYTES_FOR_SIZE_FIELD_IN_HEADER)
            true
        } catch (e: Exception) {
            Log.e("WritingHeader", "Could not write the header.", e)
            false
        }
    }


    fun writeBiometricMetadata(biometricMetadata: BiometricMetadata, outputStream: OutputStream): Boolean {
        return try {
            val blocks = BIOMETRIC_METADATA_FIELDS.map { it.property(biometricMetadata) }
            writeBinaryBlocksWithSizes(blocks, outputStream, BYTES_FOR_SIZE_FIELD_IN_METADATA)
            true
        } catch (e: Exception) {
            Log.e("WritingHeader", "Could not write the header.", e)
            false
        }
    }

    private fun writeBinaryBlocksWithSizes(
        blocks: List<ByteArray>,
        outputStream: OutputStream,
        sizeFieldBytes: Int
    ) {
        // Calculates [ numOfBits^2 - 1 ].
        val maxSize = (1 shl (sizeFieldBytes * 8)) - 1

        for (block in blocks) {
            require(block.size <= maxSize) {
                "Block size ${block.size} exceeds max encodable size $maxSize bytes."
            }
            val sizeBytes = convertIntToBytes(block.size, sizeFieldBytes)

            outputStream.write(sizeBytes)
            outputStream.write(block)
        }
    }


    fun validateAndGenerateNewMetadataIfNeeded(existingBiometricMetadata: BiometricMetadata?, masterKeyBytes: ByteArray): BiometricMetadata? {
        if (existingBiometricMetadata != null) {
            val keyAliasStringBytes = existingBiometricMetadata.keyAliasStringBytes
            val biometricSecretKey = retrieveHardwareBackedKey(keyAliasStringBytes)

            if (biometricSecretKey != null) {
                return null
            }

            // The key alias exists, but something is wrong with the stored key, so clean up.
            keyStore.deleteEntry(keyAliasStringBytes.toString(ENCRYPTOR_CHARSET))
        }

        val newKeyAliasStringBytes = UUID.randomUUID().toString().toByteArray(ENCRYPTOR_CHARSET)
        val newBiometricSecretKey = generateHardwareBackedKey(newKeyAliasStringBytes)

        val biometricCipher = initCipher("ENCRYPT", newBiometricSecretKey)
        val biometricallyEncryptedMasterKey = biometricCipher.doFinal(masterKeyBytes)

        return BiometricMetadata(
            keyAliasStringBytes = newKeyAliasStringBytes,
            masterKeyBiometricCipherIv = biometricCipher.iv,
            biometricallyEncryptedMasterKey = biometricallyEncryptedMasterKey,
        )
    }


    fun handleMetadata(metadataIOStreams: IOStreams, masterKeyBytes: ByteArray): Boolean {
        return try {
            val existingBiometricMetadata = extractBiometricMetadata(metadataIOStreams.input)
            val newBiometricMetadata =
                validateAndGenerateNewMetadataIfNeeded(existingBiometricMetadata, masterKeyBytes)

            if (newBiometricMetadata != null) {
                writeBiometricMetadata(newBiometricMetadata, metadataIOStreams.output)
            }

            true
        } catch (e: Exception) {
            Log.e("HandlingMetadata", "Something went wrong while handling metadata.", e)
            false
        }
    }


    // TODO: Consider what happens when you have to encrypt a dir
    //       that's already been encrypted previously using biometrics.
    fun encryptStream(
        fileIOStreams: IOStreams,
        metadataIOStreams: IOStreams,
        password: String,  // TODO: Make `String?`. See TODO above.
    ): Boolean {
        return try {
            val unencryptedInputStream = fileIOStreams.input
            val encryptedOutputStream = fileIOStreams.output

            val masterKey = generateSoftwareKey()
            val masterKeyBytes = masterKey.encoded

            if (!handleMetadata(metadataIOStreams, masterKeyBytes)) {
                Log.e("Encryption", "Failed to deal with biometrics.")
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

            writeEncryptionHeader(encryptionHeader, encryptedOutputStream)

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


    fun decryptMasterKeyBytesUsingBiometrics(metadataInputStream: InputStream): ByteArray? {
        return try {
            val biometricMetadata = extractBiometricMetadata(metadataInputStream)
                ?: error("Invalid biometric metadata supplied.")

            val biometricKey = retrieveHardwareBackedKey(biometricMetadata.keyAliasStringBytes)
                ?: error(
                    "Could not retrieve the key " + "with alias: \"${biometricMetadata.keyAliasStringBytes}\"."
                )

            val keyCipher = initCipher("DECRYPT", biometricKey, biometricMetadata.masterKeyBiometricCipherIv)

            keyCipher.doFinal(biometricMetadata.biometricallyEncryptedMasterKey)
        } catch (e: Exception) {
            Log.e("Decryption", "Biometric decryption failed.", e)
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

    fun decryptMasterKey(metadataIOStreams: IOStreams?, password: String?, encryptionHeader: EncryptionHeader): SecretKey {
        val isBiometricUnlock = metadataIOStreams != null
        val isPasswordUnlock = password != null

        if (!isBiometricUnlock && !isPasswordUnlock) {
            error("Neither password nor biometric data supplied.")
        }

        var masterKeyBytes: ByteArray? = null

        if (isBiometricUnlock) {
            masterKeyBytes = decryptMasterKeyBytesUsingBiometrics(metadataIOStreams!!.input)
        }

        val isBiometricUnlockSuccessful = masterKeyBytes != null

        if (isPasswordUnlock && !isBiometricUnlockSuccessful) {
            masterKeyBytes = decryptMasterKeyBytesUsingPassword(encryptionHeader, password!!)
        }

        return SecretKeySpec(masterKeyBytes, ALGORITHM)
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

            val encryptionHeader = extractDataFromHeader(encryptedInputStream)
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
}
