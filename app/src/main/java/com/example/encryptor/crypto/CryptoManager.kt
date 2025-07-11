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


    private fun readBinaryBlocksWithSizes(
        input: InputStream,
        fieldCount: Int,
        sizeFieldBytes: Int
    ): List<ByteArray> {
        val blocks = mutableListOf<ByteArray>()

        repeat(fieldCount) {
            val sizeBytes = ByteArray(sizeFieldBytes)
            readFully(input, sizeBytes)

            val size = ByteBuffer
                .wrap(ByteArray(Int.SIZE_BYTES).apply {
                    // Copy sizeBytes into the rightmost part of 4-byte int array.
                    System.arraycopy(
                        sizeBytes,
                        0,
                        this,
                        Int.SIZE_BYTES - sizeFieldBytes,
                        sizeFieldBytes
                    )
                })
                .int

            val block = ByteArray(size)
            readFully(input, block)

            blocks.add(block)
        }

        return blocks
    }


    fun extractDataFromHeader(input: InputStream): EncryptionHeader? {
        return try {
            // Example result:
            // headerFieldValues = [
            //     contentCipherIv bytes,
            //     masterKeyPasswordCipherIv bytes,
            //     passwordSalt bytes,
            //     passwordEncryptedMasterKey bytes
            // ]
            val headerFieldValues = readBinaryBlocksWithSizes(
                input,
                ENCRYPTION_HEADER_FIELDS.size,
                BYTES_FOR_SIZE_FIELD_IN_HEADER
            )

            // Example result:
            // fieldMap = {
            //   EncryptionHeader::contentCipherIv → blocks[0],
            //   EncryptionHeader::masterKeyPasswordCipherIv → blocks[1],
            //   EncryptionHeader::passwordSalt → blocks[2],
            //   EncryptionHeader::passwordEncryptedMasterKey → blocks[3]
            // }
            val fieldMap = ENCRYPTION_HEADER_FIELDS
                .mapIndexed { index, field -> field.property to headerFieldValues[index] }
                .toMap()

            EncryptionHeader(
                contentCipherIv = fieldMap.getValue(EncryptionHeader::contentCipherIv),
                masterKeyPasswordCipherIv = fieldMap.getValue(EncryptionHeader::masterKeyPasswordCipherIv),
                passwordSalt = fieldMap.getValue(EncryptionHeader::passwordSalt),
                passwordEncryptedMasterKey = fieldMap.getValue(EncryptionHeader::passwordEncryptedMasterKey)
            )
        } catch (e: Exception) {
            Log.e("HeaderExtraction", "Failed to extract data from the header.", e)
            null
        }
    }


    fun extractBiometricMetadata(input: InputStream): BiometricMetadata? {
        return try {
            // Example result:
            // metadataFieldValues = [
            //     keyAliasStringBytes bytes,
            //     masterKeyBiometricCipherIv bytes,
            //     biometricallyEncryptedMasterKey bytes
            // ]
            val metadataFieldValues = readBinaryBlocksWithSizes(
                input,
                BIOMETRIC_METADATA_FIELDS.size,
                BYTES_FOR_SIZE_FIELD_IN_METADATA
            )

            // Example result:
            // fieldMap = {
            //   BiometricMetadata::keyAliasStringBytes → blocks[0],
            //   BiometricMetadata::masterKeyBiometricCipherIv → blocks[1],
            //   BiometricMetadata::biometricallyEncryptedMasterKey → blocks[2]
            // }
            val fieldMap = BIOMETRIC_METADATA_FIELDS
                .mapIndexed { index, field -> field.property to metadataFieldValues[index] }
                .toMap()

            BiometricMetadata(
                keyAliasStringBytes = fieldMap.getValue(BiometricMetadata::keyAliasStringBytes),
                masterKeyBiometricCipherIv = fieldMap.getValue(BiometricMetadata::masterKeyBiometricCipherIv),
                biometricallyEncryptedMasterKey = fieldMap.getValue(BiometricMetadata::biometricallyEncryptedMasterKey)
            )
        } catch (e: Exception) {
            Log.i("MetadataExtraction", "Metadata file is either empty or corrupted.", e)
            null
        }
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


    fun generateNewMetadata(
        existingBiometricMetadata: BiometricMetadata?,
        masterKeyBytes: ByteArray
    ): BiometricMetadata {
        val keyAliasStringBytes = existingBiometricMetadata?.keyAliasStringBytes
            ?: UUID.randomUUID().toString().toByteArray(ENCRYPTOR_CHARSET)

        val biometricSecretKey = retrieveHardwareBackedKey(keyAliasStringBytes)
            ?: run {
                // Clean up just in case the key exists but is invalid (e.g. locked out).
                keyStore.deleteEntry(keyAliasStringBytes.toString(ENCRYPTOR_CHARSET))
                generateHardwareBackedKey(keyAliasStringBytes)
            }

        val biometricCipher = initCipher("ENCRYPT", biometricSecretKey)
        val biometricallyEncryptedMasterKey = biometricCipher.doFinal(masterKeyBytes)

        return BiometricMetadata(
            keyAliasStringBytes = keyAliasStringBytes,
            masterKeyBiometricCipherIv = biometricCipher.iv,
            biometricallyEncryptedMasterKey = biometricallyEncryptedMasterKey,
        )
    }


    fun handleMetadata(metadataIOStreams: IOStreams, masterKeyBytes: ByteArray): Boolean {
        return try {
            val existingBiometricMetadata = extractBiometricMetadata(metadataIOStreams.input)
            val newBiometricMetadata = generateNewMetadata(existingBiometricMetadata, masterKeyBytes)

            writeBiometricMetadata(newBiometricMetadata, metadataIOStreams.output)

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
            val masterKey = generateSoftwareKey()
            val masterKeyBytes = masterKey.encoded

            val biometricEncryptionSuccessful = handleMetadata(metadataIOStreams, masterKeyBytes)
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
