package com.example.encryptor.crypto

import android.util.Log
import com.example.encryptor.crypto.serialisers.BiometricMetadataSerialiser.readBiometricMetadata
import com.example.encryptor.crypto.serialisers.BiometricMetadataSerialiser.writeBiometricMetadata
import com.example.encryptor.crypto.CryptoUtils.initCipher
import com.example.encryptor.io.IOStreams
import com.example.encryptor.util.ENCRYPTOR_CHARSET
import java.io.InputStream
import java.util.UUID

class BiometricsManager {
    private val keystoreManager = KeystoreManager()


    fun decryptMasterKeyBytesUsingBiometrics(metadataInputStream: InputStream): ByteArray? {
        return try {
            val biometricMetadata = readBiometricMetadata(metadataInputStream)
                ?: error("Invalid biometric metadata supplied.")

            val biometricKey = keystoreManager.retrieveHardwareBackedKey(biometricMetadata.keyAliasStringBytes)
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


    fun handleMetadata(metadataIOStreams: IOStreams, masterKeyBytes: ByteArray): Boolean {
        return try {
            val existingBiometricMetadata = readBiometricMetadata(metadataIOStreams.input)
            val newBiometricMetadata = generateNewMetadata(existingBiometricMetadata, masterKeyBytes)

            writeBiometricMetadata(newBiometricMetadata, metadataIOStreams.output)

            true
        } catch (e: Exception) {
            Log.e("HandlingMetadata", "Something went wrong while handling metadata.", e)
            false
        }
    }


    private fun generateNewMetadata(
        existingBiometricMetadata: BiometricMetadata?,
        masterKeyBytes: ByteArray
    ): BiometricMetadata {
        val keyAliasStringBytes = existingBiometricMetadata?.keyAliasStringBytes
            ?: UUID.randomUUID().toString().toByteArray(ENCRYPTOR_CHARSET)



        val biometricSecretKey = keystoreManager.retrieveHardwareBackedKey(keyAliasStringBytes)
            ?: run {
                // Clean up just in case the key exists but is invalid (e.g. locked out).
                keystoreManager.deleteKey(keyAliasStringBytes.toString(ENCRYPTOR_CHARSET))
                keystoreManager.generateHardwareBackedKey(keyAliasStringBytes)
            }

        val biometricCipher = initCipher("ENCRYPT", biometricSecretKey)
        val biometricallyEncryptedMasterKey = biometricCipher.doFinal(masterKeyBytes)

        return BiometricMetadata(
            keyAliasStringBytes = keyAliasStringBytes,
            masterKeyBiometricCipherIv = biometricCipher.iv,
            biometricallyEncryptedMasterKey = biometricallyEncryptedMasterKey,
        )
    }
}
