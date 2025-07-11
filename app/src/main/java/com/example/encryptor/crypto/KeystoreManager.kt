package com.example.encryptor.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import com.example.encryptor.crypto.CryptoUtils.ALGORITHM
import com.example.encryptor.crypto.CryptoUtils.BLOCK_MODE
import com.example.encryptor.crypto.CryptoUtils.PADDING
import com.example.encryptor.util.ENCRYPTOR_CHARSET
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class KeystoreManager {
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }

    fun retrieveHardwareBackedKey(keyAliasStringBytes: ByteArray): SecretKey? {
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


    fun generateHardwareBackedKey(keyAlias: ByteArray): SecretKey {
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


    fun deleteKey(keyAliasStr: String) {
        keyStore.deleteEntry(keyAliasStr)
    }
}
