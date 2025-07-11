package com.example.encryptor.crypto.models

import com.example.encryptor.util.BYTES_FOR_SIZE_FIELD_IN_HEADER
import kotlin.reflect.KProperty1

data class BiometricMetadata (
    val keyAliasStringBytes: ByteArray,
    val masterKeyBiometricCipherIv: ByteArray,
    val biometricallyEncryptedMasterKey: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as BiometricMetadata

        if (!keyAliasStringBytes.contentEquals(other.keyAliasStringBytes)) return false
        if (!masterKeyBiometricCipherIv.contentEquals(other.masterKeyBiometricCipherIv)) return false
        if (!biometricallyEncryptedMasterKey.contentEquals(other.biometricallyEncryptedMasterKey)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = keyAliasStringBytes.hashCode()
        result = 31 * result + masterKeyBiometricCipherIv.contentHashCode()
        result = 31 * result + biometricallyEncryptedMasterKey.contentHashCode()
        return result
    }
}

data class MetadataField(
    val property: KProperty1<BiometricMetadata, ByteArray>,
    val bytesForSizeField: Int = BYTES_FOR_SIZE_FIELD_IN_HEADER
)
