package com.example.encryptor.crypto.models

import com.example.encryptor.util.BYTES_FOR_SIZE_FIELD_IN_HEADER
import kotlin.reflect.KProperty1

data class EncryptionHeader(
    val contentCipherIv: ByteArray,
    val masterKeyPasswordCipherIv: ByteArray,
    val passwordSalt: ByteArray,
    val passwordEncryptedMasterKey: ByteArray
) { // The rest is autogenerated by the IDE to allow valid comparisons.
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as EncryptionHeader

        if (!contentCipherIv.contentEquals(other.contentCipherIv)) return false
        if (!masterKeyPasswordCipherIv.contentEquals(other.masterKeyPasswordCipherIv)) return false
        if (!passwordSalt.contentEquals(other.passwordSalt)) return false
        if (!passwordEncryptedMasterKey.contentEquals(other.passwordEncryptedMasterKey)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = contentCipherIv.contentHashCode()
        result = 31 * result + masterKeyPasswordCipherIv.contentHashCode()
        result = 31 * result + passwordSalt.contentHashCode()
        result = 31 * result + passwordEncryptedMasterKey.contentHashCode()
        return result
    }
}

data class HeaderField(
    // I.e. `property` is a reference to a property of EncryptionHeader whose value is a ByteArray.
    val property: KProperty1<EncryptionHeader, ByteArray>,
    val bytesForSizeField: Int = BYTES_FOR_SIZE_FIELD_IN_HEADER
)
