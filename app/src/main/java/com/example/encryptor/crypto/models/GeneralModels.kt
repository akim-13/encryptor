package com.example.encryptor.crypto.models

data class PasswordEncryptionResult (
    val encryptedBytes: ByteArray,
    val iv: ByteArray,
    val passwordSalt: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PasswordEncryptionResult

        if (!encryptedBytes.contentEquals(other.encryptedBytes)) return false
        if (!iv.contentEquals(other.iv)) return false
        if (!passwordSalt.contentEquals(other.passwordSalt)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = encryptedBytes.contentHashCode()
        result = 31 * result + iv.contentHashCode()
        result = 31 * result + passwordSalt.contentHashCode()
        return result
    }
}
