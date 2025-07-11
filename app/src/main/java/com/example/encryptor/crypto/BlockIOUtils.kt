package com.example.encryptor.crypto

import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer

object BlockIOUtils {
    fun writeBinaryBlocksWithSizes(
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


    fun readBinaryBlocksWithSizes(
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


    private fun convertIntToBytes(num: Int, byteCount: Int): ByteArray {
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
}
