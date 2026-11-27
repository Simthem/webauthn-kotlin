package com.pqvault.desktop

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.InputStream
import java.io.OutputStream

/** One request on stdin, one response on stdout, between libpqvault-sk.so and this helper. */
object HelperProtocol {
    private val MAGIC = byteArrayOf('P'.code.toByte(), 'Q'.code.toByte(), 'S'.code.toByte(), 'K'.code.toByte())
    private const val VERSION = 1
    private const val MAX_FIELD = 1 shl 20

    const val OP_ENROLL = 1
    const val OP_SIGN = 2
    const val OP_LIST = 3

    /** OpenSSH's sk-api algorithm numbers. */
    const val ALG_ECDSA = 0
    const val ALG_ED25519 = 1

    /** OpenSSH's sk-api error codes. */
    const val ERR_GENERAL = -1
    const val ERR_UNSUPPORTED = -2
    const val ERR_DEVICE_NOT_FOUND = -4
    const val ERR_CREDENTIAL_EXISTS = -5

    class Request(
        val operation: Int,
        val algorithm: Int,
        val flags: Int,
        val application: String,
        /** The enrolment challenge, or the data to sign. */
        val message: ByteArray,
        /** The user ID for an enrolment, the key handle for a signature. */
        val handle: ByteArray,
    )

    sealed interface Response {
        data class Failed(val error: Int) : Response

        class Enrolled(
            val flags: Int,
            val publicKey: ByteArray,
            val keyHandle: ByteArray,
            val signature: ByteArray,
            val authenticatorData: ByteArray,
        ) : Response

        class Signed(val flags: Int, val counter: Long, val r: ByteArray, val s: ByteArray) : Response

        class Listed(val keys: List<Key>) : Response {
            class Key(
                val algorithm: Int,
                val application: String,
                val flags: Int,
                val publicKey: ByteArray,
                val keyHandle: ByteArray,
                val userId: ByteArray,
            )
        }
    }

    fun readRequest(input: InputStream): Request {
        val data = DataInputStream(input)
        val magic = ByteArray(4).also(data::readFully)
        require(magic.contentEquals(MAGIC) && data.readUnsignedByte() == VERSION) { "unknown request format" }
        val operation = data.readUnsignedByte()
        require(operation in OP_ENROLL..OP_LIST) { "unknown operation" }
        val algorithm = data.readInt()
        require(algorithm == ALG_ECDSA || algorithm == ALG_ED25519) { "unknown algorithm" }
        val flags = data.readUnsignedByte()
        val application = String(field(data, 256), Charsets.UTF_8)
        val message = field(data, MAX_FIELD)
        val handle = field(data, 1024)
        return Request(operation, algorithm, flags, application, message, handle)
    }

    fun writeRequest(output: OutputStream, request: Request) {
        val data = DataOutputStream(output)
        data.write(MAGIC)
        data.writeByte(VERSION)
        data.writeByte(request.operation)
        data.writeInt(request.algorithm)
        data.writeByte(request.flags)
        field(data, request.application.toByteArray(Charsets.UTF_8))
        field(data, request.message)
        field(data, request.handle)
        data.flush()
    }

    fun writeResponse(output: OutputStream, response: Response) {
        val data = DataOutputStream(output)
        data.write(MAGIC)
        data.writeByte(VERSION)
        when (response) {
            is Response.Failed -> data.writeInt(response.error)
            is Response.Enrolled -> {
                data.writeInt(0)
                data.writeByte(OP_ENROLL)
                data.writeByte(response.flags)
                field(data, response.publicKey)
                field(data, response.keyHandle)
                field(data, response.signature)
                field(data, ByteArray(0))
                field(data, response.authenticatorData)
            }
            is Response.Signed -> {
                data.writeInt(0)
                data.writeByte(OP_SIGN)
                data.writeByte(response.flags)
                data.writeInt(response.counter.toInt())
                field(data, response.r)
                field(data, response.s)
            }
            is Response.Listed -> {
                data.writeInt(0)
                data.writeByte(OP_LIST)
                data.writeInt(response.keys.size)
                response.keys.forEach { key ->
                    data.writeInt(key.algorithm)
                    field(data, key.application.toByteArray(Charsets.UTF_8))
                    data.writeByte(key.flags)
                    field(data, key.publicKey)
                    field(data, key.keyHandle)
                    field(data, key.userId)
                }
            }
        }
        data.flush()
    }

    private fun field(data: DataInputStream, limit: Int): ByteArray {
        val length = data.readInt()
        require(length in 0..limit) { "field too long" }
        return ByteArray(length).also(data::readFully)
    }

    private fun field(data: DataOutputStream, bytes: ByteArray) {
        data.writeInt(bytes.size)
        data.write(bytes)
    }
}
