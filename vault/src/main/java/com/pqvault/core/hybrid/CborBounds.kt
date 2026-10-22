package com.pqvault.core.hybrid

/**
 * Walks one CBOR item before it reaches the decoder, which allocates whatever a header
 * announces: five bytes claiming a 2 GiB byte string would otherwise exhaust the heap,
 * and a deep enough nesting the stack. Every declared length has to fit in the bytes
 * actually present, nesting stays shallow, and indefinite lengths are refused, as CTAP2
 * only exchanges canonical CBOR.
 */
internal object CborBounds {
    private const val MAX_DEPTH = 16

    fun check(data: ByteArray) {
        require(item(data, 0, 0) == data.size) { "trailing bytes after the CBOR item" }
    }

    /** Returns the offset just past the item that starts at [start]. */
    private fun item(data: ByteArray, start: Int, depth: Int): Int {
        require(depth <= MAX_DEPTH) { "CBOR nested too deeply" }
        require(start < data.size) { "truncated CBOR" }
        val initial = data[start].toInt() and 0xff
        val major = initial ushr 5
        val info = initial and 0x1f
        val width = when {
            info < 24 -> 0
            info == 24 -> 1
            info == 25 -> 2
            info == 26 -> 4
            info == 27 -> 8
            else -> throw IllegalArgumentException("indefinite or reserved CBOR length")
        }
        var position = start + 1
        require(width <= data.size - position) { "truncated CBOR" }
        var value = if (width == 0) info.toLong() else 0L
        repeat(width) { value = (value shl 8) or (data[position++].toLong() and 0xff) }
        val remaining = (data.size - position).toLong()

        return when (major) {
            0, 1, 7 -> position
            2, 3 -> {
                require(value in 0..remaining) { "CBOR string longer than its data" }
                position + value.toInt()
            }
            4, 5 -> {
                val children = if (major == 4) value else value * 2
                // Every child takes at least one byte, so no honest count exceeds them.
                require(value in 0..remaining && children <= remaining) { "CBOR container larger than its data" }
                var next = position
                for (child in 0 until children) next = item(data, next, depth + 1)
                next
            }
            else -> item(data, position, depth + 1)
        }
    }
}
