package com.pqvault.core.merge

import com.google.common.truth.Truth.assertThat
import com.pqvault.core.model.DeviceRecord
import com.pqvault.core.model.PasskeyEntry
import com.pqvault.core.model.Tombstone
import org.junit.jupiter.api.Test

class VaultMergeTest {

    private fun entry(
        id: String,
        updatedAt: Long,
        signCount: Long = 0,
        userName: String = "simon",
    ) = PasskeyEntry(
        credentialId = id,
        rpId = "github.com",
        userHandle = "dXNlcg",
        userName = userName,
        privateKeyPkcs8 = "cHJpdmF0ZQ",
        publicKeySpki = "cHVibGlj",
        signCount = signCount,
        createdAt = 0,
        updatedAt = updatedAt,
    )

    private fun merge(
        local: List<PasskeyEntry> = emptyList(),
        localTombs: List<Tombstone> = emptyList(),
        remote: List<PasskeyEntry> = emptyList(),
        remoteTombs: List<Tombstone> = emptyList(),
        localDevices: List<DeviceRecord> = emptyList(),
        remoteDevices: List<DeviceRecord> = emptyList(),
    ) = VaultMerge.merge(local, localTombs, localDevices, remote, remoteTombs, remoteDevices)

    @Test
    fun `entries added on either side are both kept`() {
        val result = merge(local = listOf(entry("a", 10)), remote = listOf(entry("b", 10)))

        assertThat(result.entries.map { it.credentialId }).containsExactly("a", "b")
        assertThat(result.conflicts).isEmpty()
    }

    @Test
    fun `the more recently updated copy wins`() {
        val result = merge(
            local = listOf(entry("a", updatedAt = 10, userName = "older")),
            remote = listOf(entry("a", updatedAt = 20, userName = "newer")),
        )

        assertThat(result.entries).hasSize(1)
        assertThat(result.entries[0].userName).isEqualTo("newer")
    }

    @Test
    fun `a divergent entry is reported as a conflict`() {
        val result = merge(
            local = listOf(entry("a", updatedAt = 10, userName = "edited here")),
            remote = listOf(entry("a", updatedAt = 20, userName = "edited there")),
        )

        assertThat(result.conflicts).hasSize(1)
        assertThat(result.conflicts[0].credentialId).isEqualTo("a")
        assertThat(result.conflicts[0].keptUpdatedAt).isEqualTo(20)
        assertThat(result.conflicts[0].discardedUpdatedAt).isEqualTo(10)
    }

    /**
     * The common case by far, and it used to be reported as a conflict. Using a passkey
     * bumps its counter and its timestamp on one device; the other device simply holds
     * the older copy of the same record. The counter merges by maximum and nothing else
     * differs, so nothing is discarded and there is nothing to tell the user about.
     * Calling it a conflict trained them to ignore the notification that matters.
     */
    @Test
    fun `an entry that only advanced in time and use count is not a conflict`() {
        val result = merge(
            local = listOf(entry("a", updatedAt = 10, signCount = 3)),
            remote = listOf(entry("a", updatedAt = 20, signCount = 5)),
        )

        assertThat(result.conflicts).isEmpty()
        assertThat(result.entries[0].signCount).isEqualTo(5)
        assertThat(result.entries[0].updatedAt).isEqualTo(20)
    }

    /**
     * The single most important rule here. Both devices signed while they were apart, so
     * both counters advanced. Taking the winning record's counter would move it backwards
     * relative to the other device, and relying parties treat a regressing counter as a
     * cloned authenticator.
     */
    @Test
    fun `the signature counter takes the maximum of both sides`() {
        val result = merge(
            local = listOf(entry("a", updatedAt = 30, signCount = 9)),
            remote = listOf(entry("a", updatedAt = 40, signCount = 4)),
        )

        assertThat(result.entries[0].signCount).isEqualTo(9)
        // ...and the newer record still wins on every other field.
        assertThat(result.entries[0].updatedAt).isEqualTo(40)
    }

    @Test
    fun `the signature counter never regresses in either merge direction`() {
        val local = listOf(entry("a", updatedAt = 30, signCount = 9))
        val remote = listOf(entry("a", updatedAt = 40, signCount = 4))

        val forward = merge(local = local, remote = remote)
        val backward = merge(local = remote, remote = local)

        assertThat(forward.entries[0].signCount).isEqualTo(9)
        assertThat(backward.entries[0].signCount).isEqualTo(9)
    }

    @Test
    fun `a deletion is not undone by the other side still holding the entry`() {
        val result = merge(
            local = emptyList(),
            localTombs = listOf(Tombstone("a", deletedAt = 50)),
            remote = listOf(entry("a", updatedAt = 10)),
        )

        assertThat(result.entries).isEmpty()
        assertThat(result.tombstones.map { it.credentialId }).containsExactly("a")
    }

    @Test
    fun `an edit newer than the deletion resurrects the entry`() {
        val result = merge(
            localTombs = listOf(Tombstone("a", deletedAt = 50)),
            remote = listOf(entry("a", updatedAt = 90)),
        )

        assertThat(result.entries.map { it.credentialId }).containsExactly("a")
        // The spent tombstone is dropped rather than kept forever.
        assertThat(result.tombstones).isEmpty()
    }

    @Test
    fun `the newest deletion wins when both sides deleted`() {
        val result = merge(
            localTombs = listOf(Tombstone("a", deletedAt = 50)),
            remoteTombs = listOf(Tombstone("a", deletedAt = 80)),
        )

        assertThat(result.tombstones).hasSize(1)
        assertThat(result.tombstones[0].deletedAt).isEqualTo(80)
    }

    @Test
    fun `merging is commutative for entries and tombstones`() {
        val a = listOf(entry("a", 10), entry("b", 40, signCount = 3))
        val b = listOf(entry("b", 20, signCount = 7), entry("c", 30))
        val ta = listOf(Tombstone("d", 15))
        val tb = listOf(Tombstone("e", 25))

        val forward = merge(local = a, localTombs = ta, remote = b, remoteTombs = tb)
        val backward = merge(local = b, localTombs = tb, remote = a, remoteTombs = ta)

        assertThat(forward.entries.map { it.credentialId })
            .isEqualTo(backward.entries.map { it.credentialId })
        assertThat(forward.entries.map { it.signCount })
            .isEqualTo(backward.entries.map { it.signCount })
        assertThat(forward.tombstones.map { it.credentialId })
            .isEqualTo(backward.tombstones.map { it.credentialId })
    }

    @Test
    fun `merging a copy with itself changes nothing`() {
        val entries = listOf(entry("a", 10), entry("b", 20, signCount = 5))
        val tombs = listOf(Tombstone("c", 30))

        val result = merge(local = entries, localTombs = tombs, remote = entries, remoteTombs = tombs)

        assertThat(result.entries.map { it.credentialId }).containsExactly("a", "b")
        assertThat(result.entries.map { it.signCount }).containsExactly(0L, 5L)
        assertThat(result.tombstones.map { it.credentialId }).containsExactly("c")
        assertThat(result.conflicts).isEmpty()
    }

    @Test
    fun `enrolled devices from both sides are preserved`() {
        val result = merge(
            localDevices = listOf(DeviceRecord("phone", "phone", "pk1", 10)),
            remoteDevices = listOf(DeviceRecord("tablet", "tablet", "pk2", 20)),
        )

        assertThat(result.devices.map { it.deviceId }).containsExactly("phone", "tablet")
    }

    @Test
    fun `a re-enrolled device keeps its newest record`() {
        val result = merge(
            localDevices = listOf(DeviceRecord("phone", "old", "pk1", 10)),
            remoteDevices = listOf(DeviceRecord("phone", "reinstalled", "pk2", 99)),
        )

        assertThat(result.devices).hasSize(1)
        assertThat(result.devices[0].label).isEqualTo("reinstalled")
    }
}
