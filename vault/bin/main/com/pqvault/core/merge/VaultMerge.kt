package com.pqvault.core.merge

import com.pqvault.core.model.DeviceRecord
import com.pqvault.core.model.PasskeyEntry
import com.pqvault.core.model.Tombstone

/**
 * Merges two divergent copies of a vault.
 *
 * WebDAV gives us no locking we can rely on across clients, so two phones that were both
 * offline will each hold a legitimately newer file than the server. Rejecting one of them
 * would lose passkeys, so we merge per entry instead of per file, the same reason
 * KeePassDX merges databases rather than picking a winner.
 */
object VaultMerge {

    class Result(
        val entries: List<PasskeyEntry>,
        val tombstones: List<Tombstone>,
        val devices: List<DeviceRecord>,
        /** Entries where both sides had changes and one was discarded; surfaced to the user. */
        val conflicts: List<Conflict>,
    )

    class Conflict(
        val credentialId: String,
        val keptUpdatedAt: Long,
        val discardedUpdatedAt: Long,
    )

    fun merge(
        localEntries: List<PasskeyEntry>,
        localTombstones: List<Tombstone>,
        localDevices: List<DeviceRecord>,
        remoteEntries: List<PasskeyEntry>,
        remoteTombstones: List<Tombstone>,
        remoteDevices: List<DeviceRecord>,
    ): Result {
        val tombstones = (localTombstones + remoteTombstones)
            .groupBy { it.credentialId }
            // Keep the newest deletion, so a delete-then-recreate is not undone by an
            // older tombstone from the other side.
            .mapValues { (_, all) -> all.maxBy { it.deletedAt } }

        val conflicts = mutableListOf<Conflict>()
        val byId = mutableMapOf<String, PasskeyEntry>()

        for (entry in localEntries) byId[entry.credentialId] = entry

        for (remote in remoteEntries) {
            val local = byId[remote.credentialId]
            if (local == null) {
                byId[remote.credentialId] = remote
                continue
            }
            val winner = if (remote.updatedAt > local.updatedAt) remote else local
            val loser = if (winner === remote) local else remote
            // Only a merge that actually discards something is a conflict worth telling
            // the user about. Differing timestamps alone are the normal case: using a
            // passkey bumps signCount and updatedAt on one device, and the other side is
            // simply the older copy of the same record. Since signCount is merged by
            // maximum and never lost, records that agree on everything else lose nothing,
            // and reporting them was drowning genuine conflicts in routine noise.
            if (discardsData(winner, loser)) {
                conflicts.add(Conflict(remote.credentialId, winner.updatedAt, loser.updatedAt))
            }
            // The signature counter is the one field that must never regress. Relying
            // parties read a counter going backwards as evidence of a cloned
            // authenticator and may lock the credential, so it takes the maximum of both
            // sides rather than the winning record's value: both devices may have
            // signed while they were apart.
            byId[remote.credentialId] = winner.copy(
                signCount = maxOf(local.signCount, remote.signCount),
            )
        }

        val entries = byId.values.filter { entry ->
            val tombstone = tombstones[entry.credentialId]
            tombstone == null || entry.updatedAt > tombstone.deletedAt
        }

        // A tombstone whose entry was resurrected by a newer edit is spent; dropping it
        // keeps the file from growing without bound.
        val liveIds = entries.map { it.credentialId }.toSet()
        val keptTombstones = tombstones.values.filter { it.credentialId !in liveIds }

        val devices = (localDevices + remoteDevices)
            .groupBy { it.deviceId }
            .map { (_, all) -> all.maxBy { it.enrolledAt } }

        return Result(
            entries = entries.sortedBy { it.credentialId },
            tombstones = keptTombstones.sortedBy { it.credentialId },
            devices = devices.sortedBy { it.deviceId },
            conflicts = conflicts,
        )
    }

    /**
     * True when keeping [winner] loses something [loser] carried. The two fields that
     * merge losslessly are excluded: [PasskeyEntry.signCount] is taken as the maximum of
     * both sides, and [PasskeyEntry.updatedAt] is the timestamp that decided the winner.
     */
    private fun discardsData(winner: PasskeyEntry, loser: PasskeyEntry): Boolean {
        val normalise = { entry: PasskeyEntry -> entry.copy(signCount = 0, updatedAt = 0) }
        return normalise(winner) != normalise(loser)
    }
}
