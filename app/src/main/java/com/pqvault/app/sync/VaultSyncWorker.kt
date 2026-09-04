package com.pqvault.app.sync

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.pqvault.app.data.VaultRepository
import com.pqvault.core.sync.VaultSyncEngine
import java.util.concurrent.TimeUnit

/**
 * Periodic background sync.
 *
 * Runs unattended through the device's own KEM key, so it never needs the passphrase.
 */
class VaultSyncWorker(
    context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val repository = VaultRepository.get(applicationContext)
        return when (val outcome = repository.syncUnattended()) {
            is VaultSyncEngine.Outcome.Written -> Result.success()

            // A rejected remote is not a transient error and retrying cannot fix it. The
            // user has already been notified on the security channel; retrying would only
            // hammer a server that is lying to us.
            is VaultSyncEngine.Outcome.RemoteUntrusted -> Result.failure()

            is VaultSyncEngine.Outcome.RemoteUnreadable -> Result.failure()

            // Nothing to retry until the user finishes setting the app up; anything
            // else is worth another attempt with backoff.
            is VaultSyncEngine.Outcome.Failed ->
                if (outcome.permanent) Result.failure() else Result.retry()
        }
    }

    companion object {
        private const val PERIODIC_WORK = "pqvault_periodic_sync"
        private const val ONE_SHOT_WORK = "pqvault_sync_now"

        /**
         * 15 minutes is WorkManager's floor for periodic work; the system will stretch it
         * under Doze, which is the right behaviour for a vault that is not latency
         * sensitive.
         */
        fun schedule(context: Context) {
            val request = PeriodicWorkRequestBuilder<VaultSyncWorker>(15, TimeUnit.MINUTES)
                .setConstraints(
                    Constraints.Builder()
                        .setRequiredNetworkType(NetworkType.CONNECTED)
                        .build(),
                )
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
                .build()

            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                PERIODIC_WORK,
                // KEEP, so re-opening the app does not reset the schedule and starve sync.
                ExistingPeriodicWorkPolicy.KEEP,
                request,
            )
        }

        fun syncNow(context: Context) {
            val request = OneTimeWorkRequestBuilder<VaultSyncWorker>()
                .setConstraints(
                    Constraints.Builder()
                        .setRequiredNetworkType(NetworkType.CONNECTED)
                        .build(),
                )
                .build()
            WorkManager.getInstance(context).enqueue(request)
        }

        fun cancel(context: Context) {
            WorkManager.getInstance(context).cancelUniqueWork(PERIODIC_WORK)
        }
    }
}
