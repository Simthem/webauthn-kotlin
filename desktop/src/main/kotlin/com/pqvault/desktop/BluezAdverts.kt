package com.pqvault.desktop

import com.pqvault.core.hybrid.HybridAdvert
import org.freedesktop.dbus.annotations.DBusInterfaceName
import org.freedesktop.dbus.connections.impl.DBusConnectionBuilder
import org.freedesktop.dbus.interfaces.DBusInterface
import org.freedesktop.dbus.interfaces.DBusSigHandler
import org.freedesktop.dbus.interfaces.ObjectManager
import org.freedesktop.dbus.interfaces.Properties
import org.freedesktop.dbus.types.Variant
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

@Suppress("FunctionName")
@DBusInterfaceName("org.bluez.Adapter1")
interface BluezAdapter : DBusInterface {
    fun StartDiscovery()
    fun StopDiscovery()
    fun SetDiscoveryFilter(filter: Map<String, Variant<*>>)
}

/** Listens for the phone's advert through BlueZ on the system bus. It never connects to it. */
class BluezAdverts : AdvertSource {

    override fun await(accept: (ByteArray) -> HybridAdvert.Opened?, timeoutMillis: Long): HybridAdvert.Opened? {
        DBusConnectionBuilder.forSystemBus().withShared(false).build().use { bus ->
            val objects = bus.getRemoteObject(BLUEZ, "/", ObjectManager::class.java).GetManagedObjects()
            val adapterPath = objects.entries.firstOrNull { (_, interfaces) ->
                interfaces[ADAPTER]?.get("Powered")?.value == true
            }?.key?.path ?: throw HybridFailure("no Bluetooth adapter is powered on")
            val adapter = bus.getRemoteObject(BLUEZ, adapterPath, BluezAdapter::class.java)

            val found = LinkedBlockingQueue<HybridAdvert.Opened>()
            fun offer(serviceData: Any?) {
                (serviceData as? Map<*, *>)?.forEach { (uuid, value) ->
                    if ((uuid as? String)?.lowercase() in SERVICES) serviceDataBytes(value)?.let(accept)?.let(found::offer)
                }
            }
            val added = DBusSigHandler<ObjectManager.InterfacesAdded> { signal ->
                offer(signal.interfaces[DEVICE]?.get(SERVICE_DATA)?.value)
            }
            val changed = DBusSigHandler<Properties.PropertiesChanged> { signal ->
                if (signal.interfaceName == DEVICE) offer(signal.propertiesChanged[SERVICE_DATA]?.value)
            }
            bus.addSigHandler(ObjectManager.InterfacesAdded::class.java, added)
            bus.addSigHandler(Properties.PropertiesChanged::class.java, changed)
            try {
                adapter.SetDiscoveryFilter(mapOf("Transport" to Variant("le"), "DuplicateData" to Variant(true)))
                adapter.StartDiscovery()
                return found.poll(timeoutMillis, TimeUnit.MILLISECONDS)
            } finally {
                runCatching { adapter.StopDiscovery() }
                runCatching { bus.removeSigHandler(ObjectManager.InterfacesAdded::class.java, added) }
                runCatching { bus.removeSigHandler(Properties.PropertiesChanged::class.java, changed) }
            }
        }
    }

    internal companion object {
        /** dbus-java hands `ay` inside a variant over as a list of bytes. */
        fun serviceDataBytes(value: Any?): ByteArray? = when (val raw = (value as? Variant<*>)?.value ?: value) {
            is ByteArray -> raw
            is List<*> -> raw.filterIsInstance<Byte>().takeIf { it.size == raw.size }?.toByteArray()
            else -> null
        }

        private const val BLUEZ = "org.bluez"
        private const val ADAPTER = "org.bluez.Adapter1"
        private const val DEVICE = "org.bluez.Device1"
        private const val SERVICE_DATA = "ServiceData"
        private val SERVICES = setOf("0000fff9-0000-1000-8000-00805f9b34fb", "0000fde2-0000-1000-8000-00805f9b34fb")
    }
}
