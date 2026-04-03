package com.bonded.bonded_app

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import java.net.Inet4Address

data class NetworkPathBinding(
    val transport: Int,
    val bindAddress: String?,
)

class AndroidNetworkPathManager(
    context: Context,
    private val onPathCountChanged: (Int) -> Unit,
) {
    private val connectivityManager =
        context.getSystemService(ConnectivityManager::class.java)

    private val trackedNetworks = linkedMapOf<Network, NetworkPathBinding>()
    private val callbacks = mutableListOf<ConnectivityManager.NetworkCallback>()
    private var running = false

    fun start(): Int {
        if (connectivityManager == null) {
            onPathCountChanged(1)
            return 1
        }

        if (!running) {
            running = true
            refreshTrackedNetworks()
            registerTransportRequest(NetworkCapabilities.TRANSPORT_WIFI)
            registerTransportRequest(NetworkCapabilities.TRANSPORT_CELLULAR)
            registerTransportRequest(NetworkCapabilities.TRANSPORT_ETHERNET)
            notifyPathCountChanged()
        }

        return activePathCount()
    }

    fun stop() {
        if (!running || connectivityManager == null) {
            trackedNetworks.clear()
            running = false
            return
        }

        callbacks.forEach { callback ->
            try {
                connectivityManager.unregisterNetworkCallback(callback)
            } catch (_: Exception) {
            }
        }
        callbacks.clear()
        trackedNetworks.clear()
        running = false
        notifyPathCountChanged()
    }

    fun activePathCount(): Int {
        val uniqueTransports = trackedNetworks.values.map { it.transport }.toSet().size
        return uniqueTransports.coerceIn(1, 2)
    }

    fun activeBindAddresses(limit: Int = 2): List<String> {
        return trackedNetworks.values
            .sortedBy { binding -> transportPriority(binding.transport) }
            .mapNotNull { binding -> binding.bindAddress }
            .distinct()
            .take(limit)
    }

    private fun registerTransportRequest(transportType: Int) {
        val manager = connectivityManager ?: return
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                trackNetwork(network)
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                trackNetwork(network, networkCapabilities)
            }

            override fun onLost(network: Network) {
                trackedNetworks.remove(network)
                notifyPathCountChanged()
            }
        }

        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addTransportType(transportType)
            .build()

        try {
            manager.requestNetwork(request, callback)
            callbacks.add(callback)
        } catch (_: Exception) {
        }
    }

    private fun refreshTrackedNetworks() {
        val manager = connectivityManager ?: return
        trackedNetworks.clear()
        manager.allNetworks.forEach { network ->
            trackNetwork(network)
        }
    }

    private fun trackNetwork(network: Network, capabilities: NetworkCapabilities? = null) {
        val resolvedCapabilities = capabilities
            ?: connectivityManager?.getNetworkCapabilities(network)
            ?: return

        val transport = when {
            resolvedCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> {
                NetworkCapabilities.TRANSPORT_WIFI
            }
            resolvedCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> {
                NetworkCapabilities.TRANSPORT_CELLULAR
            }
            resolvedCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> {
                NetworkCapabilities.TRANSPORT_ETHERNET
            }
            else -> return
        }

        trackedNetworks[network] = NetworkPathBinding(
            transport = transport,
            bindAddress = resolveBindAddress(network),
        )
        notifyPathCountChanged()
    }

    private fun resolveBindAddress(network: Network): String? {
        val linkProperties = connectivityManager?.getLinkProperties(network) ?: return null
        return pickBindAddress(linkProperties)
    }

    private fun pickBindAddress(linkProperties: LinkProperties): String? {
        val addresses = linkProperties.linkAddresses.mapNotNull { linkAddress ->
            val address = linkAddress.address ?: return@mapNotNull null
            when {
                address.isLoopbackAddress || address.isLinkLocalAddress || address.isAnyLocalAddress -> null
                address is Inet4Address -> address.hostAddress
                else -> null
            }
        }

        return addresses.firstOrNull()
    }

    private fun transportPriority(transport: Int): Int {
        return when (transport) {
            NetworkCapabilities.TRANSPORT_WIFI -> 0
            NetworkCapabilities.TRANSPORT_CELLULAR -> 1
            NetworkCapabilities.TRANSPORT_ETHERNET -> 2
            else -> 99
        }
    }

    private fun notifyPathCountChanged() {
        onPathCountChanged(activePathCount())
    }
}