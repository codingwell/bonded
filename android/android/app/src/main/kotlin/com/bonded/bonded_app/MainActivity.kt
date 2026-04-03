package com.bonded.bonded_app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel
import java.time.Instant
import java.util.UUID

class MainActivity : FlutterActivity() {
	private val channelName = "bonded/native"
	private val backgroundEventsChannelName = "bonded/background-events"
	private var backgroundEventSink: EventChannel.EventSink? = null
	private var pendingVpnStartResult: MethodChannel.Result? = null
	private var pendingRunInBackground = false
	private var pendingDeviceId: String? = null

	companion object {
		private const val REQUEST_CODE_VPN_PREPARE = 2001
		private var nativeLoaded = false

		init {
			try {
				System.loadLibrary("bonded_ffi")
				nativeLoaded = true
			} catch (_: UnsatisfiedLinkError) {
				nativeLoaded = false
			}
		}
	}

	private external fun nativeApiVersion(): Int
	private external fun nativeRedeemInviteToken(
		serverAddress: String,
		serverPublicKey: String,
		inviteToken: String,
		storageDir: String,
	): Boolean

	private fun startVpnWithPermissionFlow(
		deviceId: String,
		runInBackground: Boolean,
		result: MethodChannel.Result,
	) {
		val prepareIntent = VpnService.prepare(this)
		if (prepareIntent == null) {
			BondedVpnService.start(this, deviceId, runInBackground = runInBackground)
			result.success("started")
			return
		}

		if (pendingVpnStartResult != null) {
			result.error("vpn_permission_pending", "VPN permission request already in progress", null)
			return
		}

		pendingVpnStartResult = result
		pendingRunInBackground = runInBackground
		pendingDeviceId = deviceId
		startActivityForResult(prepareIntent, REQUEST_CODE_VPN_PREPARE)
	}

	override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
		super.onActivityResult(requestCode, resultCode, data)

		if (requestCode != REQUEST_CODE_VPN_PREPARE) {
			return
		}

		val pendingResult = pendingVpnStartResult
		val deviceId = pendingDeviceId
		pendingVpnStartResult = null
		pendingDeviceId = null

		if (pendingResult == null || deviceId == null) {
			return
		}

		if (resultCode == Activity.RESULT_OK) {
			BondedVpnService.start(this, deviceId, runInBackground = pendingRunInBackground)
			pendingResult.success("started")
		} else {
			pendingResult.error("permission_denied", "VPN permission denied", null)
		}
	}

	override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
		super.configureFlutterEngine(flutterEngine)

		MethodChannel(flutterEngine.dartExecutor.binaryMessenger, channelName)
			.setMethodCallHandler { call, result ->
				when (call.method) {
					"getNetworkTestLogs" -> {
						result.success(NetworkTestReceiver.getBufferedLogs())
					}

					"clearNetworkTestLogs" -> {
						NetworkTestReceiver.clearBufferedLogs()
						result.success(null)
					}

					"runNetworkTest" -> {
						val args = call.arguments as? Map<*, *>
						val action = args?.get("action") as? String
						if (action.isNullOrBlank()) {
							result.error("invalid_args", "action is required", null)
						} else {
							try {
								val intent = Intent(this, NetworkTestForegroundService::class.java)
									.setAction(NetworkTestForegroundService.ACTION_RUN)
									.putExtra(NetworkTestForegroundService.EXTRA_TEST_ACTION, action)
								(args["host"] as? String)?.let {
									intent.putExtra(NetworkTestForegroundService.EXTRA_HOST, it)
								}
								(args["expected_ip"] as? String)?.let {
									intent.putExtra(NetworkTestForegroundService.EXTRA_EXPECTED_IP, it)
								}
								(args["url"] as? String)?.let {
									intent.putExtra(NetworkTestForegroundService.EXTRA_URL, it)
								}
								(args["port"] as? Int)?.let {
									intent.putExtra(NetworkTestForegroundService.EXTRA_PORT, it)
								}
								if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
									startForegroundService(intent)
								} else {
									startService(intent)
								}
								result.success("sent")
							} catch (e: Exception) {
								result.error("service_start_failed", e.message, null)
							}
						}
					}

					"getNativeApiVersion" -> {
						if (!nativeLoaded) {
							result.success(-1)
							return@setMethodCallHandler
						}

						try {
							result.success(nativeApiVersion())
						} catch (_: UnsatisfiedLinkError) {
							result.success(-1)
						}
					}

					"getVpnStatus" -> {
						result.success(BondedVpnService.isRunning())
					}

					"getVpnSessionStatus" -> {
						result.success(BondedVpnService.getSessionSnapshot())
					}

					"startVpnService" -> {
						val args = call.arguments as? Map<*, *>
						val deviceId = args?.get("deviceId") as? String
						if (deviceId.isNullOrBlank()) {
							result.error("missing_device_id", "deviceId is required", null)
						} else {
							startVpnWithPermissionFlow(deviceId, runInBackground = false, result = result)
						}
					}

					"startBackgroundVpn" -> {
						val args = call.arguments as? Map<*, *>
						val deviceId = args?.get("deviceId") as? String
						if (deviceId.isNullOrBlank()) {
							result.error("missing_device_id", "deviceId is required", null)
						} else {
							startVpnWithPermissionFlow(deviceId, runInBackground = true, result = result)
						}
					}

					"redeemInviteToken" -> {
						val args = call.arguments as? Map<*, *>
						val serverAddress = args?.get("serverAddress") as? String
						val serverPublicKey = args?.get("serverPublicKey") as? String
						val inviteToken = args?.get("inviteToken") as? String

						if (serverAddress.isNullOrBlank() || serverPublicKey.isNullOrBlank() || inviteToken.isNullOrBlank()) {
							result.error("invalid_args", "serverAddress, serverPublicKey, and inviteToken are required", null)
						} else {
							val redeemed = try {
								nativeRedeemInviteToken(
									serverAddress,
									serverPublicKey,
									inviteToken,
									filesDir.absolutePath,
								)
							} catch (_: UnsatisfiedLinkError) {
								false
							}

							if (!redeemed) {
								result.error("pairing_failed", "Failed to redeem invite token via native runtime", null)
							} else {
								result.success(UUID.randomUUID().toString())
							}
						}
					}

					"storePairedServer" -> {
						val args = call.arguments as? Map<*, *>
						val deviceId = args?.get("deviceId") as? String
						val publicAddress = args?.get("publicAddress") as? String
						val serverPublicKey = args?.get("serverPublicKey") as? String
						val supportedProtocols = (args?.get("supportedProtocols") as? List<*>)
							?.mapNotNull { it as? String }
							?: emptyList()

						if (deviceId.isNullOrBlank() || publicAddress.isNullOrBlank() || serverPublicKey.isNullOrBlank()) {
							result.error("invalid_args", "deviceId, publicAddress, and serverPublicKey are required", null)
						} else {
							PairedServerStore.save(
								this,
								PairedServerRecord(
									id = deviceId,
									publicAddress = publicAddress,
									serverPublicKey = serverPublicKey,
									supportedProtocols = supportedProtocols,
									pairedAt = Instant.now().toString(),
								),
							)
							result.success(null)
						}
					}

					"getPairedServers" -> {
						val servers = PairedServerStore.loadAll(this).map { server ->
							mapOf(
								"id" to server.id,
								"publicAddress" to server.publicAddress,
								"serverPublicKey" to server.serverPublicKey,
								"supportedProtocols" to server.supportedProtocols,
								"pairedAt" to server.pairedAt,
							)
						}
						result.success(servers)
					}

					"updatePairedServer" -> {
						val args = call.arguments as? Map<*, *>
						val deviceId = args?.get("deviceId") as? String
						val publicAddress = args?.get("publicAddress") as? String
						val serverPublicKey = args?.get("serverPublicKey") as? String
						val supportedProtocols = (args?.get("supportedProtocols") as? List<*>)
							?.mapNotNull { it as? String }
							?: emptyList()

						val existing = deviceId?.let { PairedServerStore.findById(this, it) }
						if (deviceId.isNullOrBlank() || publicAddress.isNullOrBlank() || serverPublicKey.isNullOrBlank() || existing == null) {
							result.error("invalid_args", "existing deviceId, publicAddress, and serverPublicKey are required", null)
						} else {
							PairedServerStore.save(
								this,
								PairedServerRecord(
									id = deviceId,
									publicAddress = publicAddress,
									serverPublicKey = serverPublicKey,
									supportedProtocols = supportedProtocols,
									pairedAt = existing.pairedAt,
								),
							)
							result.success(null)
						}
					}

					"deletePairedServer" -> {
						val args = call.arguments as? Map<*, *>
						val deviceId = args?.get("deviceId") as? String
						if (deviceId.isNullOrBlank()) {
							result.error("invalid_args", "deviceId is required", null)
						} else {
							PairedServerStore.delete(this, deviceId)
							result.success(null)
						}
					}

					"stopVpnService" -> {
						BondedVpnService.stop(this)
						result.success("stopped")
					}

					"stopBackgroundVpn" -> {
						BondedVpnService.stop(this)
						result.success("stopped")
					}

					"isBackgroundVpnRunning" -> {
						result.success(BondedVpnService.isBackgroundRunning())
					}

					else -> result.notImplemented()
				}
			}

		EventChannel(flutterEngine.dartExecutor.binaryMessenger, backgroundEventsChannelName)
			.setStreamHandler(
				object : EventChannel.StreamHandler {
					override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
						backgroundEventSink = events
						BondedVpnService.setStatusListener { type, message ->
							runOnUiThread {
								backgroundEventSink?.success(
									mapOf(
										"type" to type,
										"message" to message,
									),
								)
							}
						}
					}

					override fun onCancel(arguments: Any?) {
						BondedVpnService.setStatusListener(null)
						backgroundEventSink = null
					}
				},
			)
	}
}
