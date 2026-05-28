use crate::buffer_pool::BufferPool;
use crate::config::{Config, OneWayMode};
use crate::interval_reporter::{run_reporter_task, IntervalReport, IntervalReporter};
use crate::measurements::{get_tcp_stats, IntervalStats, MeasurementsCollector, ServerOneWayStats};
use crate::protocol::{deserialize_message, serialize_message, Message, DEFAULT_STREAM_ID};
use crate::{Error, Result};
use log::{debug, error, info};
use socket2::SockRef;
use std::collections::HashMap;
use std::net::SocketAddr;
#[cfg(all(unix, target_os = "linux"))]
use std::os::unix::io::AsRawFd;
use std::os::windows::io::AsRawSocket;
use std::os::windows::prelude::RawSocket;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::RwLock;
use std::thread;
use std::time::{Duration, Instant};

// ============================================================================
// Windows multi-threaded UDP receiver using DuplicateHandle + native recv
// ============================================================================

#[cfg(target_os = "windows")]
mod windows_socket_dup {
    use std::os::windows::io::AsRawSocket;
    use std::os::windows::prelude::RawSocket;
    use tokio::net::UdpSocket;
    use std::ptr::null_mut;

    type HANDLE = *mut std::ffi::c_void;
    type DWORD = u32;
    type BOOL = i32;
    const DUPLICATE_SAME_ACCESS: DWORD = 0x00000002;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> HANDLE;
        fn DuplicateHandle(
            hSourceProcessHandle: HANDLE, hSourceHandle: HANDLE,
            hTargetProcessHandle: HANDLE, lpTargetHandle: *mut HANDLE,
            dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwOptions: DWORD,
        ) -> BOOL;
    }

    pub fn duplicate_socket_for_thread(socket: &UdpSocket) -> std::io::Result<RawSocket> {
        let raw_socket = socket.as_raw_socket();
        let self_process = unsafe { GetCurrentProcess() };
        let mut new_handle: HANDLE = null_mut();
        let result = unsafe {
            DuplicateHandle(self_process, raw_socket as HANDLE, self_process,
                           &mut new_handle, 0, 1, DUPLICATE_SAME_ACCESS)
        };
        if result == 0 { return Err(std::io::Error::last_os_error()); }
        Ok(new_handle as RawSocket)
    }
}

#[cfg(target_os = "windows")]
use windows_socket_dup::duplicate_socket_for_thread;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

/// Configure TCP socket options for optimal performance.
///
/// This function applies the following optimizations:
/// - **TCP_NODELAY**: Disables Nagle's algorithm to reduce latency
/// - **Send buffer**: Increases to 256KB for higher throughput
/// - **Receive buffer**: Increases to 256KB for higher throughput
///
/// # Arguments
///
/// * `stream` - The TCP stream to configure
///
/// # Returns
///
/// Returns `Ok(())` on success, or an `Error` if any socket option fails to set.
///
/// # Performance Impact
///
/// Expected 10-20% improvement in TCP throughput tests with these optimizations.
fn configure_tcp_socket(stream: &TcpStream) -> Result<()> {
    // Disable Nagle's algorithm for lower latency
    stream.set_nodelay(true).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("Failed to set TCP_NODELAY: {}", e),
        ))
    })?;

    // Set larger send and receive buffers for higher throughput
    const BUFFER_SIZE: usize = 256 * 1024; // 256KB
    let sock_ref = SockRef::from(stream);

    sock_ref.set_send_buffer_size(BUFFER_SIZE).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("Failed to set send buffer size: {}", e),
        ))
    })?;

    sock_ref.set_recv_buffer_size(BUFFER_SIZE).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("Failed to set recv buffer size: {}", e),
        ))
    })?;

    debug!(
        "TCP socket configured: TCP_NODELAY=true, buffers={}KB",
        BUFFER_SIZE / 1024
    );

    Ok(())
}

/// Configure UDP socket options for optimal performance.
///
/// This function applies the following optimizations:
/// - **Send buffer**: Set to `buf_size` (or 32MB default) for better burst handling
/// - **Receive buffer**: Set to `buf_size` (or 32MB default) to reduce packet loss
///
/// # Arguments
///
/// * `socket` - The UDP socket to configure
/// * `buf_size` - Buffer size in bytes (0 = use 32MB default)
///
/// # Returns
///
/// Returns `Ok(())` on success, or an `Error` if any socket option fails to set.
///
/// # Performance Impact
///
/// Expected 10-20% improvement in UDP throughput tests with reduced packet loss.
pub fn configure_udp_socket(socket: &UdpSocket, buf_size: usize) -> Result<()> {
    // Default 32MB for high-throughput multi-stream, or use user-specified size
    let bufsz = if buf_size == 0 { 32 * 1024 * 1024 } else { buf_size };
    let sock_ref = SockRef::from(socket);

    sock_ref.set_send_buffer_size(bufsz).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("Failed to set UDP send buffer size: {}", e),
        ))
    })?;

    sock_ref.set_recv_buffer_size(bufsz).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("Failed to set UDP recv buffer size: {}", e),
        ))
    })?;

    debug!(
        "UDP socket configured: buffers={}MB",
        bufsz / (1024 * 1024)
    );

    Ok(())
}

/// Network performance test server.
///
/// The `Server` listens for incoming TCP control connections and handles both TCP and UDP
/// performance test requests. All tests use a TCP control channel for coordination, with
/// UDP data transfer happening on the same port. The server supports reverse mode testing,
/// bandwidth limiting, interval reporting, JSON output, and can handle multiple concurrent clients.
///
/// # Features
///
/// - **TCP Control Channel**: Always uses TCP for client coordination
/// - **TCP and UDP Data**: Handle both reliable (TCP) and unreliable (UDP) performance tests
/// - **Reverse Mode**: Send data to client for reverse throughput testing
/// - **Bandwidth Limiting**: Control send rate in reverse mode tests
/// - **Interval Reporting**: Display periodic statistics during tests
/// - **JSON Output**: Machine-readable output format for automation
/// - **UDP Metrics**: Track packet loss, jitter, and out-of-order delivery
/// - **Concurrent Clients**: Handle multiple simultaneous test connections
///
/// # Examples
///
/// ## Basic TCP Server
///
/// ```no_run
/// use rperf3::{Server, Config};
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = Config::server(5201);
/// let server = Server::new(config);
///
/// println!("Starting server on port 5201...");
/// server.run().await?;
/// # Ok(())
/// # }
/// ```
///
/// ## UDP Server with Reverse Mode
///
/// ```no_run
/// use rperf3::{Server, Config, Protocol};
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = Config::server(5201)
///     .with_protocol(Protocol::Udp)
///     .with_reverse(true); // Server will send UDP data
///
/// let server = Server::new(config);
/// server.run().await?;
/// # Ok(())
/// # }
/// ```
pub struct Server {
    config: Config,
    measurements: MeasurementsCollector,
    tcp_buffer_pool: Arc<BufferPool>,
    udp_buffer_pool: Arc<BufferPool>,
    cancellation_token: CancellationToken,
}

impl Server {
    /// Creates a new server with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The server configuration including port and protocol
    ///
    /// # Examples
    ///
    /// ```
    /// use rperf3::{Server, Config};
    ///
    /// let config = Config::server(5201);
    /// let server = Server::new(config);
    /// ```
    pub fn new(config: Config) -> Self {
        // Create buffer pools for TCP and UDP
        // TCP: use configured buffer size, pool up to 10 buffers per stream
        let tcp_pool_size = config.parallel * 2; // 2 buffers per stream (send + receive)
        let tcp_buffer_pool = Arc::new(BufferPool::new(config.buffer_size, tcp_pool_size));

        // UDP: fixed 65536 bytes (max UDP packet size), pool up to 10 buffers
        let udp_buffer_pool = Arc::new(BufferPool::new(65536, 10));

        Self {
            config,
            measurements: MeasurementsCollector::new(),
            tcp_buffer_pool,
            udp_buffer_pool,
            cancellation_token: CancellationToken::new(),
        }
    }

    /// Returns a reference to the cancellation token.
    ///
    /// This allows external code to cancel the running server gracefully.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rperf3::{Server, Config};
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = Config::server(5201);
    /// let server = Server::new(config);
    ///
    /// // Get cancellation token to stop from another task
    /// let cancel_token = server.cancellation_token().clone();
    ///
    /// tokio::spawn(async move {
    ///     // Server will be running
    /// });
    ///
    /// // Later, to stop the server:
    /// cancel_token.cancel();
    /// # Ok(())
    /// # }
    /// ```
    pub fn cancellation_token(&self) -> &CancellationToken {
        &self.cancellation_token
    }

    /// Starts the server and begins listening for client connections.
    ///
    /// This method will run indefinitely, accepting and handling client connections.
    /// For TCP, each client connection is handled in a separate task. For UDP,
    /// the server processes incoming datagrams.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Cannot bind to the specified port
    /// - Network I/O errors occur
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use rperf3::{Server, Config};
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = Config::server(5201);
    /// let server = Server::new(config);
    ///
    /// println!("Server running...");
    /// server.run().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn run(&self) -> Result<()> {
        let bind_addr = format!(
            "{}:{}",
            self.config
                .bind_addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "0.0.0.0".to_string()),
            self.config.port
        );

        info!("Starting rperf3 server on {}", bind_addr);

        // Server always uses TCP for control connections
        // The protocol config is just for display/logging purposes
        // Both TCP and UDP tests are handled via the TCP control channel
        self.run_tcp(&bind_addr).await
    }

    async fn run_tcp(&self, bind_addr: &str) -> Result<()> {
        let listener = TcpListener::bind(bind_addr).await?;
        info!("TCP server listening on {}", bind_addr);

        loop {
            // Check for cancellation
            if self.cancellation_token.is_cancelled() {
                info!("Server shutting down gracefully");
                break;
            }

            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, addr)) => {
                            info!("New connection from {}", addr);
                            let config = self.config.clone();
                            let measurements = self.measurements.clone();
                            let tcp_buffer_pool = self.tcp_buffer_pool.clone();
                            let udp_buffer_pool = self.udp_buffer_pool.clone();

                            tokio::spawn(async move {
                                if let Err(e) = handle_tcp_client(
                                    stream,
                                    addr,
                                    config,
                                    measurements,
                                    tcp_buffer_pool,
                                    udp_buffer_pool,
                                )
                                .await
                                {
                                    error!("Error handling client {}: {}", addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Error accepting connection: {}", e);
                        }
                    }
                }
                _ = self.cancellation_token.cancelled() => {
                    info!("Server shutting down gracefully");
                    break;
                }
            }
        }
        Ok(())
    }

    #[allow(dead_code)]
    async fn run_udp(&self, bind_addr: &str) -> Result<()> {
        let socket = UdpSocket::bind(bind_addr).await?;
        let local_addr = socket.local_addr()?;

        // Configure UDP socket for optimal performance
        configure_udp_socket(&socket, self.config.socket_buf)?;

        info!("UDP server listening on {}", local_addr);

        // Use batch operations on Linux for better performance
        #[cfg(target_os = "linux")]
        return self.run_udp_batched(socket).await;

        #[cfg(not(target_os = "linux"))]
        return self.run_udp_standard(socket).await;
    }

    /// Standard UDP receive implementation (one packet per system call)
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    async fn run_udp_standard(&self, socket: UdpSocket) -> Result<()> {
        // Create async interval reporter
        let (reporter, receiver) = IntervalReporter::new();
        let reporter_task = tokio::spawn(run_reporter_task(
            receiver,
            self.config.json,
            None, // Server doesn't have callbacks
        ));

        let mut buf = self.udp_buffer_pool.get();
        let start = Instant::now();
        let mut last_interval = start;
        let mut interval_bytes = 0u64;
        let mut interval_packets = 0u64;

        loop {
            // Check for cancellation
            if self.cancellation_token.is_cancelled() {
                info!("Server shutting down gracefully");
                break;
            }

            match socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    debug!("Received {} bytes from {}", len, addr);

                    // Parse UDP packet
                    if let Some((header, _payload)) = crate::udp_packet::parse_packet(&buf[..len]) {
                        // Get current receive timestamp
                        let recv_timestamp_us = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .expect("Time went backwards")
                            .as_micros() as u64;

                        // Record packet with timing information
                        self.measurements.record_udp_packet_received(
                            header.sequence as u64,
                            header.timestamp_us,
                            recv_timestamp_us,
                        );
                        self.measurements.record_bytes_received(0, len as u64);

                        interval_bytes += len as u64;
                        interval_packets += 1;
                    } else {
                        debug!("Received non-rperf3 UDP packet from {}", addr);
                    }

                    // Report interval
                    if last_interval.elapsed() >= self.config.interval {
                        let elapsed = start.elapsed();
                        let interval_duration = last_interval.elapsed();
                        let bps = (interval_bytes as f64 * 8.0) / interval_duration.as_secs_f64();

                        let interval_start = if elapsed > interval_duration {
                            elapsed - interval_duration
                        } else {
                            Duration::ZERO
                        };

                        self.measurements.add_interval(IntervalStats {
                            start: interval_start,
                            end: elapsed,
                            bytes: interval_bytes,
                            bits_per_second: bps,
                            packets: interval_packets,
                        });

                        // Calculate UDP metrics
                        let (lost, expected) = self.measurements.calculate_udp_loss();
                        let loss_percent = if expected > 0 {
                            (lost as f64 / expected as f64) * 100.0
                        } else {
                            0.0
                        };
                        let measurements = self.measurements.get();

                        // Send to reporter task (async, non-blocking)
                        reporter.report(IntervalReport {
                            stream_id: DEFAULT_STREAM_ID,
                            interval_start,
                            interval_end: elapsed,
                            bytes: interval_bytes,
                            bits_per_second: bps,
                            packets: Some(interval_packets),
                            jitter_ms: Some(measurements.jitter_ms),
                            lost_packets: Some(lost),
                            lost_percent: Some(loss_percent),
                            retransmits: None,
                            cwnd: None,
                        });

                        interval_bytes = 0;
                        interval_packets = 0;
                        last_interval = Instant::now();
                    }
                }
                Err(e) => {
                    error!("Error receiving UDP packet: {}", e);
                }
            }
        }

        // Signal reporter completion and wait for it to finish
        reporter.complete();
        let _ = reporter_task.await;

        Ok(())
    }

    /// Batched UDP receive implementation using recvmmsg (Linux only)
    #[allow(dead_code)]
    #[cfg(target_os = "linux")]
    async fn run_udp_batched(&self, socket: UdpSocket) -> Result<()> {
        use crate::batch_socket::UdpRecvBatch;

        // Create async interval reporter
        let (reporter, receiver) = IntervalReporter::new();
        let reporter_task = tokio::spawn(run_reporter_task(
            receiver,
            self.config.json,
            None, // Server doesn't have callbacks
        ));

        let mut batch = UdpRecvBatch::new();
        let start = Instant::now();
        let mut last_interval = start;
        let mut interval_bytes = 0u64;
        let mut interval_packets = 0u64;

        loop {
            // Check for cancellation
            if self.cancellation_token.is_cancelled() {
                info!("Server shutting down gracefully");
                break;
            }

            // Receive a batch of packets
            match batch.recv(&socket).await {
                Ok(count) => {
                    if count == 0 {
                        continue;
                    }

                    debug!("Received {} packets in batch", count);

                    // Process each packet in the batch
                    for i in 0..count {
                        if let Some((packet, addr)) = batch.get(i) {
                            debug!(
                                "Processing packet {} of {} bytes from {}",
                                i,
                                packet.len(),
                                addr
                            );

                            // Parse UDP packet
                            if let Some((header, _payload)) =
                                crate::udp_packet::parse_packet(packet)
                            {
                                // Get current receive timestamp
                                let recv_timestamp_us = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .expect("Time went backwards")
                                    .as_micros()
                                    as u64;

                                // Record packet with timing information
                                self.measurements.record_udp_packet_received(
                                    header.sequence as u64,
                                    header.timestamp_us,
                                    recv_timestamp_us,
                                );
                                self.measurements
                                    .record_bytes_received(0, packet.len() as u64);

                                interval_bytes += packet.len() as u64;
                                interval_packets += 1;
                            } else {
                                debug!("Received non-rperf3 UDP packet from {}", addr);
                            }
                        }
                    }

                    // Report interval
                    if last_interval.elapsed() >= self.config.interval {
                        let elapsed = start.elapsed();
                        let interval_duration = last_interval.elapsed();
                        let bps = (interval_bytes as f64 * 8.0) / interval_duration.as_secs_f64();

                        let interval_start = if elapsed > interval_duration {
                            elapsed - interval_duration
                        } else {
                            Duration::ZERO
                        };

                        self.measurements.add_interval(IntervalStats {
                            start: interval_start,
                            end: elapsed,
                            bytes: interval_bytes,
                            bits_per_second: bps,
                            packets: interval_packets,
                        });

                        // Calculate UDP metrics
                        let (lost, expected) = self.measurements.calculate_udp_loss();
                        let loss_percent = if expected > 0 {
                            (lost as f64 / expected as f64) * 100.0
                        } else {
                            0.0
                        };
                        let measurements = self.measurements.get();

                        // Send to reporter task (async, non-blocking)
                        reporter.report(IntervalReport {
                            stream_id: DEFAULT_STREAM_ID,
                            interval_start,
                            interval_end: elapsed,
                            bytes: interval_bytes,
                            bits_per_second: bps,
                            packets: Some(interval_packets),
                            jitter_ms: Some(measurements.jitter_ms),
                            lost_packets: Some(lost),
                            lost_percent: Some(loss_percent),
                            retransmits: None,
                            cwnd: None,
                        });

                        interval_bytes = 0;
                        interval_packets = 0;
                        last_interval = Instant::now();
                    }
                }
                Err(e) => {
                    error!("Error receiving UDP batch: {}", e);
                }
            }
        }

        // Signal reporter completion and wait for it to finish
        reporter.complete();
        let _ = reporter_task.await;

        Ok(())
    }

    /// Retrieves the current measurements collected by the server.
    ///
    /// Returns a snapshot of the statistics collected from client tests. This
    /// includes total bytes transferred, bandwidth measurements, and UDP-specific
    /// metrics like packet loss and jitter.
    ///
    /// # Returns
    ///
    /// A `Measurements` struct containing comprehensive test statistics.
    ///
    /// # Examples
    ///
    /// ```
    /// use rperf3::{Server, Config};
    ///
    /// let config = Config::server(5201);
    /// let server = Server::new(config);
    ///
    /// // After tests have run
    /// let measurements = server.get_measurements();
    /// println!("Total bytes: {}", measurements.total_bytes_received);
    /// println!("Throughput: {:.2} Mbps",
    ///          measurements.total_bits_per_second() / 1_000_000.0);
    /// ```
    pub fn get_measurements(&self) -> crate::Measurements {
        self.measurements.get()
    }
}

async fn handle_tcp_client(
    mut stream: TcpStream,
    addr: SocketAddr,
    config: Config,
    measurements: MeasurementsCollector,
    tcp_buffer_pool: Arc<BufferPool>,
    udp_buffer_pool: Arc<BufferPool>,
) -> Result<()> {
    // Configure TCP socket options for optimal performance
    configure_tcp_socket(&stream)?;

    // Read setup message
    let setup_msg = deserialize_message(&mut stream).await?;

    let (protocol, duration, reverse, _parallel, bandwidth, buffer_size, one_way, expected_pps) = match setup_msg {
        Message::Setup {
            version: _,
            protocol,
            duration,
            reverse,
            parallel,
            bandwidth,
            buffer_size,
            one_way,
            expected_pps,
        } => {
            info!(
                "Client {} setup: protocol={}, duration={}s, reverse={}, parallel={}, one_way={:?}",
                addr, protocol, duration, reverse, parallel, one_way
            );
            (
                protocol,
                Duration::from_secs(duration),
                reverse,
                parallel,
                bandwidth,
                buffer_size,
                one_way,
                expected_pps,
            )
        }
        _ => {
            return Err(Error::Protocol("Expected Setup message".to_string()));
        }
    };

    // Check if this is UDP mode
    if protocol == "Udp" {
        // Create a config with the client's test parameters
        let mut udp_config = config.clone();
        udp_config.duration = duration;
        udp_config.reverse = reverse;
        udp_config.bandwidth = bandwidth;
        udp_config.buffer_size = buffer_size;
        udp_config.one_way = match one_way.as_deref() {
            Some("send") => OneWayMode::Send,
            Some("receive") => OneWayMode::Receive,
            _ => OneWayMode::None,
        };
        udp_config.expected_pps = expected_pps;

        // Handle UDP test via control channel
        return handle_udp_test(stream, addr, udp_config, measurements, udp_buffer_pool).await;
    }

    // Send setup acknowledgment for TCP
    let ack = Message::setup_ack(config.port, format!("{}", addr));
    let ack_bytes = serialize_message(&ack)?;
    stream.write_all(&ack_bytes).await?;
    stream.flush().await?;

    // Send start signal
    let start_msg = Message::start(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    );
    let start_bytes = serialize_message(&start_msg)?;
    stream.write_all(&start_bytes).await?;
    stream.flush().await?;

    measurements.set_start_time(Instant::now());

    if reverse {
        // Server sends data to client
        send_data(
            &mut stream,
            0,
            duration,
            bandwidth,
            &measurements,
            &config,
            tcp_buffer_pool.clone(),
        )
        .await?;
    } else {
        // Server receives data from client
        receive_data(
            &mut stream,
            0,
            duration,
            &measurements,
            &config,
            tcp_buffer_pool.clone(),
        )
        .await?;
    }

    // Send final results
    let final_measurements = measurements.get();
    if let Some(stream_stats) = final_measurements.streams.first() {
        let result_msg = Message::result(
            0,
            stream_stats.bytes_sent,
            stream_stats.bytes_received,
            final_measurements.total_duration.as_secs_f64(),
            final_measurements.total_bits_per_second(),
            None,
        );
        let result_bytes = serialize_message(&result_msg)?;
        stream.write_all(&result_bytes).await?;
        stream.flush().await?;
    }

    // Send done signal
    let done_msg = Message::done();
    let done_bytes = serialize_message(&done_msg)?;
    stream.write_all(&done_bytes).await?;
    stream.flush().await?;

    info!(
        "Test completed for {}: {:.2} Mbps",
        addr,
        final_measurements.total_bits_per_second() / 1_000_000.0
    );

    Ok(())
}

async fn handle_udp_test(
    mut control_stream: TcpStream,
    client_addr: SocketAddr,
    config: Config,
    measurements: MeasurementsCollector,
    udp_buffer_pool: Arc<BufferPool>,
) -> Result<()> {
    let duration = config.duration;
    let reverse = config.reverse;
    let bandwidth = config.bandwidth;
    let buffer_size = config.buffer_size;
    // Send setup acknowledgment
    let ack = Message::setup_ack(config.port, format!("{}", client_addr));
    let ack_bytes = serialize_message(&ack)?;
    control_stream.write_all(&ack_bytes).await?;
    control_stream.flush().await?;

    // Send start signal
    let start_msg = Message::start(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    );
    let start_bytes = serialize_message(&start_msg)?;
    control_stream.write_all(&start_bytes).await?;
    control_stream.flush().await?;

    measurements.set_start_time(Instant::now());

    if config.one_way == OneWayMode::Send {
        // One-way send mode: client sends, server receives only
        info!("handle_udp_test: one_way=Send, binding UDP port {}", config.port);
        let bind_addr = format!("0.0.0.0:{}", config.port);
        let socket = UdpSocket::bind(&bind_addr).await?;
        configure_udp_socket(&socket, config.socket_buf)?;

        // Single socket receives from all parallel client streams (they all send to same port)
        let stats = recv_one_way_server(
            &socket,
            duration,
            config.expected_pps,
            config.buffer_size,
            config.recv_workers,
        )
        .await?;
        info!("recv_one_way_server returned: bytes={}, packets={}",
              stats.bytes_received, stats.packets_received);
        let stream_info = if config.parallel > 1 {
            format!(" ({} streams)", config.parallel)
        } else {
            String::new()
        };
        println!("One-way send mode stats{}: bytes={}, packets={}, out_of_order={}, lost={}, loss={:.2}%",
            stream_info,
            stats.bytes_received, stats.packets_received, stats.out_of_order, stats.packets_lost, stats.packet_loss.unwrap_or(0.0));
    } else if config.one_way == OneWayMode::Receive {
        // One-way receive mode: server sends, client receives only
        send_udp_data(
            client_addr,
            duration,
            bandwidth,
            buffer_size,
            &measurements,
            &config,
            udp_buffer_pool.clone(),
        )
        .await?;
    } else if reverse {
        // Server sends UDP data to client
        send_udp_data(
            client_addr,
            duration,
            bandwidth,
            buffer_size,
            &measurements,
            &config,
            udp_buffer_pool.clone(),
        )
        .await?;
    } else {
        // Server receives UDP data from client
        receive_udp_data(duration, &measurements, &config, udp_buffer_pool.clone()).await?;
    }

    info!(
        "UDP test completed for {}: {:.2} Mbps",
        client_addr,
        measurements.get().total_bits_per_second() / 1_000_000.0
    );

    Ok(())
}

async fn send_udp_data(
    _client_tcp_addr: SocketAddr,
    duration: Duration,
    bandwidth: Option<u64>,
    buffer_size: usize,
    measurements: &MeasurementsCollector,
    config: &Config,
    buffer_pool: Arc<BufferPool>,
) -> Result<()> {
    // Create async interval reporter
    let (reporter, receiver) = IntervalReporter::new();
    let reporter_task = tokio::spawn(run_reporter_task(
        receiver,
        config.json,
        None, // Server doesn't have callbacks
    ));

    // Bind to the server's configured port for UDP
    let bind_addr = format!("0.0.0.0:{}", config.port);
    let socket = UdpSocket::bind(&bind_addr).await?;

    // Configure UDP socket for optimal performance
    configure_udp_socket(&socket, config.socket_buf)?;

    info!("UDP server listening on port {}", config.port);

    // Wait for first packet from client to discover their UDP port
    let mut buf = buffer_pool.get();
    let (_n, client_udp_addr) = socket.recv_from(&mut buf).await?;

    info!("UDP client address discovered: {}", client_udp_addr);

    // Now connect to client's UDP address
    socket.connect(client_udp_addr).await?;

    let start = Instant::now();
    let mut last_interval = start;
    let mut interval_bytes = 0u64;
    let mut interval_packets = 0u64;
    let mut sequence = 0u32;

    // Calculate payload size accounting for UDP packet header
    let payload_size = if buffer_size > crate::udp_packet::UdpPacketHeader::SIZE {
        buffer_size - crate::udp_packet::UdpPacketHeader::SIZE
    } else {
        1024
    };

    // Bandwidth limiting
    let target_bytes_per_sec = bandwidth.map(|bw| bw / 8);
    let mut total_bytes_sent = 0u64;
    let mut last_bandwidth_check = start;

    while start.elapsed() < duration {
        let packet = crate::udp_packet::create_packet_fast(0, sequence, payload_size);

        match socket.send(&packet).await {
            Ok(n) => {
                measurements.record_bytes_sent(0, n as u64);
                measurements.record_udp_packet(0);
                interval_bytes += n as u64;
                interval_packets += 1;
                sequence += 1;
                total_bytes_sent += n as u64;

                // Bandwidth limiting
                if let Some(target_bps) = target_bytes_per_sec {
                    let elapsed = last_bandwidth_check.elapsed().as_secs_f64();

                    if elapsed >= 0.001 {
                        let expected_bytes = (target_bps as f64 * elapsed) as u64;
                        let bytes_sent_in_period = total_bytes_sent;

                        if bytes_sent_in_period > expected_bytes {
                            let bytes_ahead = (bytes_sent_in_period - expected_bytes) as f64;
                            let sleep_time = bytes_ahead / target_bps as f64;
                            if sleep_time > 0.0001 {
                                time::sleep(Duration::from_secs_f64(sleep_time)).await;
                            }
                        }

                        last_bandwidth_check = Instant::now();
                        total_bytes_sent = 0;
                    }
                }

                // Report interval
                if last_interval.elapsed() >= config.interval {
                    let elapsed = start.elapsed();
                    let interval_duration = last_interval.elapsed();
                    let bps = (interval_bytes as f64 * 8.0) / interval_duration.as_secs_f64();

                    let interval_start = if elapsed > interval_duration {
                        elapsed - interval_duration
                    } else {
                        Duration::ZERO
                    };

                    measurements.add_interval(IntervalStats {
                        start: interval_start,
                        end: elapsed,
                        bytes: interval_bytes,
                        bits_per_second: bps,
                        packets: interval_packets,
                    });

                    // Send to reporter task (async, non-blocking)
                    reporter.report(IntervalReport {
                        stream_id: DEFAULT_STREAM_ID,
                        interval_start,
                        interval_end: elapsed,
                        bytes: interval_bytes,
                        bits_per_second: bps,
                        packets: Some(interval_packets),
                        jitter_ms: None,
                        lost_packets: None,
                        lost_percent: None,
                        retransmits: None,
                        cwnd: None,
                    });

                    interval_bytes = 0;
                    interval_packets = 0;
                    last_interval = Instant::now();
                }
            }
            Err(e) => {
                error!("Error sending UDP packet: {}", e);
                break;
            }
        }
    }

    // Signal reporter completion and wait for it to finish
    reporter.complete();
    let _ = reporter_task.await;

    measurements.set_duration(start.elapsed());
    Ok(())
}

async fn receive_udp_data(
    duration: Duration,
    measurements: &MeasurementsCollector,
    config: &Config,
    buffer_pool: Arc<BufferPool>,
) -> Result<()> {
    // Create async interval reporter
    let (reporter, receiver) = IntervalReporter::new();
    let reporter_task = tokio::spawn(run_reporter_task(
        receiver,
        config.json,
        None, // Server doesn't have callbacks
    ));

    // Bind UDP socket on the server port
    let bind_addr = format!("0.0.0.0:{}", config.port);
    let socket = UdpSocket::bind(&bind_addr).await?;

    // Configure UDP socket for optimal performance
    configure_udp_socket(&socket, config.socket_buf)?;

    info!("UDP server listening for packets on port {}", config.port);

    let start = Instant::now();
    let mut last_interval = start;
    let mut interval_bytes = 0u64;
    let mut interval_packets = 0u64;
    let mut buf = buffer_pool.get();

    // Receive packets until duration expires or timeout
    while start.elapsed() < duration {
        // Set a timeout so we can check elapsed time
        let remaining = duration.saturating_sub(start.elapsed());
        let timeout = remaining.min(Duration::from_millis(100));

        match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _addr))) => {
                // Parse UDP packet
                if let Some((header, _payload)) = crate::udp_packet::parse_packet(&buf[..n]) {
                    let recv_timestamp_us = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_micros() as u64;

                    measurements.record_bytes_received(0, n as u64);
                    measurements.record_udp_packet_received(
                        header.sequence as u64,
                        header.timestamp_us,
                        recv_timestamp_us,
                    );

                    interval_bytes += n as u64;
                    interval_packets += 1;
                }

                // Report interval
                if last_interval.elapsed() >= config.interval {
                    let elapsed = start.elapsed();
                    let interval_duration = last_interval.elapsed();
                    let bps = (interval_bytes as f64 * 8.0) / interval_duration.as_secs_f64();

                    let interval_start = if elapsed > interval_duration {
                        elapsed - interval_duration
                    } else {
                        Duration::ZERO
                    };

                    // Get UDP stats from measurements
                    let stats = measurements.get();
                    let jitter = if stats.jitter_ms > 0.0 {
                        Some(stats.jitter_ms)
                    } else {
                        None
                    };
                    let lost = stats.lost_packets;
                    let total = stats.total_packets;
                    let lost_percent = if total > 0 && lost > 0 {
                        Some((lost as f64 / total as f64) * 100.0)
                    } else {
                        None
                    };

                    measurements.add_interval(IntervalStats {
                        start: interval_start,
                        end: elapsed,
                        bytes: interval_bytes,
                        bits_per_second: bps,
                        packets: interval_packets,
                    });

                    // Send to reporter task (async, non-blocking)
                    reporter.report(IntervalReport {
                        stream_id: DEFAULT_STREAM_ID,
                        interval_start,
                        interval_end: elapsed,
                        bytes: interval_bytes,
                        bits_per_second: bps,
                        packets: Some(interval_packets),
                        jitter_ms: jitter,
                        lost_packets: if lost > 0 { Some(lost) } else { None },
                        lost_percent,
                        retransmits: None,
                        cwnd: None,
                    });

                    interval_bytes = 0;
                    interval_packets = 0;
                    last_interval = Instant::now();
                }
            }
            Ok(Err(e)) => {
                error!("Error receiving UDP packet: {}", e);
                break;
            }
            Err(_) => {
                // Timeout - continue to check if duration expired
                continue;
            }
        }
    }

    // Signal reporter completion and wait for it to finish
    reporter.complete();
    let _ = reporter_task.await;

    measurements.set_duration(start.elapsed());
    Ok(())
}

async fn send_data(
    stream: &mut TcpStream,
    stream_id: usize,
    duration: Duration,
    bandwidth: Option<u64>,
    measurements: &MeasurementsCollector,
    config: &Config,
    buffer_pool: Arc<BufferPool>,
) -> Result<()> {
    // Create async interval reporter
    let (reporter, receiver) = IntervalReporter::new();
    let reporter_task = tokio::spawn(run_reporter_task(
        receiver,
        config.json,
        None, // Server doesn't have callbacks
    ));

    let buffer = buffer_pool.get();
    let start = Instant::now();
    let mut last_interval = start;
    let mut interval_bytes = 0u64;
    let mut last_retransmits = 0u64;

    // Bandwidth limiting
    let target_bytes_per_sec = bandwidth.map(|bw| bw / 8);
    let mut total_bytes_sent = 0u64;
    let mut last_bandwidth_check = start;

    while start.elapsed() < duration {
        match stream.write(&buffer).await {
            Ok(n) => {
                measurements.record_bytes_sent(stream_id, n as u64);
                interval_bytes += n as u64;
                total_bytes_sent += n as u64;

                // Bandwidth limiting
                if let Some(target_bps) = target_bytes_per_sec {
                    let elapsed = last_bandwidth_check.elapsed().as_secs_f64();

                    if elapsed >= 0.001 {
                        let expected_bytes = (target_bps as f64 * elapsed) as u64;
                        let bytes_sent_in_period = total_bytes_sent;

                        if bytes_sent_in_period > expected_bytes {
                            let bytes_ahead = (bytes_sent_in_period - expected_bytes) as f64;
                            let sleep_time = bytes_ahead / target_bps as f64;
                            if sleep_time > 0.0001 {
                                time::sleep(Duration::from_secs_f64(sleep_time)).await;
                            }
                        }

                        last_bandwidth_check = Instant::now();
                        total_bytes_sent = 0;
                    }
                }

                // Report interval
                if last_interval.elapsed() >= config.interval {
                    let elapsed = start.elapsed();
                    let interval_duration = last_interval.elapsed();
                    let bps = (interval_bytes as f64 * 8.0) / interval_duration.as_secs_f64();

                    let interval_start = if elapsed > interval_duration {
                        elapsed - interval_duration
                    } else {
                        Duration::ZERO
                    };

                    // Get TCP stats for retransmits
                    let tcp_stats = get_tcp_stats(stream).ok();
                    let current_retransmits =
                        tcp_stats.as_ref().map(|s| s.retransmits).unwrap_or(0);
                    let interval_retransmits = current_retransmits.saturating_sub(last_retransmits);
                    last_retransmits = current_retransmits;

                    measurements.add_interval(IntervalStats {
                        start: interval_start,
                        end: elapsed,
                        bytes: interval_bytes,
                        bits_per_second: bps,
                        packets: u64::MAX,
                    });

                    // Get congestion window for reporting
                    let cwnd_kbytes = tcp_stats
                        .as_ref()
                        .and_then(|s| s.snd_cwnd_opt())
                        .map(|cwnd| cwnd / 1024);

                    // Send to reporter task (async, non-blocking)
                    reporter.report(IntervalReport {
                        stream_id: DEFAULT_STREAM_ID,
                        interval_start,
                        interval_end: elapsed,
                        bytes: interval_bytes,
                        bits_per_second: bps,
                        packets: None,
                        jitter_ms: None,
                        lost_packets: None,
                        lost_percent: None,
                        retransmits: if interval_retransmits > 0 {
                            Some(interval_retransmits)
                        } else {
                            None
                        },
                        cwnd: cwnd_kbytes,
                    });

                    interval_bytes = 0;
                    last_interval = Instant::now();
                }
            }
            Err(e) => {
                error!("Error sending data: {}", e);
                break;
            }
        }
    }

    // Signal reporter completion and wait for it to finish
    reporter.complete();
    let _ = reporter_task.await;

    measurements.set_duration(start.elapsed());
    stream.flush().await?;

    Ok(())
}

async fn receive_data(
    stream: &mut TcpStream,
    stream_id: usize,
    duration: Duration,
    measurements: &MeasurementsCollector,
    config: &Config,
    buffer_pool: Arc<BufferPool>,
) -> Result<()> {
    // Create async interval reporter
    let (reporter, receiver) = IntervalReporter::new();
    let reporter_task = tokio::spawn(run_reporter_task(
        receiver,
        config.json,
        None, // Server doesn't have callbacks
    ));

    let mut buffer = buffer_pool.get();
    let start = Instant::now();
    let mut last_interval = start;
    let mut interval_bytes = 0u64;
    let mut last_retransmits = 0u64;

    while start.elapsed() < duration {
        match time::timeout(Duration::from_millis(100), stream.read(&mut buffer)).await {
            Ok(Ok(0)) => {
                // Connection closed
                break;
            }
            Ok(Ok(n)) => {
                measurements.record_bytes_received(stream_id, n as u64);
                interval_bytes += n as u64;

                // Report interval
                if last_interval.elapsed() >= config.interval {
                    let elapsed = start.elapsed();
                    let interval_duration = last_interval.elapsed();
                    let bps = (interval_bytes as f64 * 8.0) / interval_duration.as_secs_f64();

                    let interval_start = if elapsed > interval_duration {
                        elapsed - interval_duration
                    } else {
                        Duration::ZERO
                    };

                    // Get TCP stats for retransmits
                    let tcp_stats = get_tcp_stats(stream).ok();
                    let current_retransmits =
                        tcp_stats.as_ref().map(|s| s.retransmits).unwrap_or(0);
                    let interval_retransmits = current_retransmits.saturating_sub(last_retransmits);
                    last_retransmits = current_retransmits;

                    measurements.add_interval(IntervalStats {
                        start: interval_start,
                        end: elapsed,
                        bytes: interval_bytes,
                        bits_per_second: bps,
                        packets: u64::MAX,
                    });

                    // Send to reporter task (async, non-blocking)
                    reporter.report(IntervalReport {
                        stream_id: DEFAULT_STREAM_ID,
                        interval_start,
                        interval_end: elapsed,
                        bytes: interval_bytes,
                        bits_per_second: bps,
                        packets: None,
                        jitter_ms: None,
                        lost_packets: None,
                        lost_percent: None,
                        retransmits: if interval_retransmits > 0 {
                            Some(interval_retransmits)
                        } else {
                            None
                        },
                        cwnd: None,
                    });

                    interval_bytes = 0;
                    last_interval = Instant::now();
                }
            }
            Ok(Err(e)) => {
                error!("Error receiving data: {}", e);
                break;
            }
            Err(_) => {
                // Timeout, check if duration expired
                if start.elapsed() >= duration {
                    break;
                }
            }
        }
    }

    // Signal reporter completion and wait for it to finish
    reporter.complete();
    let _ = reporter_task.await;

    measurements.set_duration(start.elapsed());

    Ok(())
}

/// One-way receive statistics on server side.
///
/// Collects statistics when the server receives data in one-way send mode,
/// including packet loss calculation based on expected PPS.
pub async fn recv_one_way_server(
    socket: &UdpSocket,
    duration: Duration,
    _expected_pps: Option<u64>,
    buffer_size: usize,
    recv_workers: usize,
) -> Result<ServerOneWayStats> {
    #[cfg(target_os = "linux")]
    {
        if recv_workers > 1 {
            recv_one_way_server_mt_tokio(socket, duration, buffer_size, recv_workers).await
        } else {
            recv_one_way_server_with_socket(socket, duration, buffer_size).await
        }
    }
    #[cfg(target_os = "windows")]
    {
        if recv_workers > 1 {
            recv_one_way_server_mt_windows(socket, duration, buffer_size, recv_workers).await
        } else {
            recv_one_way_server_with_socket(socket, duration, buffer_size).await
        }
    }
    #[cfg(target_os = "macos")]
    {
        recv_one_way_server_with_socket(socket, duration, buffer_size).await
    }
}

/// Internal version that takes an extra port parameter for multi-stream reception.
pub async fn recv_one_way_server_multi(
    socket: &UdpSocket,
    duration: Duration,
    buffer_size: usize,
    extra_ports: &[u16],
    port: u16,
) -> Result<ServerOneWayStats> {
    let start = Instant::now();
    let test_end = start + duration;

    info!("recv_one_way_server_multi: starting, duration={:?}, buffer_size={}, extra_ports={:?}",
          duration, buffer_size, extra_ports);

    // Track stats with atomics for safe concurrent access
    let bytes_received = Arc::new(AtomicU64::new(0));
    let packets_received = Arc::new(AtomicU64::new(0));
    let out_of_order = Arc::new(AtomicU64::new(0));
    let packets_lost = Arc::new(AtomicU64::new(0));

    // Shared buffer for all receivers
    let buffer_size_clone = buffer_size;

    // Spawn a receiver task for each port (main socket + extra ports)
    let mut handles = Vec::new();

    /// Helper to build receiver closure with its OWN expected_seq (not shared across ports)
        let make_receiver = |sock: UdpSocket, port: u16| {
            let bytes_rx = bytes_received.clone();
            let packets_rx = packets_received.clone();
            let ooo = out_of_order.clone();
            let lost = packets_lost.clone();
            let bs = buffer_size_clone;
            let end = test_end;

            tokio::spawn(async move {
                recv_one_way_receiver(&sock, end, bs, bytes_rx, packets_rx, ooo, lost).await
            })
        };

    // Main socket receiver — rebind to same port (os will reuse due to SO_REUSEPORT or close first)
    let main_port = port;
    drop(socket); // release reference so we can rebind
    let main_addr = format!("0.0.0.0:{}", main_port);
    let main_socket = UdpSocket::bind(&main_addr).await?;
    handles.push(make_receiver(main_socket, main_port));

    // Extra port receivers
    for &port in extra_ports {
        let local_addr = format!("0.0.0.0:{}", port);
        match UdpSocket::bind(&local_addr).await {
            Ok(sock) => {
                handles.push(make_receiver(sock, port));
            }
            Err(e) => {
                error!("Failed to bind extra port {}: {}", port, e);
            }
        }
    }

    // Wait for all receivers to complete
    let mut join_set = JoinSet::new();
    for (i, handle) in handles.into_iter().enumerate() {
        join_set.spawn(async move { (i, handle.await) });
    }
    let mut total_bytes: u64 = 0;
    let mut total_packets: u64 = 0;
    let mut total_lost: u64 = 0;
    let mut total_ooo: u64 = 0;
    let mut first_err: Option<String> = None;
    while let Some(result) = join_set.join_next().await {
        match result {
            Ok((i, Ok(_stats))) => {
                // Each stream's stats are accumulated in the atomic counters
            }
            Ok((i, Err(e))) => {
                let msg = format!("Receiver {} error: {}", i, e);
                error!("{}", msg);
                if first_err.is_none() { first_err = Some(msg); }
            }
            Err(e) => {
                let msg = format!("Receiver panicked: {:?}", e);
                error!("{}", msg);
                if first_err.is_none() { first_err = Some(msg); }
            }
        }
    }

    // Read final totals from atomic counters
    total_bytes = bytes_received.load(Ordering::SeqCst);
    total_packets = packets_received.load(Ordering::SeqCst);
    total_lost = packets_lost.load(Ordering::SeqCst);
    total_ooo = out_of_order.load(Ordering::SeqCst);

    let total_sent = total_packets + total_lost;
    let packet_loss = if total_sent > 0 {
        Some((total_lost as f64 / total_sent as f64) * 100.0)
    } else {
        None
    };

    let final_rate_gbps = if start.elapsed().as_secs_f64() > 0.0 {
        (total_bytes as f64 * 8.0) / (start.elapsed().as_secs_f64() * 1e9)
    } else {
        0.0
    };
    let loss_str = match packet_loss {
        Some(loss) => format!(", lost={}, loss={:.2}%", total_lost, loss),
        None => String::new(),
    };
    println!(
        "[{:.1}s] recv rate: {:.3} Gbps, total packets={}, bytes={}, out_of_order={}{}",
        start.elapsed().as_secs_f64(),
        final_rate_gbps,
        total_packets,
        total_bytes,
        total_ooo,
        loss_str
    );
    info!("recv_one_way_server_multi finished: bytes={}, packets={}", total_bytes, total_packets);

    Ok(ServerOneWayStats {
        bytes_received: total_bytes,
        packets_received: total_packets,
        out_of_order: total_ooo,
        packets_lost: total_lost,
        packet_loss,
        duration: start.elapsed(),
    })
}

/// Single UDP receiver that fills stats into shared atomics.
async fn recv_one_way_receiver(
    socket: &UdpSocket,
    test_end: Instant,
    buffer_size: usize,
    bytes_received: Arc<AtomicU64>,
    packets_received: Arc<AtomicU64>,
    out_of_order: Arc<AtomicU64>,
    packets_lost: Arc<AtomicU64>,
) {
    let mut buf = vec![0u8; buffer_size];
    let mut expected_seq: u32 = 0;

    loop {
        let now = Instant::now();
        if now >= test_end {
            break;
        }
        let remaining = test_end - now;
        let timeout_duration = std::cmp::min(remaining, Duration::from_millis(100));

        let recv_result = tokio::time::timeout(timeout_duration, socket.recv_from(&mut buf)).await;

        if now >= test_end {
            break;
        }

        match recv_result {
            Ok(Ok((n, _))) => {
                bytes_received.fetch_add(n as u64, Ordering::SeqCst);
                packets_received.fetch_add(1, Ordering::SeqCst);

                if n >= 8 {
                    // Client writes: bytes[0..4]=sequence, bytes[4..8]=stream_id
                    let seq = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                    let _stream_id = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

                    // Initialize lowest seen seq on first packet
                    if seq > expected_seq {
                        // Gap = lost packets
                        let gap = (seq as u64 - expected_seq as u64) as u64;
                        packets_lost.fetch_add(gap, Ordering::SeqCst);
                        expected_seq = seq.wrapping_add(1);
                    } else if seq < expected_seq {
                        // Out-of-order
                        out_of_order.fetch_add(1, Ordering::SeqCst);
                    } else {
                        expected_seq = expected_seq.wrapping_add(1);
                    }
                }
            }
            Ok(Err(e)) => {
                error!("Receive error on socket: {}", e);
            }
            Err(_) => {
                // Timeout — just loop
            }
        }
    }
}

/// Per-stream state for tracking sequence numbers in multi-stream mode.
struct StreamState {
    expected_seq: u32,
}

impl StreamState {
    fn new(initial_seq: u32) -> Self {
        Self {
            expected_seq: initial_seq,
        }
    }
}

/// Internal single-socket receiver (refactored out for clarity).
async fn recv_one_way_server_with_socket(
    socket: &UdpSocket,
    duration: Duration,
    buffer_size: usize,
) -> Result<ServerOneWayStats> {
    let start = Instant::now();
    let test_end = start + duration;
    info!("recv_one_way_server: starting, duration={:?}, buffer_size={}", duration, buffer_size);
    let mut bytes_received: u64 = 0;
    let mut packets_received: u64 = 0;
    let mut out_of_order: u64 = 0;
    let mut packets_lost: u64 = 0;

    // Per-stream state for sequence tracking (supports multiple parallel streams)
    let mut stream_states: HashMap<u32, StreamState> = HashMap::new();

    // Per-interval tracking for rate calculation
    let mut interval_bytes: u64 = 0;
    let mut interval_start = start;
    let mut prev_interval_end = start;

    let mut buf = vec![0u8; buffer_size];

    loop {
        let now = Instant::now();
        if now >= test_end {
            break;
        }
        // Sleep until test ends or next tick
        let remaining = test_end - now;
        let timeout_duration = std::cmp::min(remaining, Duration::from_secs(1));

        let recv_result = tokio::time::timeout(timeout_duration, socket.recv_from(&mut buf)).await;

        let current = Instant::now();

        // Print interval stats if 1 second has passed
        if current - prev_interval_end >= Duration::from_secs(1) {
            let elapsed = interval_start.elapsed().as_secs_f64();
            let rate_gbps = (interval_bytes as f64 * 8.0) / (elapsed * 1e9);
            let total_sent = packets_received + packets_lost;
            let loss_pct = if total_sent > 0 {
                (packets_lost as f64 / total_sent as f64) * 100.0
            } else {
                0.0
            };

            println!(
                "[{:.1}s] recv rate: {:.3} Gbps, packets={}, bytes={}, lost={}, loss={:.2}%",
                current.saturating_duration_since(start).as_secs_f64(),
                rate_gbps,
                packets_received,
                bytes_received,
                packets_lost,
                loss_pct
            );

            interval_bytes = 0;
            interval_start = current;
            prev_interval_end = current;
        }

        match recv_result {
            Ok(Ok((n, _))) => {
                bytes_received += n as u64;
                interval_bytes += n as u64;
                packets_received += 1;

                // Parse sequence number for loss/out-of-order detection
                if n >= 8 {
                    // Client writes: bytes[0..4]=sequence, bytes[4..8]=stream_id
                    let seq = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                    let stream_id = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

                    // Get or create per-stream state
                    let stream_state = stream_states
                        .entry(stream_id)
                        .or_insert_with(|| StreamState::new(seq));

                    if seq > stream_state.expected_seq {
                        // Gap detected: packets were lost
                        packets_lost += (seq - stream_state.expected_seq) as u64;
                        stream_state.expected_seq = seq.wrapping_add(1);
                    } else if seq < stream_state.expected_seq {
                        // Out-of-order or late packet
                        out_of_order += 1;
                    } else {
                        stream_state.expected_seq = stream_state.expected_seq.wrapping_add(1);
                    }
                }
            }
            Ok(Err(e)) => {
                error!("Receive error: {}", e);
                return Err(Error::Io(e));
            }
            Err(_) => {
                // Timeout, no data received this second — continue to print stats next tick
            }
        }
    }

    // Calculate packet loss based on sequence number gaps
    let total_sent = packets_received + packets_lost;
    let packet_loss = if total_sent > 0 {
        Some((packets_lost as f64 / total_sent as f64) * 100.0)
    } else {
        None
    };

    // Print final summary
    let total_elapsed = start.elapsed().as_secs_f64();
    let final_rate_gbps = (bytes_received as f64 * 8.0) / (total_elapsed * 1e9);
    let loss_str = match packet_loss {
        Some(loss) => format!(", lost={}, loss={:.2}%", packets_lost, loss),
        None => String::new(),
    };
    println!(
        "[{:.1}s] recv rate: {:.3} Gbps, total packets={}, bytes={}, out_of_order={}{}",
        total_elapsed,
        final_rate_gbps,
        packets_received,
        bytes_received,
        out_of_order,
        loss_str
    );
    info!("recv_one_way_server: finished after {:?}, bytes={}, packets={}",
          start.elapsed(), bytes_received, packets_received);

    Ok(ServerOneWayStats {
        bytes_received,
        packets_received,
        out_of_order,
        packets_lost,
        packet_loss,
        duration: start.elapsed(),
    })
}

// ============================================================================
// Multi-threaded UDP receiver (tokio socket fd duplicated to native threads)
// ============================================================================

/// Multi-threaded UDP receiver using tokio socket fd duplication.
/// Each worker thread gets a duplicated fd of the same tokio UdpSocket.
#[cfg(target_os = "linux")]
async fn recv_one_way_server_mt_tokio(
    socket: &UdpSocket,
    duration: Duration,
    buffer_size: usize,
    num_workers: usize,
) -> Result<ServerOneWayStats> {
    info!("recv_one_way_server_mt_tokio: starting, duration={:?}, workers={}",
          duration, num_workers);

    let socket_fd = socket.as_raw_fd();

    let mut worker_fds: Vec<i32> = Vec::with_capacity(num_workers);
    for i in 0..num_workers {
        let dup_fd = unsafe { libc::dup(socket_fd) };
        if dup_fd < 0 {
            error!("Worker {}: dup fd failed: {}", i, std::io::Error::last_os_error());
            continue;
        }
        worker_fds.push(dup_fd);
    }
    if worker_fds.is_empty() {
        return Err(Error::Io(std::io::Error::new(std::io::ErrorKind::Other, "no fds")));
    }

    let bytes_received = Arc::new(AtomicU64::new(0));
    let packets_received = Arc::new(AtomicU64::new(0));
    let (tx, rx) = std::sync::mpsc::channel();
    let running = Arc::new(AtomicBool::new(true));

    let start = Instant::now();
    let test_end = start + duration;

    // Each worker: native blocking recv + local state + channel report
    let mut handles = Vec::new();
    for fd in worker_fds {
        let bytes_rx = bytes_received.clone();
        let packets_rx = packets_received.clone();
        let running_flag = running.clone();
        let tx = tx.clone();

        let handle = thread::spawn(move || {
            let mut buf = vec![0u8; buffer_size];
            let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            let mut addr_len: libc::socklen_t = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

            // Per-worker local state: no locking needed
            let mut local_states: HashMap<u32, StreamState> = HashMap::new();
            let mut local_bytes: u64 = 0;
            let mut local_packets: u64 = 0;
            let mut last_report = std::time::Instant::now();
            let report_interval = Duration::from_millis(200);

            while running_flag.load(Ordering::SeqCst) {
                let ret = unsafe {
                    libc::recvfrom(
                        fd,
                        buf.as_mut_ptr() as *mut _,
                        buf.len(),
                        0,
                        &mut addr as *mut _ as *mut _,
                        &mut addr_len,
                    )
                };

                if ret < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        continue;
                    }
                    continue;
                }

                let n = ret as usize;
                local_bytes += n as u64;
                local_packets += 1;

                // Per-stream sequence tracking (local to this worker, no locking)
                if n >= 8 {
                    let seq = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                    let stream_id = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

                    let state = local_states
                        .entry(stream_id)
                        .or_insert_with(|| StreamState::new(seq));

                    if seq > state.expected_seq {
                        state.expected_seq = seq.wrapping_add(1);
                    } else if seq < state.expected_seq {
                        // Out-of-order: ignore in local tracking
                    } else {
                        state.expected_seq = state.expected_seq.wrapping_add(1);
                    }
                }

                // Periodically sync to shared atomics so interval stats stay accurate
                let now = std::time::Instant::now();
                if now.duration_since(last_report) >= report_interval {
                    bytes_rx.fetch_add(local_bytes, Ordering::Relaxed);
                    packets_rx.fetch_add(local_packets, Ordering::Relaxed);
                    local_bytes = 0;
                    local_packets = 0;
                    last_report = now;
                }
            }

            // Final sync + report to main thread
            bytes_rx.fetch_add(local_bytes, Ordering::Relaxed);
            packets_rx.fetch_add(local_packets, Ordering::Relaxed);
            let _ = tx.send((local_bytes, local_packets));
            unsafe { libc::close(fd); }
        });
        handles.push(handle);
    }

    // Interval stats
    let mut prev_interval_end = start;
    let mut prev_total_bytes: u64 = 0;

    loop {
        let now = Instant::now();
        if now >= test_end {
            break;
        }
        let remaining = test_end - now;
        let sleep_dur = std::cmp::min(remaining, Duration::from_secs(1));
        tokio::time::sleep(sleep_dur).await;

        let current = Instant::now();
        if current >= test_end {
            break;
        }

        let current_total = bytes_received.load(Ordering::SeqCst);
        let current_pkts = packets_received.load(Ordering::SeqCst);

        if current.saturating_duration_since(prev_interval_end).as_secs_f64() >= 0.9 {
            let elapsed = current.saturating_duration_since(start).as_secs_f64();
            let interval_b = current_total.wrapping_sub(prev_total_bytes);
            let interval_elapsed = current.saturating_duration_since(prev_interval_end).as_secs_f64();
            let rate_gbps = if interval_elapsed > 0.0 {
                (interval_b as f64 * 8.0) / (interval_elapsed * 1e9)
            } else {
                0.0
            };

            println!(
                "[{:.1}s] recv rate: {:.3} Gbps, packets={}, bytes={}",
                elapsed, rate_gbps, current_pkts, current_total
            );

            prev_total_bytes = current_total;
            prev_interval_end = current;
        }
    }

    running.store(false, Ordering::SeqCst);
    thread::sleep(Duration::from_millis(200));

    // Drain worker results
    let mut total_worker_bytes: u64 = 0;
    let mut total_worker_packets: u64 = 0;
    while let Ok((w_bytes, w_pkts)) = rx.recv_timeout(Duration::from_millis(100)) {
        total_worker_bytes += w_bytes;
        total_worker_packets += w_pkts;
    }

    for handle in handles {
        let _ = handle.join();
    }

    let total_bytes = bytes_received.load(Ordering::SeqCst);
    let total_packets = packets_received.load(Ordering::SeqCst);

    let total_elapsed = start.elapsed().as_secs_f64();
    let final_rate_gbps = if total_elapsed > 0.0 {
        (total_bytes as f64 * 8.0) / (total_elapsed * 1e9)
    } else {
        0.0
    };
    println!(
        "[{:.1}s] recv rate: {:.3} Gbps, total packets={}, bytes={}",
        total_elapsed, final_rate_gbps, total_packets, total_bytes
    );
    info!("recv_one_way_server_mt_tokio finished: bytes={}, packets={}",
          total_bytes, total_packets);

    // NOTE: per-stream loss tracking is skipped in multi-worker mode because
    // kernel RSS distributes same stream across workers. True loss must be
    // derived by comparing client-sent vs server-received bytes.

    Ok(ServerOneWayStats {
        bytes_received: total_bytes,
        packets_received: total_packets,
        out_of_order: 0,
        packets_lost: 0,
        packet_loss: None,
        duration: start.elapsed(),
    })
}

// ============================================================================
// Windows multi-threaded UDP receiver using DuplicateHandle + native recv
// ============================================================================

#[cfg(target_os = "windows")]
async fn recv_one_way_server_mt_windows(
    socket: &UdpSocket,
    duration: Duration,
    buffer_size: usize,
    num_workers: usize,
) -> Result<ServerOneWayStats> {
    info!("recv_one_way_server_mt_windows: starting, duration={:?}, workers={}",
          duration, num_workers);

    let mut worker_sockets: Vec<RawSocket> = Vec::with_capacity(num_workers);
    for i in 0..num_workers {
        match duplicate_socket_for_thread(socket) {
            Ok(raw_fd) => {
                info!("Worker {}: duplicated socket fd={}", i, raw_fd);
                worker_sockets.push(raw_fd);
            }
            Err(e) => {
                error!("Worker {}: duplicate_socket_for_thread failed: {}", i, e);
            }
        }
    }

    if worker_sockets.is_empty() {
        return Err(Error::Io(std::io::Error::new(std::io::ErrorKind::Other, "no duplicated sockets")));
    }

    let bytes_received = Arc::new(AtomicU64::new(0));
    let packets_received = Arc::new(AtomicU64::new(0));
    let (tx, rx) = std::sync::mpsc::channel();
    let running = Arc::new(AtomicBool::new(true));
    let start = Instant::now();
    let test_duration = duration;

    let mut handles = Vec::new();
    for (i, raw_sock) in worker_sockets.into_iter().enumerate() {
        let bytes_rx = bytes_received.clone();
        let packets_rx = packets_received.clone();
        let running_flag = running.clone();
        let tx = tx.clone();

        let handle = thread::spawn(move || {
            let mut buf = vec![0u8; buffer_size];
            let mut local_bytes: u64 = 0;
            let mut local_packets: u64 = 0;
            let mut last_report = std::time::Instant::now();
            let report_interval = Duration::from_millis(200);
            let mut local_states: HashMap<u32, StreamState> = HashMap::new();

            while running_flag.load(Ordering::SeqCst) {
                let ret = unsafe {
                    libc::recvfrom(
                        raw_sock as libc::SOCKET,
                        buf.as_mut_ptr() as *mut libc::c_char,
                        buf.len() as libc::c_int,
                        0,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    )
                };

                if ret < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        continue;
                    }
                    if err.raw_os_error() == Some(10035) { continue; }
                    continue;
                }

                let n = ret as usize;
                local_bytes += n as u64;
                local_packets += 1;

                if n >= 8 {
                    let seq = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                    let stream_id = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                    let state = local_states.entry(stream_id)
                        .or_insert_with(|| StreamState::new(seq));
                    if seq > state.expected_seq {
                        state.expected_seq = seq.wrapping_add(1);
                    } else if seq < state.expected_seq {
                    } else {
                        state.expected_seq = state.expected_seq.wrapping_add(1);
                    }
                }

                let now = std::time::Instant::now();
                if now.duration_since(last_report) >= report_interval {
                    bytes_rx.fetch_add(local_bytes, Ordering::Relaxed);
                    packets_rx.fetch_add(local_packets, Ordering::Relaxed);
                    local_bytes = 0;
                    local_packets = 0;
                    last_report = now;
                }
            }

            bytes_rx.fetch_add(local_bytes, Ordering::Relaxed);
            packets_rx.fetch_add(local_packets, Ordering::Relaxed);
            let _ = tx.send((local_bytes, local_packets));
            info!("Worker {}: exiting", i);
        });
        handles.push(handle);
    }

    let mut prev_total_bytes: u64 = 0;
    loop {
        let elapsed = start.elapsed();
        if elapsed >= test_duration {
            running.store(false, Ordering::SeqCst);
            break;
        }
        let current_bytes = bytes_received.load(Ordering::SeqCst);
        let current_packets = packets_received.load(Ordering::SeqCst);
        let interval_bytes = current_bytes.saturating_sub(prev_total_bytes);
        let interval_elapsed = elapsed.as_secs_f64();
        if interval_elapsed > 0.0 && interval_bytes > 0 {
            let rate_gbps = (interval_bytes as f64 * 8.0) / (interval_elapsed * 1e9);
            println!("[{:.1}s] recv rate: {:.3} Gbps, packets={}, bytes={}",
                     interval_elapsed, rate_gbps, current_packets, current_bytes);
        }
        prev_total_bytes = current_bytes;
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok((w_bytes, w_pkts)) => { info!("Worker done: bytes={}, pkts={}", w_bytes, w_pkts); }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    for handle in handles { let _ = handle.join(); }

    let total_bytes = bytes_received.load(Ordering::SeqCst);
    let total_packets = packets_received.load(Ordering::SeqCst);
    let total_elapsed = start.elapsed().as_secs_f64();
    let final_rate_gbps = if total_elapsed > 0.0 {
        (total_bytes as f64 * 8.0) / (total_elapsed * 1e9)
    } else { 0.0 };
    println!("[{:.1}s] recv rate: {:.3} Gbps, total packets={}, bytes={}",
             total_elapsed, final_rate_gbps, total_packets, total_bytes);

    Ok(ServerOneWayStats {
        bytes_received: total_bytes,
        packets_received: total_packets,
        out_of_order: 0,
        packets_lost: 0,
        packet_loss: None,
        duration: start.elapsed(),
    })
}
