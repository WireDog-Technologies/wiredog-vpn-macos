import Foundation

/// Unix domain socket server for IPC with the Electron app.
/// Accepts JSON-RPC 2.0 messages (line-delimited JSON, same format as Windows named pipe).
class SocketServer {
    private let path: String
    private let handler: JsonRpcHandler
    private var serverSocket: Int32 = -1
    private var clients: [Int32: ClientConnection] = [:]
    private let clientsQueue = DispatchQueue(label: "com.wiredog.helper.clients")

    init(path: String, handler: JsonRpcHandler) {
        self.path = path
        self.handler = handler
    }

    func start() throws {
        // Remove existing socket file
        unlink(path)

        // Create Unix domain socket
        serverSocket = socket(AF_UNIX, SOCK_STREAM, 0)
        guard serverSocket >= 0 else {
            throw SocketError.createFailed
        }

        // Bind to path
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            path.withCString { cstr in
                _ = strcpy(UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: CChar.self), cstr)
            }
        }

        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                bind(serverSocket, sockPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }

        guard bindResult == 0 else {
            close(serverSocket)
            throw SocketError.bindFailed(errno: errno)
        }

        // Set socket permissions (world read/write so the Electron app can connect as non-root)
        chmod(path, 0o666)

        // Listen for connections
        guard listen(serverSocket, 5) == 0 else {
            close(serverSocket)
            throw SocketError.listenFailed
        }

        // Accept connections on background queue
        DispatchQueue.global(qos: .default).async { [weak self] in
            self?.acceptLoop()
        }
    }

    private func acceptLoop() {
        while serverSocket >= 0 {
            var clientAddr = sockaddr_un()
            var clientAddrLen = socklen_t(MemoryLayout<sockaddr_un>.size)

            let clientSocket = withUnsafeMutablePointer(to: &clientAddr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    accept(serverSocket, sockPtr, &clientAddrLen)
                }
            }

            guard clientSocket >= 0 else { continue }

            logger.info("Client connected (fd: \(clientSocket))")

            let client = ClientConnection(socket: clientSocket, handler: handler)
            clientsQueue.async { [weak self] in
                self?.clients[clientSocket] = client
            }
            client.start { [weak self] in
                self?.clientsQueue.async {
                    self?.clients.removeValue(forKey: clientSocket)
                }
                logger.info("Client disconnected (fd: \(clientSocket))")
            }
        }
    }

    func stop() {
        if serverSocket >= 0 {
            close(serverSocket)
            serverSocket = -1
        }
        unlink(path)
    }

    /// Send a message to all connected clients (used for JSON-RPC notifications)
    func broadcast(_ message: String) {
        clientsQueue.async { [weak self] in
            guard let self = self else { return }
            for client in self.clients.values {
                client.send(message)
            }
        }
    }
}

/// Represents a single connected client
class ClientConnection {
    private let socket: Int32
    private let handler: JsonRpcHandler
    private var buffer = ""

    init(socket: Int32, handler: JsonRpcHandler) {
        self.socket = socket
        self.handler = handler
    }

    func start(onDisconnect: @escaping () -> Void) {
        DispatchQueue.global(qos: .default).async { [weak self] in
            guard let self = self else { return }

            let bufferSize = 4096
            let readBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
            defer { readBuffer.deallocate() }

            while true {
                let bytesRead = read(self.socket, readBuffer, bufferSize)
                if bytesRead <= 0 { break }

                let data = String(bytes: UnsafeBufferPointer(start: readBuffer, count: bytesRead), encoding: .utf8) ?? ""
                self.buffer += data

                // Process complete lines
                while let newlineIndex = self.buffer.firstIndex(of: "\n") {
                    let line = String(self.buffer[self.buffer.startIndex..<newlineIndex])
                    self.buffer = String(self.buffer[self.buffer.index(after: newlineIndex)...])

                    if !line.trimmingCharacters(in: .whitespaces).isEmpty {
                        self.handler.handleMessage(
                            line.trimmingCharacters(in: .whitespaces),
                            reply: { [weak self] response in
                                if let response = response {
                                    self?.send(response + "\n")
                                }
                            }
                        )
                    }
                }
            }

            close(self.socket)
            onDisconnect()
        }
    }

    func send(_ message: String) {
        message.withCString { cstr in
            _ = write(socket, cstr, strlen(cstr))
        }
    }
}

enum SocketError: LocalizedError {
    case createFailed
    case bindFailed(errno: Int32)
    case listenFailed

    var errorDescription: String? {
        switch self {
        case .createFailed:
            return "Failed to create socket"
        case .bindFailed(let errno):
            return "Failed to bind socket (errno: \(errno))"
        case .listenFailed:
            return "Failed to listen on socket"
        }
    }
}
