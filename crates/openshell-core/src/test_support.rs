// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Socket fixtures shared by crate tests.

use std::net::{SocketAddr, TcpListener, TcpStream};

/// A loopback TCP port that refuses connections for the lifetime of this guard.
///
/// The port belongs to a connected client, keeping OS-assigned listeners in
/// parallel tests from being allocated the same port. Both ends stay alive.
/// A bound, unconnected socket is insufficient: on macOS it times out instead of
/// refusing. Do not use this fixture to hand a port to a server after dropping it:
/// closing the pair can leave the client's port in `TIME_WAIT`.
#[must_use = "keep the guard alive while testing connection refusal"]
pub struct RefusingTcpPort {
    client: TcpStream,
    _peer: TcpStream,
}

impl RefusingTcpPort {
    /// Reserve an OS-assigned port that refuses new connections.
    ///
    /// # Errors
    ///
    /// Returns an error if a loopback TCP pair cannot be created.
    pub fn bind() -> std::io::Result<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let client = crate::net::connect_std_tcp_nodelay_best_effort(listener.local_addr()?)?;
        let (peer, _) = listener.accept()?;
        peer.set_nodelay(true)?;
        Ok(Self {
            client,
            _peer: peer,
        })
    }

    /// The reserved loopback address.
    ///
    /// # Panics
    ///
    /// Panics if the connected socket has no local address.
    #[must_use]
    pub fn address(&self) -> SocketAddr {
        self.client
            .local_addr()
            .expect("connected socket has a local address")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusing_port_stays_reserved() {
        let port = RefusingTcpPort::bind().unwrap();
        let address = port.address();
        assert_eq!(
            crate::net::connect_std_tcp_nodelay_best_effort(address)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::ConnectionRefused
        );
        // A socket without SO_REUSEADDR cannot take the connected client's port.
        // On macOS an explicit SO_REUSEADDR bind can reuse connected ports.
        assert_eq!(
            tokio::net::TcpSocket::new_v4()
                .unwrap()
                .bind(address)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::AddrInUse
        );
        let listeners: Vec<_> = (0..64)
            .map(|_| TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap())
            .collect();
        assert!(
            listeners
                .iter()
                .all(|listener| listener.local_addr().unwrap() != address)
        );
    }
}
