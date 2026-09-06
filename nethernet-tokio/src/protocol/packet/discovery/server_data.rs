//! ServerData binary structure for Minecraft: Bedrock Edition.
//!
//! Encapsulated in ResponsePacket.ApplicationData and sent in response
//! to RequestPacket broadcasted by clients on port 7551.

use crate::error::{NethernetError, Result};
use crate::protocol::types::{
    read_bytes_u8, read_i32_le, read_u8, write_bytes_u8, write_i32_le, write_u8,
};
use std::io::Cursor;

/// Current version of ServerData supported by the discovery module.
const VERSION: u8 = 4;

/// ServerData defines the binary structure representing worlds in Minecraft: Bedrock Edition.
#[derive(Debug, Clone)]
pub struct ServerData {
    /// Name of the server (typically the player name of the owner)
    pub server_name: String,
    /// Name of the world/level
    pub level_name: String,
    /// Default game mode (0=Survival, 1=Creative, 2=Adventure, 3=Spectator)
    pub game_type: u8,
    /// Current player count (should be at least 1 to appear in server list)
    pub player_count: i32,
    /// Maximum player count allowed
    pub max_player_count: i32,
    /// Whether this is an Editor Mode project
    pub editor_world: bool,
    /// Whether hardcore mode is enabled
    pub hardcore: bool,
    /// Transport layer (2 = NetherNet)
    pub transport_layer: u8,
    /// Connection type (4 = LAN)
    pub connection_type: u8,
}

impl ServerData {
    /// Constructs a ServerData for the given server and level names using sensible defaults.
    ///
    /// server_name: the server owner or player name.
    /// level_name: the world or level name.
    ///
    /// Defaults:
    /// - game_type = 0 (Survival)
    /// - player_count = 1
    /// - max_player_count = 8
    /// - editor_world = false
    /// - hardcore = false
    /// - transport_layer = 2 (NetherNet)
    /// - connection_type = 4 (LAN)
    pub fn new(server_name: String, level_name: String) -> Self {
        Self {
            server_name,
            level_name,
            game_type: 0,
            player_count: 1,
            max_player_count: 8,
            editor_world: false,
            hardcore: false,
            transport_layer: 2, // NetherNet
            connection_type: 4, // LAN
        }
    }

    /// Encode the ServerData into the binary format used for discovery ResponsePacket.ApplicationData.
    ///
    /// Returns a vector of bytes on success or a NethernetError if encoding fails (for example,
    /// if a field value would overflow its encoded form or an I/O write fails).
    ///
    /// Parses a RakNet pong response as sent by Minecraft listeners.
    ///
    /// The pong is a `;` separated list, of which the server name, level name, player
    /// counts and game mode are used. Transport layer and connection type are set to
    /// the values vanilla clients expect for LAN discovery over NetherNet.
    pub fn from_pong_data(data: &[u8]) -> Result<Self> {
        let pong = std::str::from_utf8(data)
            .map_err(|e| NethernetError::Other(format!("invalid pong data UTF-8: {}", e)))?;
        let parts: Vec<&str> = pong.split(';').collect();
        if parts.len() < 9 {
            return Err(NethernetError::Other(format!(
                "unexpected pong data format: {} fields, expected at least 9",
                parts.len()
            )));
        }

        Ok(Self {
            server_name: parts[1].to_string(),
            level_name: parts[7].to_string(),
            game_type: game_type(parts[8]),
            player_count: parts[4].parse().unwrap_or(0),
            max_player_count: parts[5].parse().unwrap_or(0),
            editor_world: false,
            hardcore: false,
            transport_layer: 2,
            connection_type: 4,
        })
    }

    pub fn marshal(&self) -> Result<Vec<u8>> {
        // Validate fields that will be shifted to prevent overflow
        if self.game_type >= 128 {
            return Err(NethernetError::Other(format!(
                "game_type must be less than 128 to avoid overflow, got {}",
                self.game_type
            )));
        }
        if self.transport_layer >= 128 {
            return Err(NethernetError::Other(format!(
                "transport_layer must be less than 128 to avoid overflow, got {}",
                self.transport_layer
            )));
        }
        if self.connection_type >= 128 {
            return Err(NethernetError::Other(format!(
                "connection_type must be less than 128 to avoid overflow, got {}",
                self.connection_type
            )));
        }

        let mut buf = Vec::new();

        // Write version
        write_u8(&mut buf, VERSION)?;

        // Write server name (u8-prefixed string)
        write_bytes_u8(&mut buf, self.server_name.as_bytes())?;

        // Write level name (u8-prefixed string)
        write_bytes_u8(&mut buf, self.level_name.as_bytes())?;

        // Write game type (shifted left by 1)
        write_u8(&mut buf, self.game_type << 1)?;

        // Write player counts (i32 little-endian)
        write_i32_le(&mut buf, self.player_count)?;
        write_i32_le(&mut buf, self.max_player_count)?;

        // Write booleans
        write_u8(&mut buf, if self.editor_world { 1 } else { 0 })?;
        write_u8(&mut buf, if self.hardcore { 1 } else { 0 })?;

        // Write transport layer and connection type (both shifted left by 1)
        write_u8(&mut buf, self.transport_layer << 1)?;
        write_u8(&mut buf, self.connection_type << 1)?;

        Ok(buf)
    }

    /// Decode a ServerData value from its binary representation.
    ///
    /// The function verifies the embedded version, reads each field in the expected
    /// order (version, u8-prefixed server and level names, game type, player counts,
    /// booleans, transport layer, connection type), validates UTF-8 for string
    /// fields, and ensures no unread bytes remain. On success returns a populated
    /// ServerData; on failure returns a NethernetError describing the problem.
    pub fn unmarshal(data: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data);

        // Read and verify version
        let version = read_u8(&mut cursor)?;
        if version != VERSION {
            return Err(NethernetError::Other(format!(
                "version mismatch: got {}, want {}",
                version, VERSION
            )));
        }

        // Read server name
        let server_name_bytes = read_bytes_u8(&mut cursor)?;
        let server_name = String::from_utf8(server_name_bytes)
            .map_err(|e| NethernetError::Other(format!("invalid server name UTF-8: {}", e)))?;

        // Read level name
        let level_name_bytes = read_bytes_u8(&mut cursor)?;
        let level_name = String::from_utf8(level_name_bytes)
            .map_err(|e| NethernetError::Other(format!("invalid level name UTF-8: {}", e)))?;

        // Read game type (shift right by 1)
        let game_type = read_u8(&mut cursor)? >> 1;

        // Read player counts (i32 little-endian)
        let player_count = read_i32_le(&mut cursor)?;
        let max_player_count = read_i32_le(&mut cursor)?;

        // Read booleans
        let editor_world = read_u8(&mut cursor)? != 0;
        let hardcore = read_u8(&mut cursor)? != 0;

        // Read transport layer and connection type (both shift right by 1)
        let transport_layer = read_u8(&mut cursor)? >> 1;
        let connection_type = read_u8(&mut cursor)? >> 1;

        // Ensure all data was read
        let remaining = data.len() - cursor.position() as usize;
        if remaining != 0 {
            return Err(NethernetError::Other(format!("unread {} bytes", remaining)));
        }

        Ok(Self {
            server_name,
            level_name,
            game_type,
            player_count,
            max_player_count,
            editor_world,
            hardcore,
            transport_layer,
            connection_type,
        })
    }
}

/// Returns the game type for the game mode name of a RakNet pong response.
fn game_type(mode: &str) -> u8 {
    match mode.trim().to_ascii_lowercase().as_str() {
        "creative" => 1,
        "adventure" => 2,
        "spectator" => 6,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_data_roundtrip() {
        let original = ServerData {
            server_name: "Test Server".to_string(),
            level_name: "My World".to_string(),
            game_type: 0,
            player_count: 3,
            max_player_count: 10,
            editor_world: false,
            hardcore: false,
            transport_layer: 2,
            connection_type: 4,
        };

        let encoded = original.marshal().unwrap();
        let decoded = ServerData::unmarshal(&encoded).unwrap();

        assert_eq!(original.server_name, decoded.server_name);
        assert_eq!(original.level_name, decoded.level_name);
        assert_eq!(original.game_type, decoded.game_type);
        assert_eq!(original.player_count, decoded.player_count);
        assert_eq!(original.max_player_count, decoded.max_player_count);
        assert_eq!(original.editor_world, decoded.editor_world);
        assert_eq!(original.hardcore, decoded.hardcore);
        assert_eq!(original.transport_layer, decoded.transport_layer);
        assert_eq!(original.connection_type, decoded.connection_type);
    }

    #[test]
    fn test_from_pong_data() {
        let pong = b"MCPE;Dedicated Server;800;1.21.0;3;10;13253860892328930865;Bedrock level;Creative;1;19132;19133;";
        let data = ServerData::from_pong_data(pong).unwrap();

        assert_eq!(data.server_name, "Dedicated Server");
        assert_eq!(data.level_name, "Bedrock level");
        assert_eq!(data.game_type, 1);
        assert_eq!(data.player_count, 3);
        assert_eq!(data.max_player_count, 10);
        assert_eq!(data.transport_layer, 2);
        assert_eq!(data.connection_type, 4);
    }

    #[test]
    fn test_from_pong_data_rejects_short_input() {
        assert!(ServerData::from_pong_data(b"MCPE;Server").is_err());
    }

    #[test]
    fn test_version_mismatch() {
        let data = vec![5]; // Wrong version
        let result = ServerData::unmarshal(&data);
        assert!(result.is_err());
    }
}
