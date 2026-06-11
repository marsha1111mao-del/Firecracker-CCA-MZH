// Copyright 2026
// SPDX-License-Identifier: Apache-2.0

//! Configuration for broker-backed shared memory windows.

use serde::de::{Error as SerdeError, Unexpected, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Role sent to the vmshm broker during the handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum VmshmRoleConfig {
    /// Client participant.
    Client,
    /// Proxy participant.
    Proxy,
}

impl VmshmRoleConfig {
    pub(crate) fn as_wire(self) -> u16 {
        match self {
            Self::Client => 1,
            Self::Proxy => 2,
        }
    }
}

/// Optional interrupt notification setup for a vmshm communication window.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VmshmNotifyConfig {
    /// Doorbell MMIO address. Guest writes here to signal its kick eventfd.
    #[serde(
        deserialize_with = "deserialize_u64_from_number_or_str",
        serialize_with = "serialize_u64_as_hex"
    )]
    pub doorbell_addr: u64,
    /// Doorbell MMIO size exposed in the guest device tree.
    #[serde(
        default = "default_doorbell_size",
        deserialize_with = "deserialize_u64_from_number_or_str",
        serialize_with = "serialize_u64_as_hex",
        skip_serializing_if = "is_default_doorbell_size"
    )]
    pub doorbell_size: u64,
    /// KVM GSI used by irqfd and exposed to the guest FDT node.
    pub irq: u32,
}

/// Configuration for one Firecracker vmshm shared memory window.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VmshmDeviceConfig {
    /// Unix domain socket exposed by the vmshm broker domain.
    pub socket_path: String,
    /// Participant name sent to the broker.
    pub name: String,
    /// Participant role sent to the broker.
    pub role: VmshmRoleConfig,
    /// Guest physical address where this shared window is mapped.
    #[serde(
        deserialize_with = "deserialize_u64_from_number_or_str",
        serialize_with = "serialize_u64_as_hex"
    )]
    pub guest_phys_addr: u64,
    /// Explicit KVM memory slot used for this shared window.
    pub slot: u32,
    /// Optional expected memfd size. If set, Firecracker rejects mismatched broker replies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_size: Option<u64>,
    /// Optional FDT node name. Defaults to `vmshm@<guest_phys_addr>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fdt_node_name: Option<String>,
    /// Optional FDT compatible string. Defaults to `vmshm`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fdt_compatible: Option<String>,
    /// Optional client security identity exposed to guest vmshm drivers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_vmid: Option<u32>,
    /// Optional ioeventfd/irqfd notification channel for comm windows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify: Option<VmshmNotifyConfig>,
}

fn default_doorbell_size() -> u64 {
    4096
}

fn is_default_doorbell_size(value: &u64) -> bool {
    *value == default_doorbell_size()
}

fn serialize_u64_as_hex<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format!("{value:#x}"))
}

fn deserialize_u64_from_number_or_str<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    struct U64Visitor;

    impl<'de> Visitor<'de> for U64Visitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a u64 number or a decimal/hex string")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
            Ok(value)
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: SerdeError,
        {
            if let Some(hex) = value.strip_prefix("0x") {
                u64::from_str_radix(hex, 16).map_err(|_| {
                    E::invalid_value(Unexpected::Str(value), &"a valid hexadecimal u64 string")
                })
            } else {
                value.parse::<u64>().map_err(|_| {
                    E::invalid_value(Unexpected::Str(value), &"a valid decimal u64 string")
                })
            }
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: SerdeError,
        {
            self.visit_str(&value)
        }
    }

    deserializer.deserialize_any(U64Visitor)
}
