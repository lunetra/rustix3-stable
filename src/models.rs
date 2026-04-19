use crate::inbounds::{InboundProtocols, SniffingOption, TransportProtocol};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{json::JsonString, serde_as};
use std::collections::BTreeMap;
use std::ops::Not;

#[derive(Debug, Deserialize, Clone)]
pub struct Response<T> {
    success: bool,
    #[serde(rename = "msg")]
    pub message: String,
    #[serde(rename = "obj")]
    pub object: T,
}

impl<T> Response<T> {
    pub fn is_ok(&self) -> bool {
        self.success
    }

    pub fn is_err(&self) -> bool {
        self.success.not()
    }

    pub fn into_result(self) -> crate::Result<T> {
        if self.success {
            Ok(self.object)
        } else {
            let msg = if self.message.is_empty() {
                "Unknown API error".to_string()
            } else {
                self.message
            };
            Err(crate::error::Error::ApiError { message: msg })
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ClientStats {
    pub id: u64,
    #[serde(rename = "inboundId")]
    pub inbound_id: u64,
    pub enable: bool,
    pub email: String,
    pub uuid: Option<String>,
    #[serde(rename = "subId")]
    pub sub_id: Option<String>,
    pub up: u128,
    pub down: u128,
    #[serde(rename = "allTime")]
    pub all_time: Option<u128>,
    #[serde(rename = "expiryTime")]
    pub expiry_time: i64, // todo
    pub total: u128,
    pub reset: i64,
    #[serde(rename = "lastOnline")]
    pub last_online: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Inbounds {
    pub id: u64,
    pub up: u128,
    pub down: u128,
    pub total: u128,
    #[serde(rename = "allTime")]
    pub all_time: Option<u128>,
    pub remark: String,
    pub enable: bool,
    #[serde(rename = "expiryTime")]
    pub expiry_time: i64,
    #[serde(rename = "trafficReset")]
    pub traffic_reset: Option<String>,
    #[serde(rename = "lastTrafficResetTime")]
    pub last_traffic_reset_time: Option<i64>,
    #[serde(rename = "clientStats")]
    pub client_stats: Option<Vec<ClientStats>>,
    pub listen: Option<String>,
    pub port: u16,
    pub protocol: InboundProtocols,
    #[serde(
        deserialize_with = "de_settings_from_str_or_map",
        serialize_with = "se_settings_as_str"
    )]
    pub settings: Settings,
    #[serde(
        rename = "streamSettings",
        deserialize_with = "de_json_opt_from_str_or_map",
        serialize_with = "se_json_opt_as_str"
    )]
    pub stream_settings: Option<StreamSettings>,
    pub tag: String,
    #[serde(
        default,
        deserialize_with = "de_json_opt_from_str_or_map",
        serialize_with = "se_json_opt_as_str"
    )]
    pub sniffing: Option<Sniffing>,
    #[serde(default)]
    pub allocate: Option<serde_json::Value>,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateInboundRequest {
    pub up: i64,
    pub down: i64,
    pub total: i64,
    pub remark: String,
    pub enable: bool,
    #[serde(rename = "expiryTime")]
    pub expiry_time: i64,
    pub listen: String,
    pub port: u16,
    pub protocol: InboundProtocols,
    #[serde_as(as = "JsonString<_>")]
    pub settings: SettingsRequest,
    #[serde_as(as = "JsonString<_>")]
    #[serde(rename = "streamSettings")]
    pub stream_settings: StreamSettings,
    #[serde_as(as = "JsonString<_>")]
    pub sniffing: Sniffing,
    #[serde_as(as = "JsonString<_>")]
    pub allocate: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct StreamSettings {
    pub network: Option<TransportProtocol>,
    pub security: Option<String>,
    #[serde(rename = "externalProxy")]
    pub external_proxy: Option<Vec<serde_json::Value>>,
    #[serde(rename = "tcpSettings")]
    pub tcp_settings: Option<TcpSettings>,
    #[serde(rename = "wsSettings")]
    pub ws_settings: Option<WebSocketSettings>,
    #[serde(rename = "grpcSettings")]
    pub grpc_settings: Option<GrpcSettings>,
    #[serde(rename = "kcpSettings")]
    pub kcp_settings: Option<KcpSettings>,
    #[serde(rename = "httpUpgradeSettings")]
    pub http_upgrade_settings: Option<HttpUpgradeSettings>,
    #[serde(rename = "xhttpSettings")]
    pub xhttp_settings: Option<XHttpSettings>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TcpSettings {
    pub accept_proxy_protocol: Option<bool>,
    pub header: Option<TcpHeader>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TcpHeader {
    #[serde(rename = "type")]
    pub header_type: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct WebSocketSettings {
    pub path: Option<String>,
    pub headers: Option<BTreeMap<String, String>>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GrpcSettings {
    pub service_name: Option<String>,
    pub multi_mode: Option<bool>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct KcpSettings {
    pub mtu: Option<u32>,
    pub tti: Option<u32>,
    pub uplink_capacity: Option<u32>,
    pub downlink_capacity: Option<u32>,
    pub congestion: Option<bool>,
    pub read_buffer_size: Option<u32>,
    pub write_buffer_size: Option<u32>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct HttpUpgradeSettings {
    pub host: Option<String>,
    pub path: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct XHttpSettings {
    pub host: Option<String>,
    pub path: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Sniffing {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    #[serde(rename = "destOverride")]
    pub dest_override: Vec<SniffingOption>,
    #[serde(default)]
    pub metadata_only: bool,
    #[serde(default)]
    pub route_only: bool,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Settings {
    #[serde(default)]
    pub clients: Vec<User>,
    #[serde(default)]
    pub decryption: Option<String>,
    #[serde(default)]
    pub encryption: Option<String>,
    #[serde(default)]
    pub fallbacks: Vec<Fallback>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SettingsRequest {
    #[serde(default)]
    pub clients: Vec<UserRequest>,
    #[serde(default)]
    pub decryption: Option<String>,
    #[serde(default)]
    pub encryption: Option<String>,
    #[serde(default)]
    pub fallbacks: Vec<Fallback>,
}

fn de_settings_from_str_or_map<'de, D>(d: D) -> Result<Settings, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Wire {
        Str(String),
        Map(Settings),
    }
    match Wire::deserialize(d)? {
        Wire::Str(s) => serde_json::from_str(&s).map_err(serde::de::Error::custom),
        Wire::Map(m) => Ok(m),
    }
}

fn se_settings_as_str<S>(value: &Settings, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let json = serde_json::to_string(value).map_err(serde::ser::Error::custom)?;
    s.serialize_str(&json)
}

fn de_json_opt_from_str_or_map<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Wire<T> {
        Str(String),
        Map(T),
    }

    let opt = Option::<Wire<T>>::deserialize(d)?;

    match opt {
        None => Ok(None),

        Some(Wire::Str(s)) => {
            let s = s.trim();

            if s.is_empty() {
                return Ok(None);
            }

            serde_json::from_str(s)
                .map(Some)
                .map_err(serde::de::Error::custom)
        }

        Some(Wire::Map(m)) => Ok(Some(m)),
    }
}

fn se_json_opt_as_str<S, T>(value: &Option<T>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Serialize,
{
    match value {
        Some(val) => {
            let json = serde_json::to_string(val).map_err(serde::ser::Error::custom)?;
            s.serialize_some(&json)
        }
        None => s.serialize_none(),
    }
}

fn de_opt_num_from_str_or_num<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: serde::de::DeserializeOwned + std::str::FromStr,
    <T as std::str::FromStr>::Err: std::fmt::Display,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Wire<T> {
        Str(String),
        Num(T),
    }
    let opt = Option::<Wire<T>>::deserialize(d)?;
    match opt {
        None => Ok(None),
        Some(Wire::Str(s)) => s.parse::<T>().map(Some).map_err(serde::de::Error::custom),
        Some(Wire::Num(n)) => Ok(Some(n)),
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: Option<String>,
    pub email: String,
    #[serde(default)]
    pub flow: Option<String>,
    pub comment: Option<String>,
    #[serde(rename = "created_at")]
    pub created_at: Option<i64>,
    #[serde(rename = "updated_at")]
    pub updated_at: Option<i64>,
    pub password: Option<String>,
    #[serde(default)]
    pub limit_ip: Option<u32>,
    #[serde(rename = "totalGB")]
    #[serde(default)]
    pub total_gb: Option<u64>,
    #[serde(default)]
    pub expiry_time: Option<u64>,
    #[serde(default)]
    pub enable: Option<bool>,
    #[serde(default)]
    pub tg_id: Option<TgId>,
    #[serde(default)]
    pub sub_id: Option<String>,
    #[serde(default)]
    pub reset: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UserRequest {
    pub id: String,
    pub flow: Option<String>,
    pub email: String,
    pub limit_ip: u32,
    #[serde(rename = "totalGB")]
    pub total_gb: u64,
    pub expiry_time: u64,
    pub enable: bool,
    #[serde(default)]
    pub tg_id: Option<TgId>,
    pub sub_id: String,
    pub reset: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum TgId {
    String(String),
    Int(u64),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Fallback {
    #[serde(rename = "SNI")]
    pub sni: String,
    #[serde(rename = "ALPN")]
    pub alpn: String,
    pub path: String,
    pub dest: String,
    pub x_ver: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientSettings {
    pub clients: Vec<UserRequest>,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct ClientRequest {
    pub id: u64,
    #[serde_as(as = "JsonString<_>")]
    pub settings: ClientSettings,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CpuHistoryPoint {
    pub cpu: f64,
    pub t: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum ClientIps {
    Ips(Vec<String>),
    Message(String),
}

impl ClientIps {
    pub fn as_ips(&self) -> Option<&[String]> {
        match self {
            ClientIps::Ips(v) => Some(v),
            ClientIps::Message(_) => None,
        }
    }

    pub fn as_message(&self) -> Option<&str> {
        match self {
            ClientIps::Message(s) => Some(s),
            ClientIps::Ips(_) => None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Uuid {
    pub uuid: uuid::Uuid,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LoginInfo {
    pub token: Option<String>,
    #[serde(rename = "twoFactorEnabled")]
    pub two_factor_enabled: Option<bool>,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<i64>,
    pub username: Option<String>,
    #[serde(rename = "role")]
    pub role: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ServerStatus {
    #[serde(default, deserialize_with = "de_opt_num_from_str_or_num")]
    pub cpu: Option<f64>,
    #[serde(default, deserialize_with = "de_opt_num_from_str_or_num")]
    #[serde(rename = "cpuCores")]
    pub cpu_cores: Option<u64>,
    #[serde(default, deserialize_with = "de_opt_num_from_str_or_num")]
    #[serde(rename = "logicalPro")]
    pub logical_pro: Option<u64>,
    #[serde(default, deserialize_with = "de_opt_num_from_str_or_num")]
    #[serde(rename = "cpuSpeedMhz")]
    pub cpu_speed_mhz: Option<f64>,
    pub mem: Option<MemStat>,
    pub swap: Option<MemStat>,
    pub disk: Option<MemStat>,
    pub xray: Option<XrayStatus>,
    #[serde(default, deserialize_with = "de_opt_num_from_str_or_num")]
    pub uptime: Option<u64>,
    #[serde(default)]
    pub loads: Vec<f64>,
    #[serde(default, deserialize_with = "de_opt_num_from_str_or_num")]
    #[serde(rename = "tcpCount")]
    pub tcp_count: Option<u64>,
    #[serde(default, deserialize_with = "de_opt_num_from_str_or_num")]
    #[serde(rename = "udpCount")]
    pub udp_count: Option<u64>,
    #[serde(rename = "netIO")]
    pub net_io: Option<NetIo>,
    #[serde(rename = "netTraffic")]
    pub net_traffic: Option<NetTraffic>,
    #[serde(rename = "publicIP")]
    pub public_ip: Option<PublicIp>,
    #[serde(rename = "appStats")]
    pub app_stats: Option<AppStats>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MemStat {
    #[serde(default, deserialize_with = "de_opt_num_from_str_or_num")]
    pub current: Option<u64>,
    #[serde(default, deserialize_with = "de_opt_num_from_str_or_num")]
    pub total: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct XrayStatus {
    pub state: Option<String>,
    #[serde(rename = "errorMsg")]
    pub error_msg: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetIo {
    #[serde(default, deserialize_with = "de_opt_num_from_str_or_num")]
    pub up: Option<u64>,
    #[serde(default, deserialize_with = "de_opt_num_from_str_or_num")]
    pub down: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetTraffic {
    #[serde(default, deserialize_with = "de_opt_num_from_str_or_num")]
    pub sent: Option<u64>,
    #[serde(default, deserialize_with = "de_opt_num_from_str_or_num")]
    pub recv: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PublicIp {
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AppStats {
    #[serde(default, deserialize_with = "de_opt_num_from_str_or_num")]
    pub threads: Option<u64>,
    #[serde(default, deserialize_with = "de_opt_num_from_str_or_num")]
    pub mem: Option<u64>,
    #[serde(default, deserialize_with = "de_opt_num_from_str_or_num")]
    pub uptime: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct X25519Cert {
    #[serde(rename = "privateKey")]
    pub private_key: Option<String>,
    #[serde(rename = "publicKey")]
    pub public_key: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Mldsa65 {
    pub seed: Option<String>,
    pub verify: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Mlkem768 {
    pub seed: Option<String>,
    pub verify: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VlessEnc {
    #[serde(default)]
    pub auths: Vec<VlessAuth>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VlessAuth {
    pub decryption: Option<String>,
    pub encryption: Option<String>,
    pub label: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EchCert {
    #[serde(rename = "echConfigList")]
    pub ech_config_list: Option<String>,
    #[serde(rename = "echServerKeys")]
    pub ech_server_keys: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigJson {
    pub api: Option<ConfigApi>,
    pub inbounds: Option<Vec<ConfigInbound>>,
    pub outbounds: Option<Vec<ConfigOutbound>>,
    pub log: Option<ConfigLog>,
    pub metrics: Option<ConfigMetrics>,
    pub routing: Option<ConfigRouting>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigApi {
    #[serde(default)]
    pub services: Vec<String>,
    pub tag: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ConfigInbound {
    pub listen: Option<String>,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub settings: Option<serde_json::Value>,
    pub sniffing: Option<serde_json::Value>,
    #[serde(rename = "streamSettings")]
    pub stream_settings: Option<serde_json::Value>,
    pub tag: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigOutbound {
    pub protocol: Option<String>,
    pub settings: Option<serde_json::Value>,
    pub tag: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ConfigLog {
    pub access: Option<String>,
    pub dns_log: Option<bool>,
    pub error: Option<String>,
    pub loglevel: Option<String>,
    pub mask_address: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ConfigMetrics {
    pub listen: Option<String>,
    pub tag: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ConfigRouting {
    pub domain_strategy: Option<crate::inbounds::DomainStrategyOption>,
    #[serde(default)]
    pub rules: Vec<RoutingRule>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RoutingRule {
    #[serde(rename = "type")]
    pub rule_type: Option<String>,
    #[serde(rename = "inboundTag")]
    pub inbound_tag: Option<Vec<String>>,
    #[serde(rename = "outboundTag")]
    pub outbound_tag: Option<String>,
    pub ip: Option<Vec<String>>,
    pub domain: Option<Vec<String>>,
    pub port: Option<String>,
    pub protocol: Option<Vec<String>>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}
