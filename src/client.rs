#![allow(dead_code)]

use super::{
    ClientIpsResponse, ClientsStatsResponse, ClientsStatsVecResponse, ConfigJsonResponse,
    CpuHistoryResponse, DeleteInboundResponse, EchCertResponse, InboundResponse, InboundsResponse,
    LoginResponse, Mldsa65Response, Mlkem768Response, NullObjectResponse, OnlineClientsResponse,
    OptStringVecResponse, Result, ServerStatusResponse, StringResponse, StringVecResponse,
    UuidResponse, VlessEncResponse, X25519CertResponse,
};
use crate::error::Error;
use crate::models::{
    ClientRequest, ClientStats, ConfigJson, CpuHistoryPoint, CreateInboundRequest, EchCert,
    Inbounds, LoginInfo, Mldsa65, Mlkem768, ServerStatus, Uuid, VlessEnc, X25519Cert,
};
use crate::response_ext::ResponseJsonVerboseExt;
use log::debug;
use reqwest::header::RETRY_AFTER;
use reqwest::multipart::{Form, Part};
use reqwest::{Client as RClient, IntoUrl, Method, StatusCode, Url, Proxy};
use serde::Serialize;
use tokio::time::{Duration, sleep};

/// Client configuration for retry policy and timeouts.
#[derive(Debug, Clone)]
pub struct ClientOptions {
    pub retry_count: u32,
    pub retry_base_delay: Duration,
    pub retry_max_delay: Duration,
    pub retry_methods: Vec<Method>,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub proxy_url: Option<String>,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            retry_count: 2,
            retry_base_delay: Duration::from_millis(200),
            retry_max_delay: Duration::from_secs(2),
            retry_methods: vec![Method::GET, Method::HEAD],
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(30),
            proxy_url: None,
        }
    }
}

/// Result of a login attempt.
#[derive(Debug, Clone)]
pub struct LoginResult {
    pub message: String,
    pub details: Option<LoginInfo>,
}

/// API client for 3x-ui panel.
#[derive(Debug)]
pub struct Client {
    username: String,
    password: String,
    url: Url,
    client: RClient,
    options: ClientOptions,
}

impl Client {
    /// Create a client with default retry policy and timeouts.
    pub async fn new(
        username: impl Into<String>,
        password: impl Into<String>,
        url: impl IntoUrl,
    ) -> Result<Self> {
        Self::new_with_options(username, password, url, ClientOptions::default()).await
    }

    /// Create a client with custom retry policy and timeouts.
    pub async fn new_with_options(
        username: impl Into<String>,
        password: impl Into<String>,
        url: impl IntoUrl,
        options: ClientOptions,
    ) -> Result<Self> {
        let mut builder = RClient::builder()
            .cookie_store(true)
            .connect_timeout(options.connect_timeout)
            .timeout(options.request_timeout);

        if let Some(ref proxy_url) = options.proxy_url {
            let proxy = reqwest::Proxy::all(proxy_url)?;
            builder = builder.proxy(proxy);
        }

        let client = Self {
            username: username.into(),
            password: password.into(),
            url: url.into_url()?,
            client: builder.build()?,
            options,
        };

        debug!("{:?}", client);
        let _ = client.login().await?;
        Ok(client)
    }

    fn gen_url_with_base(&self, base: &[&str], segs: Vec<&str>) -> Result<Url> {
        let base_str = self.url.as_str().trim_end_matches('/');
        let mut url =
            Url::parse(base_str).map_err(|_| Error::InvalidUrl("Invalid base URL".into()))?;
        {
            let mut path_segments = url
                .path_segments_mut()
                .map_err(|_| Error::InvalidUrl("Cannot be a base URL".into()))?;
            path_segments.extend(base.iter().copied());
            path_segments.extend(segs);
        }
        debug!("Generated URL: {}", url);
        Ok(url)
    }

    fn gen_server_url(&self, segs: Vec<&str>) -> Result<Url> {
        self.gen_url_with_base(&["panel", "api", "server"], segs)
    }

    fn gen_inbounds_url(&self, segs: Vec<&str>) -> Result<Url> {
        let base_segs = vec!["panel", "api", "inbounds"];
        self.gen_url_with_base(&base_segs, segs)
    }

    async fn login(&self) -> Result<LoginResult> {
        #[derive(Serialize)]
        struct LoginRequest {
            username: String,
            password: String,
        }
        let body = LoginRequest {
            username: self.username.clone(),
            password: self.password.clone(),
        };

        debug!("Sending login request!");
        let json_url = self.url.clone().join("login").unwrap();
        let response = self
            .send_with_retry(self.client.post(json_url).json(&body))
            .await?;
        match response.status() {
            StatusCode::NOT_FOUND | StatusCode::UNSUPPORTED_MEDIA_TYPE => {
                let form_url = self.url.clone().join("login/").unwrap();
                let form = Form::new()
                    .text("username", self.username.clone())
                    .text("password", self.password.clone())
                    .text("twoFactorCode", String::new());
                let form_response = self
                    .send_with_retry(self.client.post(form_url).multipart(form))
                    .await?;
                match form_response.status() {
                    StatusCode::NOT_FOUND => {
                        return Err(Error::NotFound(
                            form_response.error_for_status().unwrap_err(),
                        ));
                    }
                    StatusCode::OK => {}
                    e => {
                        log::warn!("Unimplemented handle err{:?}", e)
                    }
                }
                let login: LoginResponse = form_response.json().await?;
                let message = login.message.clone();
                let details = login.into_result()?;
                return Ok(LoginResult { message, details });
            }
            StatusCode::OK => {}
            e => {
                log::warn!("Unimplemented handle err{:?}", e)
            }
        }
        let login: LoginResponse = response.json().await?;
        let message = login.message.clone();
        let details = login.into_result()?;
        Ok(LoginResult { message, details })
    }

    /// List all inbounds.
    pub async fn get_inbounds_list(&self) -> Result<Vec<Inbounds>> {
        let path = vec!["list"];
        let res: InboundsResponse = self
            .send_with_retry(self.client.get(self.gen_inbounds_url(path)?))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Get inbound by id.
    pub async fn get_inbound_by_id(&self, inbound_id: u64) -> Result<Inbounds> {
        let id = inbound_id.to_string();
        let path = vec!["get", &id];
        let res: InboundResponse = self
            .send_with_retry(self.client.get(self.gen_inbounds_url(path)?))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Get client traffic by email.
    pub async fn get_client_traffic_by_email(&self, email: impl AsRef<str>) -> Result<ClientStats> {
        let path = vec!["getClientTraffics", email.as_ref()];
        let res: ClientsStatsResponse = self
            .send_with_retry(self.client.get(self.gen_inbounds_url(path)?))
            .await?
            .json_verbose()
            .await?; // todo check is null return user not found
        res.into_result()
    }

    /// Get client traffic by id.
    pub async fn get_client_traffic_by_id(&self, id: impl AsRef<str>) -> Result<Vec<ClientStats>> {
        // todo id to uuid
        let id = id.as_ref();
        let path = vec!["getClientTrafficsById", id];
        let res: ClientsStatsVecResponse = self
            .send_with_retry(self.client.get(self.gen_inbounds_url(path)?))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Trigger backup via bot.
    pub async fn send_backup_by_bot(&self) -> Result<()> {
        // todo tests
        let path = vec!["createbackup"];
        let res = self
            .send_with_retry(self.client.get(self.gen_inbounds_url(path)?))
            .await?;
        if res.status() != StatusCode::OK {
            return Err(Error::OtherError("Todo".into()));
        }
        Ok(())
    }

    /// Get client IPs by email.
    pub async fn get_client_ips(&self, client_email: impl AsRef<str>) -> Result<ClientIpsResponse> {
        // todo tests
        let path = vec!["clientIps", client_email.as_ref()];
        let res = self
            .send_with_retry(self.client.post(self.gen_inbounds_url(path)?))
            .await?;
        res.json_verbose().await.map_err(Into::into)
    }

    /// Create inbound.
    pub async fn add_inbound(&self, req: &CreateInboundRequest) -> Result<Inbounds> {
        let url = self.gen_inbounds_url(vec!["add"])?;
        let res: InboundResponse = self
            .send_with_retry(self.client.post(url).json(req))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Add client(s) to inbound.
    pub async fn add_client_to_inbound(&self, req: &ClientRequest) -> Result<Option<()>> {
        let url = self.gen_inbounds_url(vec!["addClient"])?;
        let res: NullObjectResponse = self
            .send_with_retry(self.client.post(url).json(req))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Update inbound.
    pub async fn update_inbound(
        &self,
        inbound_id: u64,
        req: &CreateInboundRequest,
    ) -> Result<Inbounds> {
        let url = self.gen_inbounds_url(vec!["update", &inbound_id.to_string()])?;
        let res: InboundResponse = self
            .send_with_retry(self.client.post(url).json(req))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Update client by UUID.
    pub async fn update_client(&self, uuid: &str, req: &ClientRequest) -> Result<Option<()>> {
        let url = self.gen_inbounds_url(vec!["updateClient", uuid])?;
        let res: NullObjectResponse = self
            .send_with_retry(self.client.post(url).json(req))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Clear client IPs by email.
    pub async fn clear_client_ips(&self, email: &str) -> Result<Option<()>> {
        let url = self.gen_inbounds_url(vec!["clearClientIps", email])?;
        let res: NullObjectResponse = self
            .send_with_retry(self.client.post(url))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Reset all inbound traffics.
    pub async fn reset_all_inbound_traffics(&self) -> Result<Option<()>> {
        let url = self.gen_inbounds_url(vec!["resetAllTraffics"])?;
        let res: NullObjectResponse = self
            .send_with_retry(self.client.post(url))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Reset all client traffics for inbound.
    pub async fn reset_all_client_traffics(&self, inbound_id: u64) -> Result<Option<()>> {
        let url = self.gen_inbounds_url(vec!["resetAllClientTraffics", &inbound_id.to_string()])?;
        let res: NullObjectResponse = self
            .send_with_retry(self.client.post(url))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Reset client traffic by email.
    pub async fn reset_client_traffic(&self, inbound_id: u64, email: &str) -> Result<Option<()>> {
        let url =
            self.gen_inbounds_url(vec![&inbound_id.to_string(), "resetClientTraffic", email])?;
        let res: NullObjectResponse = self
            .send_with_retry(self.client.post(url))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Delete client by UUID.
    pub async fn delete_client(&self, inbound_id: u64, uuid: &str) -> Result<Option<()>> {
        let url = self.gen_inbounds_url(vec![&inbound_id.to_string(), "delClient", uuid])?;
        let res: NullObjectResponse = self
            .send_with_retry(self.client.post(url))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Delete inbound by id.
    pub async fn delete_inbound(&self, inbound_id: u64) -> Result<u64> {
        let url = self.gen_inbounds_url(vec!["del", &inbound_id.to_string()])?;
        let res: DeleteInboundResponse = self
            .send_with_retry(self.client.post(url))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Delete depleted clients by inbound.
    pub async fn delete_depleted_clients(&self, inbound_id: u64) -> Result<Option<()>> {
        let url = self.gen_inbounds_url(vec!["delDepletedClients", &inbound_id.to_string()])?;
        let res: NullObjectResponse = self
            .send_with_retry(self.client.post(url))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// List online clients.
    pub async fn online_clients(&self) -> Result<Option<Vec<String>>> {
        let url = self.gen_inbounds_url(vec!["onlines"])?;
        let res: OnlineClientsResponse = self
            .send_with_retry(self.client.post(url))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Import inbound.
    pub async fn import_inbound(&self, inbound: &Inbounds) -> Result<Inbounds> {
        let url = self.gen_inbounds_url(vec!["import"])?;
        let json_str = serde_json::to_string(inbound)
            .map_err(|e| Error::OtherError(format!("serialize inbound: {e}")))?;
        let form = Form::new().text("data", json_str);
        let res: InboundResponse = self
            .send_with_retry(self.client.post(url).multipart(form))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Get last online clients.
    pub async fn get_last_online(&self) -> Result<Option<Vec<String>>> {
        let url = self.gen_inbounds_url(vec!["onlines"])?;
        let res: OptStringVecResponse = self
            .send_with_retry(self.client.post(url))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Delete client by email.
    pub async fn del_client_by_email(&self, inbound_id: u64, email: &str) -> Result<Option<()>> {
        let url =
            self.gen_inbounds_url(vec![&inbound_id.to_string(), "delClientByEmail", email])?;
        let res: NullObjectResponse = self
            .send_with_retry(self.client.post(url))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Get server status.
    pub async fn server_status(&self) -> Result<Option<ServerStatus>> {
        let url = self.gen_server_url(vec!["status"])?;
        let res: ServerStatusResponse = self
            .send_with_retry(self.client.get(url))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Download server database.
    pub async fn server_get_db(&self) -> Result<Vec<u8>> {
        let url = self.gen_server_url(vec!["getDb"])?;
        let res = self.send_with_retry(self.client.get(url)).await?;
        Ok(res.bytes().await?.to_vec())
    }

    /// Get Xray versions.
    pub async fn get_xray_version(&self) -> Result<Option<Vec<String>>> {
        let url = self.gen_server_url(vec!["getXrayVersion"])?;
        let res: OptStringVecResponse = self
            .send_with_retry(self.client.get(url))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Get config JSON.
    pub async fn get_config_json(&self) -> Result<ConfigJson> {
        let url = self.gen_server_url(vec!["getConfigJson"])?;
        let res: ConfigJsonResponse = self
            .send_with_retry(self.client.get(url))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Get CPU history for a time bucket.
    pub async fn cpu_history(&self, minutes: u32) -> Result<Option<Vec<CpuHistoryPoint>>> {
        let url = self.gen_server_url(vec!["cpuHistory", &minutes.to_string()])?;
        let res: CpuHistoryResponse = self
            .send_with_retry(self.client.get(url))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Request a new UUID.
    pub async fn get_new_uuid(&self) -> Result<Uuid> {
        let url = self.gen_server_url(vec!["getNewUUID"])?;
        let res: UuidResponse = self
            .send_with_retry(self.client.get(url))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Request a new X25519 certificate.
    pub async fn get_new_x25519_cert(&self) -> Result<X25519Cert> {
        let url = self.gen_server_url(vec!["getNewX25519Cert"])?;
        let res: X25519CertResponse = self
            .send_with_retry(self.client.get(url))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Request a new MLDsa65 bundle.
    pub async fn get_new_mldsa65(&self) -> Result<Mldsa65> {
        let url = self.gen_server_url(vec!["getNewmldsa65"])?;
        let res: Mldsa65Response = self
            .send_with_retry(self.client.get(url))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Request a new MLKEM768 bundle.
    pub async fn get_new_mlkem768(&self) -> Result<Mlkem768> {
        let url = self.gen_server_url(vec!["getNewmlkem768"])?;
        let res: Mlkem768Response = self
            .send_with_retry(self.client.get(url))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Request VLESS encryption settings.
    pub async fn get_new_vless_enc(&self) -> Result<VlessEnc> {
        let url = self.gen_server_url(vec!["getNewVlessEnc"])?;
        let res: VlessEncResponse = self
            .send_with_retry(self.client.get(url))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Request a new ECH certificate.
    pub async fn get_new_ech_cert(&self) -> Result<EchCert> {
        let url = self.gen_server_url(vec!["getNewEchCert"])?;
        let res: EchCertResponse = self
            .send_with_retry(self.client.post(url))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Stop Xray service.
    pub async fn stop_xray_service(&self) -> Result<Option<()>> {
        let url = self.gen_server_url(vec!["stopXrayService"])?;
        let res: NullObjectResponse = self
            .send_with_retry(self.client.post(url))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Restart Xray service.
    pub async fn restart_xray_service(&self) -> Result<Option<()>> {
        let url = self.gen_server_url(vec!["restartXrayService"])?;
        let res: NullObjectResponse = self
            .send_with_retry(self.client.post(url))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Install Xray version.
    pub async fn install_xray_version(&self, version: &str) -> Result<Option<()>> {
        let url = self.gen_server_url(vec!["installXray", version])?;
        let res: NullObjectResponse = self
            .send_with_retry(self.client.post(url))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Update geofile bundle.
    pub async fn update_geofile(&self) -> Result<Option<()>> {
        let url = self.gen_server_url(vec!["updateGeofile"])?;
        let res: NullObjectResponse = self
            .send_with_retry(self.client.post(url))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Update geofile by name.
    pub async fn update_geofile_by_name(&self, file_name: &str) -> Result<Option<()>> {
        let url = self.gen_server_url(vec!["updateGeofile", file_name])?;
        let res: NullObjectResponse = self
            .send_with_retry(self.client.post(url))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Fetch server logs.
    pub async fn logs(&self, count: u32) -> Result<Vec<String>> {
        let url = self.gen_server_url(vec!["logs", &count.to_string()])?;
        let res: StringVecResponse = self
            .send_with_retry(self.client.post(url))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Fetch Xray logs.
    pub async fn xray_logs(&self, count: u32) -> Result<Option<Vec<String>>> {
        let url = self.gen_server_url(vec!["xraylogs", &count.to_string()])?;
        let res: OptStringVecResponse = self
            .send_with_retry(self.client.post(url))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    /// Import DB upload.
    pub async fn import_db_upload(&self, filename: &str, bytes: Vec<u8>) -> Result<String> {
        let url = self.gen_server_url(vec!["importDB"])?;
        let form = Form::new().part("db", Part::bytes(bytes).file_name(filename.to_string()));
        let res: StringResponse = self
            .send_with_retry(self.client.post(url).multipart(form))
            .await?
            .json_verbose()
            .await?;
        res.into_result()
    }

    async fn send_with_retry(&self, builder: reqwest::RequestBuilder) -> Result<reqwest::Response> {
        if self.options.retry_count == 0 || builder.try_clone().is_none() {
            return Ok(builder.send().await?);
        }

        let mut last_err: Option<reqwest::Error> = None;
        for attempt in 0..=self.options.retry_count {
            let cloned = builder
                .try_clone()
                .ok_or_else(|| Error::OtherError("request is not clonable for retry".into()))?;
            let request = cloned.build()?;
            let method = request.method().clone();
            let response = self.client.execute(request).await;
            match response {
                Ok(resp) => {
                    if attempt < self.options.retry_count
                        && self.should_retry_status(&method, &resp)
                    {
                        let delay = self.retry_delay(attempt, resp.headers().get(RETRY_AFTER));
                        sleep(delay).await;
                        continue;
                    }
                    return Ok(resp);
                }
                Err(err) => {
                    if attempt < self.options.retry_count && self.should_retry_error(&method, &err)
                    {
                        last_err = Some(err);
                        sleep(self.retry_delay(attempt, None)).await;
                        continue;
                    }
                    return Err(err.into());
                }
            }
        }

        if let Some(err) = last_err {
            return Err(err.into());
        }
        Err(Error::OtherError("request retry failed".into()))
    }

    fn should_retry_status(&self, method: &Method, resp: &reqwest::Response) -> bool {
        if !self.is_idempotent(method) {
            return false;
        }
        let status = resp.status();
        status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
    }

    fn should_retry_error(&self, method: &Method, err: &reqwest::Error) -> bool {
        if !self.is_idempotent(method) {
            return false;
        }
        err.is_timeout() || err.is_connect()
    }

    fn is_idempotent(&self, method: &Method) -> bool {
        self.options.retry_methods.iter().any(|m| m == method)
    }

    fn retry_delay(
        &self,
        attempt: u32,
        retry_after: Option<&reqwest::header::HeaderValue>,
    ) -> Duration {
        if let Some(value) = retry_after
            && let Ok(s) = value.to_str()
            && let Ok(secs) = s.parse::<u64>()
        {
            return Duration::from_secs(secs);
        }
        let backoff = 1u64.checked_shl(attempt).unwrap_or(u64::MAX);
        let ms = self
            .options
            .retry_base_delay
            .as_millis()
            .saturating_mul(backoff as u128)
            .min(self.options.retry_max_delay.as_millis());
        Duration::from_millis(ms as u64)
    }
}
