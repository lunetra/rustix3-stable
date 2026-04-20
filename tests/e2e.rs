use anyhow::Context;
use dotenv::dotenv;
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{Duration, sleep};
use uuid::Uuid;

use rustix3::models::TgId;
use rustix3::{
    client::Client,
    inbounds::{InboundProtocols, SniffingOption, TransportProtocol},
    models::{
        ClientRequest, ClientSettings, CreateInboundRequest, Fallback, SettingsRequest, Sniffing,
        StreamSettings, TcpHeader, TcpSettings, UserRequest,
    },
};

fn future_expiry_ms(days: u64) -> i64 {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_millis() as i64;
    let delta = (days as i64) * 24 * 60 * 60 * 1000;
    now_ms + delta
}

fn default_stream_settings() -> StreamSettings {
    StreamSettings {
        network: Some(TransportProtocol::Tcp),
        security: Some("none".into()),
        external_proxy: Some(Vec::new()),
        tcp_settings: Some(TcpSettings {
            accept_proxy_protocol: Some(false),
            header: Some(TcpHeader {
                header_type: Some("none".into()),
                extra: Default::default(),
            }),
            extra: Default::default(),
        }),
        ws_settings: None,
        grpc_settings: None,
        kcp_settings: None,
        http_upgrade_settings: None,
        xhttp_settings: None,
        extra: Default::default(),
    }
}

fn default_sniffing() -> Sniffing {
    Sniffing {
        enabled: false,
        dest_override: vec![
            SniffingOption::Http,
            SniffingOption::Tls,
            SniffingOption::Quic,
            SniffingOption::FakeDns,
        ],
        metadata_only: false,
        route_only: false,
        extra: Default::default(),
    }
}

fn default_allocate() -> serde_json::Value {
    json!({
        "strategy": "always",
        "refresh": 5,
        "concurrency": 3
    })
}

#[tokio::test]
async fn e2e_full_flow() -> anyhow::Result<()> {
    dotenv().ok();
    env_logger::init();

    log::info!("Starting full flow");
    let base = env::var("PANEL_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:2053/".into());
    let user = env::var("PANEL_USERNAME").unwrap_or_else(|_| "admin".into());
    let pass = env::var("PANEL_PASSWORD").unwrap_or_else(|_| "admin".into());

    let client = Client::new(user, pass, base).await.context("login")?;
    log::info!("connected");

    let list_before = client.get_inbounds_list().await.context("list")?;
    log::info!("list_before = {:#?}", list_before);

    let remark = format!("e2e-{}", Uuid::new_v4());
    let inbound_expiry = future_expiry_ms(30);
    let req = CreateInboundRequest {
        up: 0,
        down: 0,
        total: 0,
        remark: remark.clone(),
        enable: true,
        expiry_time: inbound_expiry,
        listen: "0.0.0.0".into(),
        port: 31001,
        protocol: InboundProtocols::Vless,
        settings: SettingsRequest {
            clients: vec![],
            decryption: Some("none".into()),
            encryption: Some("none".into()),
            fallbacks: Vec::<Fallback>::new(),
        },
        stream_settings: default_stream_settings(),
        sniffing: default_sniffing(),
        allocate: default_allocate(),
    };

    let created = client.add_inbound(&req).await.context("add_inbound")?;

    let inbounds = client.get_inbounds_list().await.context("list")?;
    log::info!("inbounds = {:#?}", inbounds);

    let inbound_id = created.id;

    let by_id = client
        .get_inbound_by_id(inbound_id)
        .await
        .context("get_by_id")?;
    assert_eq!(by_id.remark, remark);

    let mut updated_req = req;
    updated_req.remark = format!("{}-upd", remark);
    let updated = client
        .update_inbound(inbound_id, &updated_req)
        .await
        .context("update_inbound")?;
    assert_eq!(updated.remark, updated_req.remark);

    let cuuid = Uuid::new_v4().to_string();
    let email = format!("{}@example.com", cuuid);
    let sub_id = Uuid::new_v4().simple().to_string();
    let user_obj = UserRequest {
        id: cuuid.clone(),
        flow: String::new(),
        email: email.clone(),
        limit_ip: 2,
        total_gb: 100,
        expiry_time: future_expiry_ms(14),
        enable: true,
        tg_id: Some(TgId::Int(0)),
        sub_id,
        reset: 0,
    };
    let add_client_req = ClientRequest {
        id: inbound_id,
        settings: ClientSettings {
            clients: vec![user_obj.clone()],
        },
    };
    client
        .add_client_to_inbound(&add_client_req)
        .await
        .context("add_client")?;

    let inbounds = client.get_inbounds_list().await.context("list")?;
    log::info!("inbounds = {:#?}", inbounds);

    sleep(Duration::from_millis(200)).await;

    let traffic_by_email = client
        .get_client_traffic_by_email(email.clone())
        .await
        .context("traffic_by_email")?;
    assert_eq!(traffic_by_email.email, email);

    let traffic_by_id = client
        .get_client_traffic_by_id(cuuid.clone())
        .await
        .context("traffic_by_id")?;
    log::info!("traffic_by_id = {:#?}", traffic_by_id);

    let mut updated_user = user_obj;
    updated_user.limit_ip = 1;
    let upd_client_req = ClientRequest {
        id: inbound_id,
        settings: ClientSettings {
            clients: vec![updated_user],
        },
    };
    client
        .update_client(&cuuid, &upd_client_req)
        .await
        .context("update_client")?;

    client.clear_client_ips(&email).await.context("clear_ips")?;

    client
        .reset_client_traffic(inbound_id, &email)
        .await
        .context("reset_client")?;

    client
        .reset_all_client_traffics(inbound_id)
        .await
        .context("reset_all_clients")?;

    client
        .reset_all_inbound_traffics()
        .await
        .context("reset_all_inbounds")?;

    let onlines = client.online_clients().await.context("online_clients")?;

    log::info!("onlines = {:#?}", onlines);

    let cuuid = Uuid::new_v4().to_string();
    let email = format!("{}@example.com", cuuid);
    let sub_id = Uuid::new_v4().simple().to_string();
    let user_obj = UserRequest {
        id: cuuid.clone(),
        flow: String::new(),
        email: email.clone(),
        limit_ip: 2,
        total_gb: 100,
        expiry_time: future_expiry_ms(14),
        enable: true,
        tg_id: Some(TgId::Int(0)),
        sub_id,
        reset: 0,
    };
    let add_client_req = ClientRequest {
        id: inbound_id,
        settings: ClientSettings {
            clients: vec![user_obj.clone()],
        },
    };
    client
        .add_client_to_inbound(&add_client_req)
        .await
        .context("add_client")?;

    let inbounds = client.get_inbounds_list().await.context("list")?;
    log::info!("inbounds = {:#?}", inbounds);

    client
        .delete_client(inbound_id, &cuuid)
        .await
        .context("delete_client")?;

    let inbounds = client.get_inbounds_list().await.context("list")?;
    log::info!("inbounds = {:#?}", inbounds);

    client
        .delete_depleted_clients(inbound_id)
        .await
        .context("delete_depleted")?;

    let del_inbound = client
        .delete_inbound(inbound_id)
        .await
        .context("delete_inbound")?;

    log::info!("del_inbound = {:#?}", del_inbound);

    let list_after = client.get_inbounds_list().await.context("list_after")?;
    log::info!("list_after = {:#?}", list_after);

    let last_online = client.get_last_online().await.context("last_online")?;
    log::info!("last_online = {:#?}", last_online);

    let cuuid = Uuid::new_v4().to_string();
    let email = "testclient".to_string();
    let sub_id = Uuid::new_v4().simple().to_string();
    let user_obj1 = UserRequest {
        id: cuuid.clone(),
        flow: String::new(),
        email: email.clone(),
        limit_ip: 2,
        total_gb: 100,
        expiry_time: future_expiry_ms(7),
        enable: true,
        tg_id: Some(TgId::Int(0)),
        sub_id,
        reset: 0,
    };

    let cuuid = Uuid::new_v4().to_string();
    let email = "testclient2".to_string();
    let sub_id = Uuid::new_v4().simple().to_string();
    let user_obj2 = UserRequest {
        id: cuuid.clone(),
        flow: String::new(),
        email: email.clone(),
        limit_ip: 2,
        total_gb: 100,
        expiry_time: future_expiry_ms(7),
        enable: true,
        tg_id: Some(TgId::Int(0)),
        sub_id,
        reset: 0,
    };

    let remark2 = format!("e2e-del-by-email-{}", Uuid::new_v4());
    let inbound_expiry = future_expiry_ms(30);
    let tmp_inb_req = CreateInboundRequest {
        up: 0,
        down: 0,
        total: 0,
        remark: remark2.clone(),
        enable: true,
        expiry_time: inbound_expiry,
        listen: "0.0.0.0".into(),
        port: 31002,
        protocol: InboundProtocols::Vless,
        settings: SettingsRequest {
            clients: vec![user_obj1, user_obj2],
            decryption: Some("none".into()),
            encryption: Some("none".into()),
            fallbacks: Vec::<Fallback>::new(),
        },
        stream_settings: default_stream_settings(),
        sniffing: default_sniffing(),
        allocate: default_allocate(),
    };
    let tmp_created = client
        .add_inbound(&tmp_inb_req)
        .await
        .context("add_inbound_tmp")?;
    let tmp_inbound_id = tmp_created.id;

    let tmp = client.get_inbounds_list().await.context("tmp inbound")?;
    log::info!("tmp inbound = {:#?}", tmp);

    client
        .del_client_by_email(tmp_inbound_id, &email)
        .await
        .context("del_client_by_email")?;

    let res = client
        .delete_inbound(tmp_inbound_id)
        .await
        .context("del_tmp_inbound")?;
    log::info!("delete_inbound = {:#?}", res);

    let srv_status = client.server_status().await.context("server_status")?;
    log::info!("srv_status = {:#?}", srv_status);

    let db_bytes = client.server_get_db().await.context("server_get_db")?;
    assert!(!db_bytes.is_empty(), "db should not be empty");

    let imported_db = client
        .import_db_upload("file", db_bytes.clone())
        .await
        .context("import_db_upload")?;
    log::info!("imported_db = {:#?}", imported_db);

    let xver = client.get_xray_version().await.context("xray_version")?;
    let current_version = xver.clone().unwrap_or_default();

    let cfg = client.get_config_json().await.context("get_config_json")?;
    log::info!("cfg = {:#?}", cfg);

    let cpu_hist = client.cpu_history(2).await.context("cpu_history_1min")?; // todo bucket

    if let Some(first) = cpu_hist.as_ref().and_then(|v| v.first()) {
        assert!(first.t > 0, "cpu history timestamp should be > 0");
    }

    let new_uuid = client.get_new_uuid().await.context("get_new_uuid")?;

    log::info!("new_uuid = {:#?}", new_uuid);

    let x25519 = client
        .get_new_x25519_cert()
        .await
        .context("get_new_x25519")?;
    log::info!("x25519 = {:#?}", x25519);

    let mldsa = client.get_new_mldsa65().await.context("get_new_mldsa65")?;
    log::info!("mldsa = {:#?}", mldsa);

    let mlkem = client
        .get_new_mlkem768()
        .await
        .context("get_new_mlkem768")?;
    log::info!("mlkem768 = {:#?}", mlkem);

    let venc = client
        .get_new_vless_enc()
        .await
        .context("get_new_vless_enc")?;
    log::info!("vless enc = {:#?}", venc);

    let ech = client
        .get_new_ech_cert()
        .await
        .context("get_new_ech_cert")?;
    log::info!("ech = {:#?}", ech);

    client
        .stop_xray_service()
        .await
        .context("stop_xray_service")?;

    sleep(Duration::from_secs(1)).await;

    client
        .restart_xray_service()
        .await
        .context("restart_xray_service")?;

    sleep(Duration::from_secs(2)).await;

    log::info!("ver: {:#?}", current_version.first().context("version"));

    client
        .install_xray_version(current_version.first().context("version")?)
        .await
        .context("install_xray_version")?;

    client.update_geofile().await.context("update_geofile")?;

    client
        .update_geofile_by_name("geoip.dat")
        .await
        .context("update_geofile_by_name")?;

    let logs = client.logs(50).await.context("logs_count")?;
    log::info!("logs = {:#?}", logs);

    let xlogs = client.xray_logs(50).await.context("xray_logs_count")?;
    log::info!("xlogs = {:#?}", xlogs);

    let remark = format!("e2e-{}", Uuid::new_v4());
    let inbound_expiry = future_expiry_ms(30);
    let req = CreateInboundRequest {
        up: 0,
        down: 0,
        total: 0,
        remark: remark.clone(),
        enable: true,
        expiry_time: inbound_expiry,
        listen: "0.0.0.0".into(),
        port: 31001,
        protocol: InboundProtocols::Vless,
        settings: SettingsRequest {
            clients: vec![],
            decryption: Some("none".into()),
            encryption: Some("none".into()),
            fallbacks: Vec::<Fallback>::new(),
        },
        stream_settings: default_stream_settings(),
        sniffing: default_sniffing(),
        allocate: default_allocate(),
    };

    let created = client.add_inbound(&req).await.context("add_inbound")?;
    log::info!("created = {:#?}", created);

    let inbds = client
        .get_inbounds_list()
        .await
        .context("list_for_import")?;

    log::info!("{:#?}", inbds);

    let mut import = inbds[0].clone();
    import.port = 30222;
    let import_inb = client
        .import_inbound(&import)
        .await
        .context("import_inbounds")?;
    log::info!("import_inbound = {:#?}", import_inb);
    Ok(())
}
use serde_json::json;
