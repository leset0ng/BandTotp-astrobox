use astrobox_ng_wit::astrobox::psys_host::{device, dialog, interconnect, thirdpartyapp};
use serde::Serialize;

/// Parsed TOTP entry, matching the Android `TOTPInfo` data class.
#[derive(Serialize, Clone, Debug)]
pub struct TotpInfo {
    pub name: String,
    pub usr: String,
    pub key: String,
    pub algorithm: String,
    pub digits: u32,
    pub period: u32,
}

/// The payload shape sent to the wearable: `{ "list": [...] }`.
#[derive(Serialize, Clone, Debug)]
pub struct SyncPayload {
    pub list: Vec<TotpInfo>,
}

impl SyncPayload {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| r#"{"list":[]}"#.to_string())
    }
}

/// Parse a single `otpauth://totp/...` URI into a `TotpInfo`.
pub fn parse_totp_uri(totp_uri: &str) -> Option<TotpInfo> {
    let trimmed = totp_uri.trim();
    if trimmed.is_empty() {
        return None;
    }

    let uri = url::Url::parse(trimmed).ok()?;

    if uri.scheme() != "otpauth" || uri.host_str() != Some("totp") {
        return None;
    }

    let path = uri.path();
    let stripped = path.trim_start_matches('/');
    let split_path: Vec<&str> = stripped.splitn(2, ':').collect();
    if split_path.len() != 2 {
        return None;
    }

    let issuer_from_path = split_path[0];
    let account = split_path[1];

    let secret = get_query_param(&uri, "secret")?;
    let issuer_from_query = get_query_param(&uri, "issuer");
    let name = issuer_from_query.unwrap_or_else(|| issuer_from_path.to_string());
    let algorithm = get_query_param(&uri, "algorithm").unwrap_or_else(|| "SHA1".to_string());
    let digits = get_query_param(&uri, "digits")
        .and_then(|v| v.parse().ok())
        .unwrap_or(6);
    let period = get_query_param(&uri, "period")
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);

    Some(TotpInfo {
        name,
        usr: account.to_string(),
        key: secret,
        algorithm,
        digits,
        period,
    })
}

fn get_query_param(uri: &url::Url, key: &str) -> Option<String> {
    uri.query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

/// Parse a multi-line text block into a list of valid TOTP entries.
pub fn parse_totp_text(text: &str) -> Vec<TotpInfo> {
    text.lines().filter_map(parse_totp_uri).collect()
}

/// Pick a plain-text file and return its contents as a string.
pub async fn pick_totp_file() -> Result<String, String> {
    let config = dialog::PickConfig {
        read: true,
        copy_to: None,
    };
    let filter = dialog::FilterConfig {
        multiple: false,
        extensions: vec![],
        default_directory: "".to_string(),
        default_file_name: "".to_string(),
    };

    let result = dialog::pick_file(&config, &filter).await;
    String::from_utf8(result.data).map_err(|e| format!("file is not valid UTF-8: {}", e))
}

/// Return the first currently connected wearable device, if any.
pub async fn first_connected_device() -> Result<device::DeviceInfo, String> {
    let devices = device::get_connected_device_list().await;
    devices.into_iter().next().ok_or_else(|| "no connected device".to_string())
}

/// Launch the BandTOTP quick app on the first connected device.
pub async fn launch_band_totp(app_pkg: &str) -> Result<String, String> {
    let dev = first_connected_device().await?;
    let apps = thirdpartyapp::get_thirdparty_app_list(&dev.addr)
        .await
        .map_err(|()| "device returned error while listing apps".to_string())?;

    let app = apps
        .into_iter()
        .find(|a| a.package_name == app_pkg || a.app_name == app_pkg)
        .ok_or_else(|| format!("quick app '{}' not found on {}", app_pkg, dev.name))?;

    thirdpartyapp::launch_qa(&dev.addr, &app, "pages/index")
        .await
        .map_err(|()| "failed to launch quick app".to_string())?;

    Ok(format!("opened {} on {}", app_pkg, dev.name))
}

/// Send the prepared JSON payload to the wearable quick app.
pub async fn send_payload(payload: &str, app_pkg: &str) -> Result<String, String> {
    let dev = first_connected_device().await?;
    interconnect::send_qaic_message(&dev.addr, app_pkg, payload)
        .await
        .map_err(|()| "device rejected message".to_string())?;

    Ok(format!("sent {} bytes to {}", payload.len(), dev.name))
}
