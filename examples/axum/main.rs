use std::{env, error::Error as StdError, net::SocketAddr};

use axum::{
    Json, Router,
    extract::Request,
    http::{StatusCode, header::COOKIE},
    response::{IntoResponse, Response},
    routing::get,
};
use http_extract::{
    Error,
    api_key::extract_header_api_key,
    authority::extract_request_authority,
    authorization::extract_header_authorization,
    client_ip::{extract_axum_peer_address, extract_axum_peer_ip, extract_client_ip},
    content_type::extract_header_content_type,
    forwarded::FORWARDED,
    request_id::extract_header_request_id,
    x_forwarded::X_FORWARDED_FOR,
};
use serde_json::{Value, json};

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError>> {
    tracing_subscriber::fmt()
        .with_target(false)
        .compact()
        .init();

    let listen_address = env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:3000".to_owned())
        .parse::<SocketAddr>()?;

    let listener = tokio::net::TcpListener::bind(listen_address).await?;
    tracing::info!(%listen_address, "listening");
    axum::serve(
        listener,
        build_app().into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

fn build_app() -> Router {
    Router::new().route("/request-context", get(request_context))
}

async fn request_context(request: Request) -> Result<Json<Value>, Response> {
    let peer: SocketAddr = extract_axum_peer_address(&request).ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "connection information unavailable\n",
        )
            .into_response()
    })?;
    let headers = request.headers();
    let client_ip = extract_client_ip(headers).map_err(reject_metadata)?;
    let cookie_field_count = headers.get_all(COOKIE).iter().count();
    let authorization = extract_header_authorization(headers).map_err(reject_metadata)?;
    let api_key = extract_header_api_key(headers).map_err(reject_metadata)?;
    let cookies = headers
        .get_all(COOKIE)
        .iter()
        .map(|value| value.to_str().map(mask_sensitive))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid request metadata\n").into_response())?;

    let context = json!({
        "peer_address": peer.to_string(),
        "peer_ip": extract_axum_peer_ip(&request).map(|ip| ip.to_string()),
        "client_ip": client_ip.map(|address| address.to_string()),
        "client_source": client_ip.and_then(|_| selected_client_source(headers)),
        "authority": extract_request_authority(&request)
            .map_err(reject_metadata)?
            .map(|authority| authority.to_string()),
        "request_id": extract_header_request_id(headers).map_err(reject_metadata)?,
        "content_type": extract_header_content_type(headers)
            .map_err(reject_metadata)?
            .map(|content_type| content_type.to_string()),
        "authorization": authorization.map(mask_sensitive),
        "api_key": api_key.map(mask_sensitive),
        "cookies": cookies,
        "cookie_present": cookie_field_count > 0,
        "cookie_field_count": cookie_field_count,
    });

    tracing::info!(request_context = %context, "request metadata extracted");
    Ok(Json(context))
}

fn mask_sensitive(value: &str) -> String {
    let length = value.chars().count();
    if length <= 4 {
        return "*".repeat(length);
    }

    let prefix: String = value.chars().take(2).collect();
    let mut suffix: Vec<char> = value.chars().rev().take(2).collect();
    suffix.reverse();
    format!("{prefix}***{}", suffix.into_iter().collect::<String>())
}

fn selected_client_source(headers: &http::HeaderMap) -> Option<&'static str> {
    if headers.contains_key("cf-connecting-ip") {
        Some("cf-connecting-ip")
    } else if headers.contains_key("x-real-ip") {
        Some("x-real-ip")
    } else if headers.contains_key(&FORWARDED) {
        Some("forwarded")
    } else if headers.contains_key(&X_FORWARDED_FOR) {
        Some("x-forwarded-for")
    } else {
        None
    }
}

fn reject_metadata(error: Error) -> Response {
    // http_extract::Error carries only field names, never parser details or
    // field values.
    tracing::warn!(error = %error, "request metadata rejected");
    (StatusCode::BAD_REQUEST, "invalid request metadata").into_response()
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, extract::ConnectInfo};
    use http::Request;
    use tower::ServiceExt;

    use super::*;

    fn request_with_peer(uri: &str) -> http::request::Builder {
        Request::builder().uri(uri).extension(ConnectInfo(
            "127.0.0.1:43210".parse::<SocketAddr>().unwrap(),
        ))
    }

    async fn response_json(response: Response) -> Value {
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[test]
    fn extracts_axum_peer_from_request_extensions() {
        let request = request_with_peer("/").body(()).unwrap();
        assert_eq!(
            extract_axum_peer_address(&request),
            Some("127.0.0.1:43210".parse().unwrap())
        );

        let request = Request::new(());
        assert_eq!(extract_axum_peer_address(&request), None);
    }

    #[test]
    fn masks_sensitive_values_without_splitting_utf8() {
        assert_eq!(mask_sensitive("ab1234cd"), "ab***cd");
        assert_eq!(mask_sensitive("中文明文内容"), "中文***内容");
        assert_eq!(mask_sensitive("abcd"), "****");
        assert_eq!(mask_sensitive(""), "");
    }

    #[tokio::test]
    async fn client_error_response_is_clear_and_does_not_echo_input() {
        let request = request_with_peer("/request-context")
            .header("x-forwarded-for", "not-an-address")
            .body(Body::empty())
            .unwrap();
        let response = build_app().oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(body.as_ref(), b"invalid request metadata");
        assert!(!String::from_utf8_lossy(&body).contains("not-an-address"));
    }

    #[tokio::test]
    async fn one_step_axum_request_demo_returns_complete_safe_json() {
        let raw_forwarded_chain = "198.51.100.8, 127.0.0.2";
        let request = request_with_peer("/request-context?private=query-secret")
            .header("host", "api.example.test")
            .header("x-real-ip", "198.51.100.9")
            .header("x-forwarded-for", raw_forwarded_chain)
            .header("x-request-id", "request-123")
            .header("content-type", "application/json")
            .header("authorization", "Bearer authorization-secret")
            .header("cookie", "session=cookie-secret")
            .header("x-api-key", "api-key-secret")
            .body(Body::from("body-secret"))
            .unwrap();

        let context = response_json(build_app().oneshot(request).await.unwrap()).await;
        assert_eq!(context["peer_address"], "127.0.0.1:43210");
        assert_eq!(context["peer_ip"], "127.0.0.1");
        assert_eq!(context["client_ip"], "198.51.100.9");
        assert_eq!(context["client_source"], "x-real-ip");
        assert_eq!(context["authority"], "api.example.test");
        assert_eq!(context["request_id"], "request-123");
        assert_eq!(context["content_type"], "application/json");
        assert_eq!(context["authorization"], "Be***et");
        assert_eq!(context["api_key"], "ap***et");
        assert_eq!(context["cookies"][0], "se***et");
        assert_eq!(context["cookie_present"], true);
        assert_eq!(context["cookie_field_count"], 1);

        println!("complete safe request context: {context:#}");
        let observable = context.to_string();
        for excluded in [
            raw_forwarded_chain,
            "query-secret",
            "authorization-secret",
            "cookie-secret",
            "api-key-secret",
            "body-secret",
        ] {
            assert!(!observable.contains(excluded));
        }
    }

    #[tokio::test]
    async fn optional_values_are_null_when_absent() {
        let request = request_with_peer("/request-context")
            .body(Body::empty())
            .unwrap();
        let context = response_json(build_app().oneshot(request).await.unwrap()).await;

        assert!(context["client_ip"].is_null());
        assert!(context["client_source"].is_null());
        assert!(context["authority"].is_null());
        assert!(context["request_id"].is_null());
        assert!(context["content_type"].is_null());
        assert!(context["authorization"].is_null());
        assert!(context["api_key"].is_null());
        assert_eq!(context["cookies"], json!([]));
        assert_eq!(context["cookie_present"], false);
        assert_eq!(context["cookie_field_count"], 0);
    }
}
