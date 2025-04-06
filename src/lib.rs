use std::future::Future;

use base64::prelude::*;
use crypto::android_pubkey_encode;
use rsa::{pkcs8::DecodePrivateKey, Pkcs1v15Sign, RsaPrivateKey};
use sha1::{Digest, Sha1};
use types::{ErrorResponse, SignResponse};
use worker::*;

mod crypto;
mod types;

#[event(fetch)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();

    let mut response = wrap_future_with_error(async move {
        match req.method() {
            Method::Get => http_get_redirect(env).await,
            Method::Post => sign(req, env).await,
            _ => Ok(ErrorResponse::new("Unsupported method", 400)),
        }
    })
    .await;

    // Apply shared CORS headers to all responses
    let _ = response
        .headers_mut()
        .set("Access-Control-Allow-Origin".into(), "*".into());

    Ok(response)
}

async fn http_get_redirect(env: Env) -> Result<Response> {
    let redirect_url = env.secret("REDIRECT_URL")?.to_string();
    let redirect_url = Url::parse(&redirect_url)?;

    Response::redirect(redirect_url)
}

async fn sign(mut req: Request, env: Env) -> Result<Response> {
    // The private key must have the full header and newlines, like it would be stored in the pem file
    let private_key = env.secret("PRIVATE_KEY")?.to_string();
    let private_key = match RsaPrivateKey::from_pkcs8_pem(&private_key) {
        Ok(key) => key,
        Err(err) => return Err(Error::RustError(err.to_string())),
    };

    let bytes = req.bytes().await?;

    if bytes.len() != Sha1::output_size() {
        return Err(Error::RustError(format!(
            "Input must be {} bytes",
            Sha1::output_size()
        )));
    }

    let token = match private_key.sign(Pkcs1v15Sign::new::<Sha1>(), bytes.as_ref()) {
        Ok(token) => token,
        Err(err) => return Err(Error::RustError(err.to_string())),
    };

    // We could have this be staticly created from the private key on deploy, but I want to make sure they stay in sync
    let public_key = android_pubkey_encode(private_key)?;

    let token = BASE64_STANDARD.encode(token);

    let response = SignResponse { token, public_key };

    Ok(Response::from_json(&response)?.with_status(200))
}

async fn wrap_future_with_error<F>(future: F) -> Response
where
    F: Future<Output = Result<Response>>,
{
    let output = match future.await {
        Ok(response) => response,
        Err(err) => ErrorResponse::new(&err.to_string(), 400),
    };

    output
}
