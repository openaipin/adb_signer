use std::future::Future;

use base64::prelude::*;
use rsa::{pkcs8::DecodePrivateKey, Pkcs1v15Sign, RsaPrivateKey};
use sha1::{Digest, Sha1};
use types::{ErrorResponse, SignResponse};
use worker::*;

mod types;

#[event(fetch)]
async fn main(mut req: Request, env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();

    wrap_future_with_error(async move {
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

        let token = BASE64_STANDARD.encode(token);

        let response = SignResponse { token };
        Ok(Response::from_json(&response)?.with_status(200))
    })
    .await
}

async fn wrap_future_with_error<F>(future: F) -> Result<Response>
where
    F: Future<Output = Result<Response>>,
{
    let output = match future.await {
        Ok(response) => response,
        Err(err) => Response::from_json(&ErrorResponse {
            error: err.to_string(),
        })?
        .with_status(400),
    };

    Ok(output)
}
