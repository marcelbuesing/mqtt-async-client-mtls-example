use anyhow::{anyhow, Result};
use mqtt_async_client::client::{Client, Publish};
use rustls::{
    internal::msgs::handshake::DigitallySignedStruct, Certificate, HandshakeSignatureValid,
    RootCertStore, ServerCertVerified, TLSError,
};
use std::{io::Cursor, sync::Arc, time::Duration};
use tracing::error;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let mut client = init_client()?;
    client.connect().await?;
    println!("Successfully connected to broker");
    let p = Publish::new("hello".to_string(), b"hi".to_vec());
    client.publish(&p).await?;
    println!("Successfully published message to hello topic");
    // Connect errors are not necessarily directly visible right now
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

fn init_client() -> Result<Client> {
    let mut b = Client::builder();
    b.set_url_string("mqtts://localhost:1883")?
        .set_username(Some("johndoe".to_string()))
        .set_password(Some(b"pass".to_vec()));

    let mut client_config = rustls::ClientConfig::new();

    // Server certificate to verify server
    let cert_bytes = std::fs::read("../server/certs/ca/ca.crt")?;
    let ca_certs = rustls::internal::pemfile::certs(&mut Cursor::new(&cert_bytes[..]))
        .map_err(|_| anyhow!("Failed to read server cert"))?;

    client_config
        .dangerous()
        .set_certificate_verifier(Arc::new(SelfSignedCertVerifier {
            certs: ca_certs.clone(),
        }));

    client_config.root_store.add(&ca_certs[0])?;

    // Client certificate so server can verify the client
    let cert_bytes = std::fs::read("../server/certs/client/client.crt")?;
    let client_cert = rustls::internal::pemfile::certs(&mut Cursor::new(&cert_bytes[..]))
        .map_err(|_| anyhow!("Failed to read client cert"))?;

    let key_bytes = std::fs::read("../server/certs/client/client.key")?;
    let client_key = rustls::internal::pemfile::rsa_private_keys(&mut Cursor::new(&key_bytes[..]))
        .map_err(|_| anyhow!("Failed to read client key"))?;

    client_config.set_single_client_cert(vec![client_cert[0].clone()], client_key[0].clone())?;
    b.set_tls_client_config(client_config);

    let client = b.build()?;
    Ok(client)
}

struct SelfSignedCertVerifier {
    certs: Vec<rustls::Certificate>,
}

impl rustls::ServerCertVerifier for SelfSignedCertVerifier {
    fn verify_server_cert(
        &self,
        _roots: &RootCertStore,
        presented_certs: &[Certificate],
        dns_name: webpki::DNSNameRef,
        _ocsp_response: &[u8],
    ) -> Result<ServerCertVerified, TLSError> {
        if presented_certs.is_empty() {
            return Err(TLSError::NoCertificatesPresented);
        }

        if presented_certs[1] == self.certs[0] {
            return Ok(rustls::ServerCertVerified::assertion());
        }

        let untrusted_der: Vec<&[u8]> = presented_certs
            .iter()
            .map(|certificate| certificate.0.as_slice())
            .collect();

        let leaf = webpki::EndEntityCert::from(untrusted_der[0])
            .map_err(|_| rustls::TLSError::WebPKIError(webpki::Error::UnsupportedCertVersion))?;
        leaf.verify_is_valid_for_dns_name(dns_name).unwrap();

        Err(rustls::TLSError::WebPKIError(webpki::Error::UnknownIssuer))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TLSError> {
        let x509_cert = x509_signature::parse_certificate(&cert.0).map_err(
            |x509_err: x509_signature::Error| {
                error!("error parsing certificate: {}", x509_err);
                rustls::TLSError::WebPKIError(x509_err)
            },
        )?;
        x509_cert
            .check_signature(convert_scheme(dss.scheme)?, message, &dss.sig.0)
            .map_err(|x509_err: x509_signature::Error| {
                error!("error checking signature: {}", x509_err);
                rustls::TLSError::WebPKIError(x509_err)
            })?;
        Ok(rustls::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TLSError> {
        let x509_cert = x509_signature::parse_certificate(&cert.0).map_err(
            |x509_err: x509_signature::Error| {
                error!("error parsing certificate: {}", x509_err);
                rustls::TLSError::WebPKIError(x509_err)
            },
        )?;
        x509_cert
            .check_signature(convert_scheme(dss.scheme)?, message, &dss.sig.0)
            .map_err(|x509_err: x509_signature::Error| {
                error!("error checking signature: {}", x509_err);
                rustls::TLSError::WebPKIError(x509_err)
            })?;
        Ok(HandshakeSignatureValid::assertion())
    }
}

fn convert_scheme(
    scheme: rustls::SignatureScheme,
) -> Result<x509_signature::SignatureScheme, TLSError> {
    match scheme {
        // nb. for TLS1.2 the curve is not fixed by SignatureScheme.
        rustls::SignatureScheme::ECDSA_NISTP256_SHA256 => {
            Ok(x509_signature::SignatureScheme::ECDSA_NISTP256_SHA256)
        }
        rustls::SignatureScheme::ECDSA_NISTP384_SHA384 => {
            Ok(x509_signature::SignatureScheme::ECDSA_NISTP384_SHA384)
        }

        rustls::SignatureScheme::ED25519 => Ok(x509_signature::SignatureScheme::ED25519),

        rustls::SignatureScheme::RSA_PKCS1_SHA256 => {
            Ok(x509_signature::SignatureScheme::RSA_PKCS1_SHA256)
        }
        rustls::SignatureScheme::RSA_PKCS1_SHA384 => {
            Ok(x509_signature::SignatureScheme::RSA_PKCS1_SHA384)
        }
        rustls::SignatureScheme::RSA_PKCS1_SHA512 => {
            Ok(x509_signature::SignatureScheme::RSA_PKCS1_SHA512)
        }

        rustls::SignatureScheme::RSA_PSS_SHA256 => {
            Ok(x509_signature::SignatureScheme::RSA_PSS_SHA256)
        }
        rustls::SignatureScheme::RSA_PSS_SHA384 => {
            Ok(x509_signature::SignatureScheme::RSA_PSS_SHA384)
        }
        rustls::SignatureScheme::RSA_PSS_SHA512 => {
            Ok(x509_signature::SignatureScheme::RSA_PSS_SHA512)
        }

        _ => {
            let error_msg = format!("received unadvertised sig scheme {:?}", scheme);
            Err(TLSError::PeerIncompatibleError(error_msg))
        }
    }
}
