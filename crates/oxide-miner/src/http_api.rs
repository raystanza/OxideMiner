use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use tokio::net::TcpListener;
use tracing::info;

pub async fn run_http_api(port: u16, accepted: Arc<AtomicU64>, rejected: Arc<AtomicU64>) {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = match TcpListener::bind(addr).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("HTTP bind failed: {e}");
            return;
        }
    };
    info!("HTTP API listening on http://{addr}");

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("HTTP accept error: {e}");
                continue;
            }
        };
        let io = TokioIo::new(stream);
        let a = accepted.clone();
        let r = rejected.clone();

        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<Incoming>| {
                let a = a.clone();
                let r = r.clone();

                async move {
                    if req.method() == Method::GET && req.uri().path() == "/metrics" {
                        let body = format!(
                            "{{\"accepted\":{},\"rejected\":{}}}",
                            a.load(Ordering::Relaxed),
                            r.load(Ordering::Relaxed)
                        );
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(body))))
                    } else {
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(404)
                                .body(Full::new(Bytes::from("not found")))
                                .unwrap(),
                        )
                    }
                }
            });

            if let Err(err) = http1::Builder::new().serve_connection(io, svc).await {
                eprintln!("http connection error: {err}");
            }
        });
    }
}
