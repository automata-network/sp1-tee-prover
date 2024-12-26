use sp1_tee_prover::chain::TxSender;

use alloy::primitives::Address;
use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use lazy_static::lazy_static;
use secp256k1::hashes::{sha256, Hash};
use secp256k1::{Message, Secp256k1, SecretKey, PublicKey};
use serde::{Deserialize, Serialize};
use sp1_sdk::{HashableKey, ProverClient, SP1Stdin};
use sp1_sdk::network::proto::network::ProofMode;
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::{sync::{Arc, Mutex}, time::Duration};
use tdx::device::DeviceOptions;
use tdx::Tdx;
use tokio::{task, time};
use tokio::net::TcpListener;
use uuid::Uuid;

/// Simple SP1-TEE-Prover in TDX
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The private key of the account to register TEE prover periodically
    #[arg(short, long)]
    key: String,
    /// The RPC URL to interact with the blockchain
    #[arg(short, long, default_value_t = format!("https://rpc-testnet.ata.network"))]
    rpc_url: String,
    /// The TEE registry contract
    #[arg(short, long, default_value_t = format!("6D67Ae70d99A4CcE500De44628BCB4DaCfc1A145"))]
    contract: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RequestProofBody {
    pub elf: Vec<u8>,
    pub stdin: SP1Stdin,
    pub proof_mode: ProofMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TEEProof {
    pub signature: Vec<u8>,
    pub vk: Vec<u8>,
    pub public_values: Vec<u8>,
}

pub struct TEEKeyPair {
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
}

lazy_static! {
    static ref TEE_KEY_PAIR: Arc<Mutex<TEEKeyPair>> = {
        let key_pair = generate_key_pair();
        Arc::new(Mutex::new(key_pair))
    };
    static ref PROOFS: Arc<Mutex<BTreeMap<String, TEEProof>>> = {
        Arc::new(Mutex::new(BTreeMap::new()))
    };
}

fn generate_key_pair() -> TEEKeyPair {
    let secp = Secp256k1::new();
    let mut rng = rand::thread_rng();
    let (secret_key, public_key) = secp.generate_keypair(&mut rng);
    TEEKeyPair { secret_key, public_key }
}

fn evm_address_from_public_key(public_key: &PublicKey) -> Address {
    let public_key = public_key.serialize_uncompressed();
    let hash = web3::signing::keccak256(&public_key[1..]);
    Address::from_slice(&hash[12..])
}

fn tee_sign(vk: &[u8], public_values: &[u8]) -> Vec<u8> {
    let tee_key_pair = TEE_KEY_PAIR.lock().unwrap();
    let secp = Secp256k1::new();
    
    let mut msg = Vec::new();
    msg.append(&mut vk.to_vec());
    msg.append(&mut public_values.to_vec());
    let msg = sha256::Hash::hash(&msg);
    let msg = Message::from_digest_slice(msg.as_ref()).unwrap();
    let sig = secp.sign_ecdsa_recoverable(&msg, &tee_key_pair.secret_key);
    let (recovery_id, serialize_sig) = sig.serialize_compact();
    let mut recovery_id_vec = vec![recovery_id as u8];
    let mut result = Vec::new();
    result.append(&mut recovery_id_vec);
    result.append(&mut serialize_sig.to_vec());
    result
}

async fn handle_request(req: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    match (req.method(), req.uri().path()) {
        (&Method::POST, "/request_proof") => {
            let body_bytes = req.collect().await.unwrap().to_bytes();

            // Parse request
            let request_body: RequestProofBody = match serde_json::from_slice(&body_bytes) {
                Ok(body) => body,
                Err(_) => {
                    return Ok(
                        Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Full::new(Bytes::from("Invalid body")))
                        .unwrap()
                    );
                }
            };

            // Generate TEE proof
            let proof_id = Uuid::new_v4().to_string();
            let client = ProverClient::new();
            let (public_values, report) = client.execute(&request_body.elf, request_body.stdin).run().unwrap();
            log::info!("executed program with {} cycles", report.total_instruction_count());
            let (_proving_key, verifying_key) = client.setup(&request_body.elf);
            let sig = tee_sign(&verifying_key.hash_bytes(), &public_values.as_slice());
            let tee_proof = TEEProof {
                signature: sig,
                vk: verifying_key.hash_bytes().to_vec(),
                public_values: public_values.as_slice().to_vec(),
            };
            let mut proofs = PROOFS.lock().unwrap();
            proofs.insert(proof_id.clone(), tee_proof);

            Ok(Response::new(Full::new(Bytes::from(proof_id))))
        },
        (&Method::POST, "/wait_proof") => {
            let body_bytes = req.collect().await.unwrap().to_bytes();

            // Parse request
            let proof_id = match String::from_utf8(body_bytes.to_vec()) {
                Ok(s) => s,
                Err(_) => {
                    return Ok(
                        Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Full::new(Bytes::from("Invalid body")))
                        .unwrap()
                    );
                }
            };

            // Get proof
            let proofs = PROOFS.lock().unwrap();
            if !proofs.contains_key(&proof_id) {
                return Ok(
                    Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Full::new(Bytes::from(format!("{:?} Not found", proof_id))))
                    .unwrap()
                );
            }
            let response = proofs.get(&proof_id).unwrap();

            Ok(Response::new(Full::new(Bytes::from(serde_json::to_string(response).unwrap()))))
        },
        _ => {
            return Ok(
                Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from("")))
                .unwrap()
            );
        }
    }
}

// rotate the key pair every 30 mins
async fn key_rotation_task() {
    let mut interval = time::interval(Duration::from_secs(1800));
    loop {
        interval.tick().await;
        let new_key_pair = generate_key_pair();
        // Replace the key pair
        let new_evm_account = {
            let mut tee_key_pair_guard = TEE_KEY_PAIR.lock().unwrap();
            *tee_key_pair_guard = new_key_pair;
            let new_evm_account = evm_address_from_public_key(&tee_key_pair_guard.public_key);
            log::info!("Key pair updated, new evm account: {:?}", new_evm_account);
            drop(tee_key_pair_guard);
            new_evm_account
        };
        // Update the TEE registry
        {
            let args = Args::parse();
            let mut tx_sender = TxSender::new(&args.rpc_url, &args.contract).unwrap();
            tx_sender.set_wallet(&args.key).unwrap();
            let (report_data, isv_report_data) = tx_sender.generate_report_data(new_evm_account).await.unwrap();
            // Initialise a TDX object
            let tdx = Tdx::new();
            // Retrieve an attestation report with default options passed to the hardware device
            let tdx_dcap_quote = tdx.get_attestation_report_raw_with_options(
                DeviceOptions {
                    report_data: Some(isv_report_data),
                }
            ).unwrap();
            log::debug!("TDX Quote: {:?}", hex::encode(tdx_dcap_quote.clone()));
            let calldata = tx_sender.generate_register_calldata(report_data, tdx_dcap_quote);
            log::debug!("calldata: {:?}", calldata);
            let tx_receipt = tx_sender.send(calldata.clone()).await.unwrap();
            let hash = tx_receipt.transaction_hash;
            log::info!("See transaction at: 0x{}", hex::encode(hash.as_slice()));
        }
        // TODO: clean up the out-of-date TEE proofs to reduce memory usage
    }
}

async fn server() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    log::info!("Server running on http://{}", addr);
    let listener = TcpListener::bind(addr).await.unwrap();
    loop {
        let (stream, _addr) = listener.accept().await.unwrap();
        let io = TokioIo::new(stream);
        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service_fn(handle_request))
                .await
            {
                log::error!("Error serving connection: {:?}", err);
            }
        });
    }
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    let key_rotation = task::spawn(async move {
        key_rotation_task().await;
    });

    server().await;
    let _ = key_rotation.await;
}
