use anyhow::Result;

use alloy::{
    network::{EthereumWallet, TransactionBuilder},
    primitives::{Address, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::{BlockNumberOrTag, TransactionReceipt, TransactionRequest},
    signers::{k256::ecdsa::SigningKey, local::PrivateKeySigner, utils::secret_key_to_address},
    sol, sol_types::{SolInterface, SolValue},
};
use tiny_keccak::{Hasher, Keccak};

sol! {
    #[sol(rpc)]
    interface ISP1TEEProverRegistry {
        #[derive(Debug)]
        struct ReportData {
            uint256 referenceBlockNumber;
            bytes32 referenceBlockHash;
            address proverAddress;
        }

        #[derive(Debug)]
        function register(ReportData calldata report_data, bytes calldata dcap_quote);
    }
}

pub struct TxSender {
    rpc_url: String,
    wallet: EthereumWallet,
    contract: Address,
}

impl TxSender {
    pub fn new(
        rpc_url: &str,
        contract: &str,
    ) -> Result<Self> {
        let contract = contract.parse::<Address>()?;

        Ok(TxSender {
            rpc_url: rpc_url.to_string(),
            wallet: EthereumWallet::default(),
            contract,
        })
    }

    pub fn set_wallet(&mut self, private_key: &str) -> Result<()> {
        let signer_key =
        SigningKey::from_slice(&hex::decode(private_key).unwrap()).expect("Invalid key");
        let wallet = EthereumWallet::from(PrivateKeySigner::from_signing_key(signer_key));
        self.wallet = wallet;

        Ok(())
    }


    pub async fn generate_report_data(&self, prover_address: Address) -> Result<(ISP1TEEProverRegistry::ReportData, [u8; 64])> {
        let rpc_url = self.rpc_url.parse()?;
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(&self.wallet)
            .on_http(rpc_url);
        let latest_block_number = provider.get_block_number().await?;
        log::info!("Latest Block Number: {:?}", latest_block_number);
        let mut block;
        let block_number_tag: BlockNumberOrTag = latest_block_number.into();
        loop {
            block = provider.get_block_by_number(block_number_tag, true).await?;
            if block.is_some() {
                break;
            }
        }
        let report_data = ISP1TEEProverRegistry::ReportData {
            referenceBlockNumber: U256::from(latest_block_number),
            referenceBlockHash: block.unwrap().header.hash.unwrap(),
            proverAddress: prover_address
        };
        log::info!("Report data: {:?}", report_data);

        let encoded_report_data = report_data.abi_encode();
        let mut hasher = Keccak::v256();
        hasher.update(&encoded_report_data);
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);

        let mut isv_report_data: [u8; 64] = [0u8; 64];
        isv_report_data[12..32].copy_from_slice(prover_address.as_slice());
        isv_report_data[32..64].copy_from_slice(&hash);
        log::info!("isv_report_data: {:?}", hex::encode(isv_report_data));

        Ok((report_data, isv_report_data))
    }

    pub fn generate_register_calldata(&self, report_data: ISP1TEEProverRegistry::ReportData, dcap_quote: Vec<u8>) -> Vec<u8> {
        ISP1TEEProverRegistry::ISP1TEEProverRegistryCalls::register(
            ISP1TEEProverRegistry::registerCall {
                report_data: report_data,
                dcap_quote: Bytes::from(dcap_quote),
            },
        ).abi_encode()
    }

    /// Sends the transaction
    pub async fn send(&self, calldata: Vec<u8>) -> Result<TransactionReceipt> {
        let rpc_url = self.rpc_url.parse()?;
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(&self.wallet)
            .on_http(rpc_url);
        let tx = TransactionRequest::default()
            .with_to(self.contract)
            .with_input(calldata);
        let receipt = provider
            .send_transaction(tx.clone())
            .await?
            .get_receipt()
            .await?;

        Ok(receipt)
    }

    /// Makes a staticcall with the given transaction request
    pub async fn call(&self, calldata: Vec<u8>) -> Result<Bytes> {
        let rpc_url = self.rpc_url.parse()?;
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(&self.wallet)
            .on_http(rpc_url);
        let tx = TransactionRequest::default()
            .with_to(self.contract)
            .with_input(calldata);
        let call_output = provider.call(&tx).await?;
         
        Ok(call_output)
    }
}

pub fn get_evm_address_from_key(key: &str) -> String {
    let key_slice = hex::decode(key).unwrap();
    let signing_key = SigningKey::from_slice(&key_slice).expect("Invalid key");
    let address = secret_key_to_address(&signing_key);
    address.to_checksum(None)
}
