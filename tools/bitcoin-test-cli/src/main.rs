use demon_vault_bitcoin::{BitcoinTestNetwork, BitcoinTestWallet};

fn main() {
    let seed = [0x51u8; 32];

    for network in [
        BitcoinTestNetwork::Testnet,
        BitcoinTestNetwork::Testnet4,
        BitcoinTestNetwork::Signet,
        BitcoinTestNetwork::Regtest,
    ] {
        let mut wallet =
            BitcoinTestWallet::from_seed(network, &seed).expect("BTC test wallet must initialize");
        let address = wallet.next_receive_address();
        let validated = wallet
            .validate_recipient(&address.to_string())
            .expect("derived address must validate for its test network");
        assert_eq!(validated, address);
    }

    println!("Bitcoin test environment CLI: PASS");
}
