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
        assert!(address.is_valid_for_network(network.network()));
    }

    println!("Bitcoin test environment CLI: PASS");
}
