/**
 * TrezorSigner - Ethers.js Signer for Trezor hardware wallets
 *
 * This signer integrates Trezor hardware wallets with ethers.js v6
 * using @trezor/connect-web for transaction signing.
 */

const { ethers } = require('ethers');
const TrezorConnect = require('@trezor/connect-web').default;

class TrezorSigner extends ethers.AbstractSigner {
  constructor(provider, path = "m/44'/60'/0'/0/0") {
    super(provider);
    this.path = path;
    this._address = null;
    this._initialized = false;
  }

  async _init() {
    if (this._initialized) return;

    try {
      // Initialize Trezor Connect
      await TrezorConnect.init({
        lazyLoad: false,
        manifest: {
          email: 'dev@example.com',
          appUrl: 'https://example.com'
        }
      });

      this._initialized = true;
    } catch (error) {
      throw new Error(`Failed to initialize Trezor: ${error.message}`);
    }
  }

  async getAddress() {
    if (this._address) return this._address;

    await this._init();

    const result = await TrezorConnect.ethereumGetAddress({
      path: this.path,
      showOnTrezor: false
    });

    if (!result.success) {
      throw new Error(`Failed to get address from Trezor: ${result.payload.error}`);
    }

    this._address = result.payload.address;
    return this._address;
  }

  async signTransaction(transaction) {
    await this._init();

    // Ensure we have all required fields
    const tx = await ethers.resolveProperties(transaction);

    // Convert to format expected by Trezor
    const trezorTx = {
      to: tx.to,
      value: tx.value ? '0x' + BigInt(tx.value).toString(16) : '0x0',
      gasPrice: tx.gasPrice ? '0x' + BigInt(tx.gasPrice).toString(16) : undefined,
      gasLimit: tx.gasLimit ? '0x' + BigInt(tx.gasLimit).toString(16) : '0x5208',
      nonce: tx.nonce ? '0x' + BigInt(tx.nonce).toString(16) : '0x0',
      data: tx.data || '0x',
      chainId: tx.chainId || 1,
      maxFeePerGas: tx.maxFeePerGas ? '0x' + BigInt(tx.maxFeePerGas).toString(16) : undefined,
      maxPriorityFeePerGas: tx.maxPriorityFeePerGas ? '0x' + BigInt(tx.maxPriorityFeePerGas).toString(16) : undefined
    };

    console.log('\n⚠️  Please confirm transaction on your Trezor device...');

    const result = await TrezorConnect.ethereumSignTransaction({
      path: this.path,
      transaction: trezorTx
    });

    if (!result.success) {
      throw new Error(`Failed to sign transaction: ${result.payload.error}`);
    }

    console.log('✓ Transaction signed on Trezor');

    // Construct the signed transaction
    const signature = {
      r: '0x' + result.payload.r,
      s: '0x' + result.payload.s,
      v: parseInt(result.payload.v, 16)
    };

    return ethers.Transaction.from({
      ...tx,
      signature
    }).serialized;
  }

  async signMessage(message) {
    await this._init();

    const messageHex = ethers.hexlify(ethers.toUtf8Bytes(message));

    console.log('\n⚠️  Please confirm message signature on your Trezor device...');

    const result = await TrezorConnect.ethereumSignMessage({
      path: this.path,
      message: messageHex.slice(2), // Remove '0x' prefix
      hex: true
    });

    if (!result.success) {
      throw new Error(`Failed to sign message: ${result.payload.error}`);
    }

    console.log('✓ Message signed on Trezor');

    return '0x' + result.payload.signature;
  }

  async signTypedData(domain, types, value) {
    throw new Error('signTypedData is not yet supported with Trezor');
  }

  connect(provider) {
    return new TrezorSigner(provider, this.path);
  }
}

module.exports = TrezorSigner;
