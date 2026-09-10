const fs = require('fs');
const path = require('path');
const { ethers } = require('ethers');

// Network Configuration (Polygon Amoy Testnet)
const DEFAULT_RPC = process.env.RPC_URL || 'https://polygon-amoy-bor-rpc.publicnode.com';
const NETWORK_NAME = process.env.NETWORK_NAME || 'Polygon Amoy Testnet (Chain ID 80002)';
const FAUCET_URL = 'https://faucet.polygon.technology/';

async function main() {
  console.log('====================================================');
  console.log(' CrimeNet — Smart Contract Testnet Deployment Runner');
  console.log('====================================================');
  console.log(`Network: ${NETWORK_NAME}`);
  console.log(`RPC Endpoint: ${DEFAULT_RPC}`);

  const walletFile = path.resolve(__dirname, 'deployer-wallet.json');
  let privateKey = process.env.PRIVATE_KEY;

  if (!privateKey) {
    if (fs.existsSync(walletFile)) {
      const saved = JSON.parse(fs.readFileSync(walletFile, 'utf8'));
      privateKey = saved.privateKey;
      console.log(`Loaded existing deployer wallet: ${saved.address}`);
    } else {
      const randomWallet = ethers.Wallet.createRandom();
      privateKey = randomWallet.privateKey;
      fs.writeFileSync(
        walletFile,
        JSON.stringify(
          {
            address: randomWallet.address,
            privateKey: randomWallet.privateKey,
            createdAt: new Date().toISOString(),
          },
          null,
          2
        ),
        'utf8'
      );
      console.log(`Generated new deployer wallet: ${randomWallet.address}`);
    }
  }

  const provider = new ethers.JsonRpcProvider(DEFAULT_RPC);
  const wallet = new ethers.Wallet(privateKey, provider);
  console.log(`Deployer Public Address: ${wallet.address}`);

  const balance = await provider.getBalance(wallet.address);
  const formattedBalance = ethers.formatEther(balance);
  console.log(`Current Balance: ${formattedBalance} POL`);

  if (balance === 0n) {
    console.log('\n----------------------------------------------------');
    console.log('⚠️  INSUFFICIENT TESTNET BALANCE FOR DEPLOYMENT');
    console.log('----------------------------------------------------');
    console.log(`Please fund your deployer wallet with free testnet tokens:`);
    console.log(`1. Copy Address: ${wallet.address}`);
    console.log(`2. Visit Free Faucet: ${FAUCET_URL}`);
    console.log(`   or alternative: https://www.alchemy.com/faucets/polygon-amoy`);
    console.log(`3. Request 0.5 POL tokens, then re-run this script:`);
    console.log(`   node deploy.js`);
    console.log('----------------------------------------------------\n');
    return;
  }

  console.log('\nBalance detected! Proceeding with contract deployment...');
  const artifactPath = path.resolve(__dirname, 'DocumentProvenanceAnchor.json');
  if (!fs.existsSync(artifactPath)) {
    console.error('Artifact not found! Please run `node compile.js` first.');
    process.exit(1);
  }

  const artifact = JSON.parse(fs.readFileSync(artifactPath, 'utf8'));
  const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, wallet);

  console.log('Broadcasting deployment transaction to Polygon Amoy...');
  const contract = await factory.deploy();
  console.log(`Transaction sent! TxHash: ${contract.deploymentTransaction().hash}`);
  console.log('Waiting for block confirmation on-chain...');

  await contract.waitForDeployment();
  const contractAddress = await contract.getAddress();

  console.log('\n====================================================');
  console.log('🎉 CONTRACT DEPLOYED SUCCESSFULLY!');
  console.log('====================================================');
  console.log(`Contract Address : ${contractAddress}`);
  console.log(`Deployer Address : ${wallet.address}`);
  console.log(`Tx Hash          : ${contract.deploymentTransaction().hash}`);
  console.log(`Polygonscan URL  : https://amoy.polygonscan.com/address/${contractAddress}`);
  console.log('====================================================\n');

  const deploymentInfo = {
    network: NETWORK_NAME,
    rpc: DEFAULT_RPC,
    contractAddress,
    deployer: wallet.address,
    txHash: contract.deploymentTransaction().hash,
    deployedAt: new Date().toISOString(),
    explorerUrl: `https://amoy.polygonscan.com/address/${contractAddress}`,
  };

  fs.writeFileSync(
    path.resolve(__dirname, 'deployed-address.json'),
    JSON.stringify(deploymentInfo, null, 2),
    'utf8'
  );
  console.log('Saved deployment record to `contracts/deployed-address.json`');
}

main().catch(err => {
  console.error('Deployment error:', err.message);
  process.exit(1);
});
