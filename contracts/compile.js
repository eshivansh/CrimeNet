const fs = require('fs');
const path = require('path');
const solc = require('solc');

const contractPath = path.resolve(__dirname, 'DocumentProvenanceAnchor.sol');
const source = fs.readFileSync(contractPath, 'utf8');

const input = {
  language: 'Solidity',
  sources: {
    'DocumentProvenanceAnchor.sol': {
      content: source,
    },
  },
  settings: {
    optimizer: {
      enabled: true,
      runs: 200,
    },
    outputSelection: {
      '*': {
        '*': ['abi', 'evm.bytecode'],
      },
    },
  },
};

console.log('Compiling DocumentProvenanceAnchor.sol...');
const output = JSON.parse(solc.compile(JSON.stringify(input)));

if (output.errors) {
  for (const err of output.errors) {
    console.error(err.formattedMessage);
    if (err.severity === 'error') process.exit(1);
  }
}

const contract = output.contracts['DocumentProvenanceAnchor.sol']['DocumentProvenanceAnchor'];
const abi = contract.abi;
const bytecode = '0x' + contract.evm.bytecode.object;

fs.writeFileSync(
  path.resolve(__dirname, 'DocumentProvenanceAnchor.json'),
  JSON.stringify({ abi, bytecode }, null, 2),
  'utf8'
);

console.log('Compilation successful!');
console.log('Bytecode length:', bytecode.length);
console.log('ABI methods:', abi.filter(x => x.type === 'function').map(x => x.name));
