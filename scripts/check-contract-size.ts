import { artifacts } from "hardhat";
import * as fs from "fs";
import * as path from "path";

const CONTRACT_SIZE_LIMIT = 24576; // 24KB - Standard EVM limit

async function main() {
  const contractName = "uRWA20";
  
  try {
    // Read the artifact
    const artifactPath = path.join(
      __dirname,
      "..",
      "artifacts",
      "contracts",
      `${contractName}.sol`,
      `${contractName}.json`
    );
    
    const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
    
    // Calculate bytecode size (remove 0x prefix and divide by 2 for byte count)
    const bytecode = artifact.bytecode.replace("0x", "");
    const bytecodeSize = bytecode.length / 2;
    
    const deployedBytecode = artifact.deployedBytecode.replace("0x", "");
    const deployedBytecodeSize = deployedBytecode.length / 2;
    
    console.log(`\n=== Contract Size Analysis: ${contractName} ===\n`);
    console.log(`Bytecode size:        ${bytecodeSize.toLocaleString()} bytes (${(bytecodeSize / 1024).toFixed(2)} KB)`);
    console.log(`Deployed bytecode:    ${deployedBytecodeSize.toLocaleString()} bytes (${(deployedBytecodeSize / 1024).toFixed(2)} KB)`);
    console.log(`Contract size limit:  ${CONTRACT_SIZE_LIMIT.toLocaleString()} bytes (${(CONTRACT_SIZE_LIMIT / 1024).toFixed(2)} KB)`);
    console.log(`\n--- Status ---`);
    
    if (bytecodeSize > CONTRACT_SIZE_LIMIT) {
      const overage = bytecodeSize - CONTRACT_SIZE_LIMIT;
      const overagePercent = ((overage / CONTRACT_SIZE_LIMIT) * 100).toFixed(2);
      console.log(`❌ EXCEEDS LIMIT by ${overage.toLocaleString()} bytes (${overagePercent}%)`);
      console.log(`\n⚠️  Contract cannot be deployed on EVM-compatible chains.`);
      console.log(`\n💡 Suggestions to reduce size:`);
      console.log(`   1. Increase optimizer runs (currently: ${process.env.OPTIMIZER_RUNS || "1"})`);
      console.log(`   2. Split functionality into separate contracts/libraries`);
      console.log(`   3. Remove unused functions`);
      console.log(`   4. Use libraries for common functionality`);
      console.log(`   5. Consider using proxy patterns`);
    } else {
      const remaining = CONTRACT_SIZE_LIMIT - bytecodeSize;
      const usagePercent = ((bytecodeSize / CONTRACT_SIZE_LIMIT) * 100).toFixed(2);
      console.log(`✅ Within limit (${usagePercent}% used, ${remaining.toLocaleString()} bytes remaining)`);
    }
    
    console.log(`\n`);
    
  } catch (error) {
    console.error("Error reading contract artifact:", error);
    process.exit(1);
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

