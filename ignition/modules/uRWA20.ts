// This setup uses Hardhat Ignition to manage smart contract deployments.
// Learn more about it at https://hardhat.org/ignition

import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

const uRWA20Module = buildModule("uRWA20Module", (m) => {
  // Get deployment parameters from environment variables or use defaults for localnet
  const tokenName = m.getParameter("tokenName", process.env.TOKEN_NAME || "Real World Asset Token");
  const tokenSymbol = m.getParameter("tokenSymbol", process.env.TOKEN_SYMBOL || "RWA");
  const initialAdmin = m.getParameter("initialAdmin", process.env.INITIAL_ADMIN || m.getAccount(0));
  const siweDomain = m.getParameter("siweDomain", process.env.SIWE_DOMAIN || "localhost");

  const uRWA20 = m.contract("uRWA20", [tokenName, tokenSymbol, initialAdmin, siweDomain]);

  return { uRWA20 };
});

export default uRWA20Module;
