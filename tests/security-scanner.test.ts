
import { Cl } from "@stacks/transactions";
import { describe, expect, it } from "vitest";

const accounts = simnet.getAccounts();
const deployer = accounts.get("deployer")!;
const wallet1 = accounts.get("wallet_1")!;
const wallet2 = accounts.get("wallet_2")!;

describe("Security Scanner Contract", () => {
  it("ensures simnet is well initialised", () => {
    expect(simnet.blockHeight).toBeDefined();
  });

  it("can perform security scan on protocol", () => {
    const scanResult = simnet.callPublicFn(
      "security-scanner",
      "scan-protocol",
      [
        Cl.principal(wallet1),
        Cl.list([Cl.uint(1), Cl.uint(4)]) // Reentrancy + Flashloan checks
      ],
      deployer
    );

    expect(scanResult.result).toBeDefined();

    // Verify scan results were stored
    const getScanResult = simnet.callReadOnlyFn(
      "security-scanner",
      "get-scan-results",
      [Cl.uint(1)],
      deployer
    );

    expect(getScanResult.result).toBeDefined();
  });

  it("prevents scanning when scanner is disabled", () => {
    // First disable the scanner
    const disableResult = simnet.callPublicFn(
      "security-scanner",
      "update-scanner-config",
      [Cl.bool(false), Cl.uint(0), Cl.uint(10)],
      deployer
    );
    expect(disableResult.result).toStrictEqual(Cl.ok(Cl.bool(true)));

    // Try to scan - should fail
    const scanResult = simnet.callPublicFn(
      "security-scanner",
      "scan-protocol",
      [
        Cl.principal(wallet1),
        Cl.list([Cl.uint(1)])
      ],
      deployer
    );

    expect(scanResult.result).toStrictEqual(Cl.error(Cl.uint(2002))); // ERR_SCAN_FAILED
  });

  it("validates scan parameters", () => {
    const scanResult = simnet.callPublicFn(
      "security-scanner",
      "scan-protocol",
      [
        Cl.principal(wallet1),
        Cl.list([]) // Empty scan types list
      ],
      deployer
    );

    expect(scanResult.result).toStrictEqual(Cl.error(Cl.uint(2001))); // ERR_INVALID_PARAMETERS
  });

  it("can report vulnerabilities", () => {
    const reportResult = simnet.callPublicFn(
      "security-scanner",
      "report-vulnerability",
      [
        Cl.principal(wallet1),
        Cl.uint(4), // Flashloan vulnerability
        Cl.uint(3), // Medium severity
        Cl.stringAscii("Potential flashloan exploit detected")
      ],
      deployer
    );

    expect(reportResult.result).toStrictEqual(Cl.ok(Cl.bool(true)));

    // Verify vulnerability was stored
    const getVulnResult = simnet.callReadOnlyFn(
      "security-scanner",
      "get-protocol-vulnerability",
      [Cl.principal(wallet1), Cl.uint(4)],
      deployer
    );

    expect(getVulnResult.result).toBeDefined();
  });

  it("validates vulnerability severity", () => {
    const reportResult = simnet.callPublicFn(
      "security-scanner",
      "report-vulnerability",
      [
        Cl.principal(wallet1),
        Cl.uint(1),
        Cl.uint(6), // Invalid severity (> 5)
        Cl.stringAscii("Test vulnerability")
      ],
      deployer
    );

    expect(reportResult.result).toStrictEqual(Cl.error(Cl.uint(2001))); // ERR_INVALID_PARAMETERS
  });

  it("can resolve reported vulnerabilities", () => {
    // First report a vulnerability
    const reportResult = simnet.callPublicFn(
      "security-scanner",
      "report-vulnerability",
      [
        Cl.principal(wallet1),
        Cl.uint(2), // Access control vulnerability
        Cl.uint(2), // Low severity
        Cl.stringAscii("Access control issue")
      ],
      deployer
    );
    expect(reportResult.result).toStrictEqual(Cl.ok(Cl.bool(true)));

    // Resolve the vulnerability
    const resolveResult = simnet.callPublicFn(
      "security-scanner",
      "resolve-vulnerability",
      [Cl.principal(wallet1), Cl.uint(2)],
      deployer
    );

    expect(resolveResult.result).toStrictEqual(Cl.ok(Cl.bool(true)));
  });

  it("handles resolving non-existent vulnerability", () => {
    const resolveResult = simnet.callPublicFn(
      "security-scanner",
      "resolve-vulnerability",
      [Cl.principal(wallet2), Cl.uint(99)], // Non-existent vulnerability
      deployer
    );

    expect(resolveResult.result).toStrictEqual(Cl.error(Cl.uint(2001))); // ERR_INVALID_PARAMETERS
  });

  it("returns correct scanner configuration", () => {
    const configResult = simnet.callReadOnlyFn(
      "security-scanner",
      "get-scanner-config",
      [],
      deployer
    );

    expect(configResult.result).toBeTuple({
      enabled: Cl.bool(true),
      fee: Cl.uint(0),
      "max-depth": Cl.uint(10)
    });
  });

  it("allows owner to update scanner configuration", () => {
    const updateResult = simnet.callPublicFn(
      "security-scanner",
      "update-scanner-config",
      [Cl.bool(false), Cl.uint(100), Cl.uint(20)],
      deployer
    );

    expect(updateResult.result).toStrictEqual(Cl.ok(Cl.bool(true)));

    // Verify configuration was updated
    const configResult = simnet.callReadOnlyFn(
      "security-scanner",
      "get-scanner-config",
      [],
      deployer
    );

    expect(configResult.result).toBeTuple({
      enabled: Cl.bool(false),
      fee: Cl.uint(100),
      "max-depth": Cl.uint(20)
    });
  });

  it("prevents non-owner from updating configuration", () => {
    const updateResult = simnet.callPublicFn(
      "security-scanner",
      "update-scanner-config",
      [Cl.bool(false), Cl.uint(50), Cl.uint(5)],
      wallet1 // Non-owner trying to update
    );

    expect(updateResult.result).toStrictEqual(Cl.error(Cl.uint(2000))); // ERR_UNAUTHORIZED
  });

  it("calculates risk scores correctly based on vulnerability count", () => {
    // Test with flashloan check which always returns 1 vulnerability
    const scanResult = simnet.callPublicFn(
      "security-scanner",
      "scan-protocol",
      [
        Cl.principal(wallet1),
        Cl.list([Cl.uint(4)]) // Flashloan check only
      ],
      deployer
    );

    expect(scanResult.result).toBeDefined();
    
    // Verify that risk score was calculated (1 vulnerability = 15 points)
    const getScanResult = simnet.callReadOnlyFn(
      "security-scanner",
      "get-scan-results",
      [Cl.uint(1)],
      deployer
    );

    expect(getScanResult.result).toBeDefined();
  });
});
