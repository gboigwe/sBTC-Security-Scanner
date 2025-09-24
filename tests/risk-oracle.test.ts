
import { Cl } from "@stacks/transactions";
import { describe, expect, it } from "vitest";

const accounts = simnet.getAccounts();
const deployer = accounts.get("deployer")!;
const wallet1 = accounts.get("wallet_1")!;

describe("Risk Oracle Contract", () => {
  it("ensures simnet is well initialised", () => {
    expect(simnet.blockHeight).toBeDefined();
  });

  it("allows owner to initialize protocol", () => {
    const initializeResult = simnet.callPublicFn(
      "risk-oracle",
      "initialize-protocol",
      [Cl.principal(wallet1)],
      deployer
    );

    expect(initializeResult.result).toStrictEqual(Cl.ok(Cl.bool(true)));

    // Check protocol was initialized with default values
    const getRiskResult = simnet.callReadOnlyFn(
      "risk-oracle",
      "get-protocol-risk",
      [Cl.principal(wallet1)],
      deployer
    );

    expect(getRiskResult.result).toBeDefined();
  });

  it("only allows owner to initialize protocol", () => {
    const initializeResult = simnet.callPublicFn(
      "risk-oracle",
      "initialize-protocol",
      [Cl.principal(wallet1)],
      wallet1 // Non-owner trying to initialize
    );

    expect(initializeResult.result).toStrictEqual(Cl.error(Cl.uint(1000))); // ERR_UNAUTHORIZED
  });

  it("allows owner to update risk scores", () => {
    // Initialize protocol first
    const initializeResult = simnet.callPublicFn(
      "risk-oracle",
      "initialize-protocol",
      [Cl.principal(wallet1)],
      deployer
    );
    expect(initializeResult.result).toStrictEqual(Cl.ok(Cl.bool(true)));

    // Update risk score
    const updateResult = simnet.callPublicFn(
      "risk-oracle",
      "update-risk-score",
      [Cl.principal(wallet1), Cl.uint(80)],
      deployer
    );

    expect(updateResult.result).toStrictEqual(Cl.ok(Cl.bool(true)));
  });

  it("prevents updating risk score for non-existent protocol", () => {
    const updateResult = simnet.callPublicFn(
      "risk-oracle",
      "update-risk-score",
      [Cl.principal(wallet1), Cl.uint(80)],
      deployer
    );

    expect(updateResult.result).toStrictEqual(Cl.error(Cl.uint(1002))); // ERR_PROTOCOL_NOT_FOUND
  });

  it("allows owner to authorize assessors", () => {
    const authorizeResult = simnet.callPublicFn(
      "risk-oracle",
      "authorize-assessor",
      [Cl.principal(wallet1)],
      deployer
    );

    expect(authorizeResult.result).toStrictEqual(Cl.ok(Cl.bool(true)));

    // Check authorization status
    const isAuthResult = simnet.callReadOnlyFn(
      "risk-oracle",
      "is-authorized-assessor",
      [Cl.principal(wallet1)],
      deployer
    );

    expect(isAuthResult.result).toStrictEqual(Cl.bool(true));
  });

  it("allows authorized assessor to update risk scores", () => {
    // Initialize protocol
    simnet.callPublicFn(
      "risk-oracle",
      "initialize-protocol",
      [Cl.principal(wallet1)],
      deployer
    );

    // Authorize wallet1 as assessor
    simnet.callPublicFn(
      "risk-oracle",
      "authorize-assessor",
      [Cl.principal(wallet1)],
      deployer
    );

    // Authorized assessor updates risk score
    const updateResult = simnet.callPublicFn(
      "risk-oracle",
      "update-risk-score",
      [Cl.principal(wallet1), Cl.uint(75)],
      wallet1 // Authorized assessor calling
    );

    expect(updateResult.result).toStrictEqual(Cl.ok(Cl.bool(true)));
  });

  it("returns correct risk category for different scores", () => {
    const lowRiskResult = simnet.callReadOnlyFn(
      "risk-oracle",
      "get-risk-category",
      [Cl.uint(20)],
      deployer
    );
    expect(lowRiskResult.result).toStrictEqual(Cl.stringAscii("low"));

    const mediumLowResult = simnet.callReadOnlyFn(
      "risk-oracle",
      "get-risk-category",
      [Cl.uint(40)],
      deployer
    );
    expect(mediumLowResult.result).toStrictEqual(Cl.stringAscii("medium-low"));

    const mediumHighResult = simnet.callReadOnlyFn(
      "risk-oracle",
      "get-risk-category",
      [Cl.uint(60)],
      deployer
    );
    expect(mediumHighResult.result).toStrictEqual(Cl.stringAscii("medium-high"));

    const highRiskResult = simnet.callReadOnlyFn(
      "risk-oracle",
      "get-risk-category",
      [Cl.uint(90)],
      deployer
    );
    expect(highRiskResult.result).toStrictEqual(Cl.stringAscii("high"));
  });

  it("returns risk thresholds configuration", () => {
    const thresholdsResult = simnet.callReadOnlyFn(
      "risk-oracle",
      "get-risk-thresholds",
      [],
      deployer
    );

    expect(thresholdsResult.result).toBeTuple({
      min: Cl.uint(1),
      max: Cl.uint(100),
      "oracle-enabled": Cl.bool(true)
    });
  });

  it("allows owner to update risk thresholds", () => {
    const updateResult = simnet.callPublicFn(
      "risk-oracle",
      "update-risk-thresholds",
      [Cl.uint(5), Cl.uint(95)],
      deployer
    );

    expect(updateResult.result).toStrictEqual(Cl.ok(Cl.bool(true)));

    // Check updated thresholds
    const thresholdsResult = simnet.callReadOnlyFn(
      "risk-oracle",
      "get-risk-thresholds",
      [],
      deployer
    );

    expect(thresholdsResult.result).toBeTuple({
      min: Cl.uint(5),
      max: Cl.uint(95),
      "oracle-enabled": Cl.bool(true)
    });
  });

  it("prevents setting invalid risk thresholds", () => {
    const updateResult = simnet.callPublicFn(
      "risk-oracle",
      "update-risk-thresholds",
      [Cl.uint(50), Cl.uint(25)], // min > max
      deployer
    );

    expect(updateResult.result).toStrictEqual(Cl.error(Cl.uint(1001))); // ERR_INVALID_RISK_LEVEL
  });
});
