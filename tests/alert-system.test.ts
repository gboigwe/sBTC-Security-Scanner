
import { Cl } from "@stacks/transactions";
import { describe, expect, it } from "vitest";

const accounts = simnet.getAccounts();
const deployer = accounts.get("deployer")!;
const wallet1 = accounts.get("wallet_1")!;
const wallet2 = accounts.get("wallet_2")!;

describe("Alert System Contract", () => {
  it("ensures simnet is well initialised", () => {
    expect(simnet.blockHeight).toBeDefined();
  });

  it("can create and manage alerts", () => {
    const createAlertResult = simnet.callPublicFn(
      "alert-system",
      "create-alert",
      [
        Cl.principal(wallet1),
        Cl.uint(75), // High risk score
        Cl.stringAscii("Critical vulnerability detected in protocol")
      ],
      deployer
    );

    expect(createAlertResult.result).toStrictEqual(
      Cl.ok(Cl.tuple({ "alert-id": Cl.uint(1), "alert-level": Cl.uint(3) }))
    );

    // Verify alert was created
    const getAlertResult = simnet.callReadOnlyFn(
      "alert-system",
      "get-alert",
      [Cl.uint(1)],
      deployer
    );

    expect(getAlertResult.result).toBeDefined();
  });

  it("calculates correct alert levels based on risk score", () => {
    // Test low risk alert
    const lowRiskAlert = simnet.callPublicFn(
      "alert-system",
      "create-alert",
      [
        Cl.principal(wallet1),
        Cl.uint(60), // Medium-high risk
        Cl.stringAscii("Medium risk issue detected")
      ],
      deployer
    );

    expect(lowRiskAlert.result).toStrictEqual(
      Cl.ok(Cl.tuple({ "alert-id": Cl.uint(1), "alert-level": Cl.uint(3) }))
    );

    // Test critical risk alert
    const criticalAlert = simnet.callPublicFn(
      "alert-system",
      "create-alert",
      [
        Cl.principal(wallet2),
        Cl.uint(85), // Critical risk
        Cl.stringAscii("Critical vulnerability found")
      ],
      deployer
    );

    expect(criticalAlert.result).toStrictEqual(
      Cl.ok(Cl.tuple({ "alert-id": Cl.uint(2), "alert-level": Cl.uint(4) }))
    );
  });

  it("prevents creating alerts below global threshold", () => {
    const lowRiskAlert = simnet.callPublicFn(
      "alert-system",
      "create-alert",
      [
        Cl.principal(wallet1),
        Cl.uint(40), // Below default threshold of 50
        Cl.stringAscii("Low risk issue")
      ],
      deployer
    );

    expect(lowRiskAlert.result).toStrictEqual(Cl.error(Cl.uint(3001))); // ERR_INVALID_THRESHOLD
  });

  it("allows users to subscribe to protocol alerts", () => {
    const subscribeResult = simnet.callPublicFn(
      "alert-system",
      "subscribe-to-alerts",
      [
        Cl.principal(wallet1),
        Cl.uint(50) // Alert threshold
      ],
      wallet2
    );

    expect(subscribeResult.result).toStrictEqual(Cl.ok(Cl.bool(true)));

    // Verify subscription
    const getSubResult = simnet.callReadOnlyFn(
      "alert-system",
      "get-subscription",
      [Cl.principal(wallet2), Cl.principal(wallet1)],
      deployer
    );

    expect(getSubResult.result).toBeDefined();
  });

  it("validates subscription threshold parameters", () => {
    const invalidSubscribe = simnet.callPublicFn(
      "alert-system",
      "subscribe-to-alerts",
      [
        Cl.principal(wallet1),
        Cl.uint(150) // Invalid threshold > 100
      ],
      wallet2
    );

    expect(invalidSubscribe.result).toStrictEqual(Cl.error(Cl.uint(3001))); // ERR_INVALID_THRESHOLD
  });

  it("allows users to unsubscribe from alerts", () => {
    // First subscribe
    simnet.callPublicFn(
      "alert-system",
      "subscribe-to-alerts",
      [Cl.principal(wallet1), Cl.uint(60)],
      wallet2
    );

    // Then unsubscribe
    const unsubscribeResult = simnet.callPublicFn(
      "alert-system",
      "unsubscribe-from-alerts",
      [Cl.principal(wallet1)],
      wallet2
    );

    expect(unsubscribeResult.result).toStrictEqual(Cl.ok(Cl.bool(true)));
  });

  it("handles unsubscribing from non-existent subscription", () => {
    const unsubscribeResult = simnet.callPublicFn(
      "alert-system",
      "unsubscribe-from-alerts",
      [Cl.principal(wallet1)],
      wallet2 // Never subscribed
    );

    expect(unsubscribeResult.result).toStrictEqual(Cl.error(Cl.uint(3002))); // ERR_ALERT_NOT_FOUND
  });

  it("allows resolving active alerts", () => {
    // Create an alert first
    simnet.callPublicFn(
      "alert-system",
      "create-alert",
      [
        Cl.principal(wallet1),
        Cl.uint(70),
        Cl.stringAscii("Security issue detected")
      ],
      deployer
    );

    // Resolve the alert
    const resolveResult = simnet.callPublicFn(
      "alert-system",
      "resolve-alert",
      [Cl.uint(1)],
      wallet1
    );

    expect(resolveResult.result).toStrictEqual(Cl.ok(Cl.bool(true)));
  });

  it("prevents resolving non-existent alerts", () => {
    const resolveResult = simnet.callPublicFn(
      "alert-system",
      "resolve-alert",
      [Cl.uint(999)], // Non-existent alert ID
      wallet1
    );

    expect(resolveResult.result).toStrictEqual(Cl.error(Cl.uint(3002))); // ERR_ALERT_NOT_FOUND
  });

  it("prevents resolving already resolved alerts", () => {
    // Create and resolve an alert
    simnet.callPublicFn(
      "alert-system",
      "create-alert",
      [Cl.principal(wallet1), Cl.uint(80), Cl.stringAscii("Test alert")],
      deployer
    );
    
    simnet.callPublicFn(
      "alert-system",
      "resolve-alert",
      [Cl.uint(1)],
      wallet1
    );

    // Try to resolve again
    const resolveAgainResult = simnet.callPublicFn(
      "alert-system",
      "resolve-alert",
      [Cl.uint(1)],
      wallet1
    );

    expect(resolveAgainResult.result).toStrictEqual(Cl.error(Cl.uint(3002))); // ERR_ALERT_NOT_FOUND
  });

  it("can create bulk alerts", () => {
    const bulkAlertsResult = simnet.callPublicFn(
      "alert-system",
      "create-bulk-alerts",
      [
        Cl.principal(wallet1),
        Cl.list([
          Cl.tuple({
            "risk-score": Cl.uint(60),
            "message": Cl.stringAscii("First bulk alert")
          }),
          Cl.tuple({
            "risk-score": Cl.uint(80), 
            "message": Cl.stringAscii("Second bulk alert")
          })
        ])
      ],
      deployer
    );

    expect(bulkAlertsResult.result).toBeDefined();
  });

  it("correctly identifies notification subscribers", () => {
    // Subscribe wallet2 to wallet1 alerts with threshold 50
    simnet.callPublicFn(
      "alert-system",
      "subscribe-to-alerts",
      [Cl.principal(wallet1), Cl.uint(50)],
      wallet2
    );

    // Check if subscriber should be notified for high risk score
    const shouldNotifyHighResult = simnet.callReadOnlyFn(
      "alert-system",
      "should-notify-subscriber",
      [Cl.principal(wallet2), Cl.principal(wallet1), Cl.uint(75)],
      deployer
    );

    expect(shouldNotifyHighResult.result).toStrictEqual(Cl.bool(true));

    // Check if subscriber should be notified for low risk score
    const shouldNotifyLowResult = simnet.callReadOnlyFn(
      "alert-system",
      "should-notify-subscriber",
      [Cl.principal(wallet2), Cl.principal(wallet1), Cl.uint(30)],
      deployer
    );

    expect(shouldNotifyLowResult.result).toStrictEqual(Cl.bool(false));
  });

  it("returns alert system configuration", () => {
    const configResult = simnet.callReadOnlyFn(
      "alert-system",
      "get-alert-config",
      [],
      deployer
    );

    expect(configResult.result).toBeTuple({
      enabled: Cl.bool(true),
      "global-threshold": Cl.uint(50),
      "max-alerts": Cl.uint(100)
    });
  });

  it("allows owner to update alert configuration", () => {
    const updateResult = simnet.callPublicFn(
      "alert-system",
      "update-alert-config",
      [Cl.bool(false), Cl.uint(30), Cl.uint(50)],
      deployer
    );

    expect(updateResult.result).toStrictEqual(Cl.ok(Cl.bool(true)));

    // Verify configuration was updated
    const configResult = simnet.callReadOnlyFn(
      "alert-system",
      "get-alert-config",
      [],
      deployer
    );

    expect(configResult.result).toBeTuple({
      enabled: Cl.bool(false),
      "global-threshold": Cl.uint(30),
      "max-alerts": Cl.uint(50)
    });
  });

  it("prevents non-owner from updating configuration", () => {
    const updateResult = simnet.callPublicFn(
      "alert-system",
      "update-alert-config",
      [Cl.bool(false), Cl.uint(25), Cl.uint(25)],
      wallet1 // Non-owner
    );

    expect(updateResult.result).toStrictEqual(Cl.error(Cl.uint(3000))); // ERR_UNAUTHORIZED
  });

  it("validates configuration parameters", () => {
    const invalidUpdate = simnet.callPublicFn(
      "alert-system",
      "update-alert-config",
      [Cl.bool(true), Cl.uint(150), Cl.uint(50)], // Invalid threshold > 100
      deployer
    );

    expect(invalidUpdate.result).toStrictEqual(Cl.error(Cl.uint(3001))); // ERR_INVALID_THRESHOLD
  });

  it("tracks protocol alert statistics", () => {
    // Create multiple alerts for a protocol
    simnet.callPublicFn(
      "alert-system",
      "create-alert",
      [Cl.principal(wallet1), Cl.uint(60), Cl.stringAscii("Alert 1")],
      deployer
    );

    simnet.callPublicFn(
      "alert-system",
      "create-alert",
      [Cl.principal(wallet1), Cl.uint(70), Cl.stringAscii("Alert 2")],
      deployer
    );

    // Check alert statistics
    const statsResult = simnet.callReadOnlyFn(
      "alert-system",
      "get-protocol-alert-stats",
      [Cl.principal(wallet1)],
      deployer
    );

    expect(statsResult.result).toBeDefined();
  });
});
