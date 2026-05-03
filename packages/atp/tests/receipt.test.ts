/**
 * Action Receipt tests.
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

import { describe, expect, test } from "bun:test";
import {
  issueAic,
  signReceipt,
  verifyReceipt,
  addReceiverSignature,
  receiptsForCert,
  generateKeyPair,
} from "../src/index";
import { makeScope } from "../src/scope";
import { sha256Hex } from "../src/crypto";

const baseInput = () => ({
  modelId: "anthropic/claude-sonnet-4-6",
  systemPromptHash: sha256Hex("p"),
  scope: makeScope({ allowedTools: ["x"], maxSubAgentDepth: 0 }),
  operatorId: "guy@lyrie.ai",
});

const sampleAction = (tool = "x") => ({
  tool,
  params: { y: 1 },
  timestamp: 1_700_000_000_000,
});
const sampleResult = () => ({ success: true, summary: "ok", timestamp: 1_700_000_000_500 });

describe("signReceipt", () => {
  test("produces a verifiable receipt", () => {
    const r = issueAic(baseInput());
    const receipt = signReceipt({
      cert: r.cert,
      privateKey: r.keyPair.privateKey,
      action: sampleAction(),
      result: sampleResult(),
    });
    expect(receipt.agentSignature.length).toBe(88);
    expect(verifyReceipt(receipt, { cert: r.cert }).valid).toBe(true);
  });

  test("binds receipt to the issuing AIC", () => {
    const a = issueAic(baseInput());
    const b = issueAic(baseInput());
    const receipt = signReceipt({
      cert: a.cert,
      privateKey: a.keyPair.privateKey,
      action: sampleAction(),
      result: sampleResult(),
    });
    const v = verifyReceipt(receipt, { cert: b.cert });
    expect(v.valid).toBe(false);
    expect(v.code).toBe("ATP_RECEIPT_AGENT_MISMATCH");
  });

  test("rejects tampered action params", () => {
    const r = issueAic(baseInput());
    const receipt = signReceipt({
      cert: r.cert,
      privateKey: r.keyPair.privateKey,
      action: sampleAction(),
      result: sampleResult(),
    });
    const tampered = { ...receipt, action: { ...receipt.action, params: { y: 999 } } };
    const v = verifyReceipt(tampered, { cert: r.cert });
    expect(v.valid).toBe(false);
    expect(v.code).toBe("ATP_SIGNATURE_INVALID");
  });

  test("rejects tampered result.success", () => {
    const r = issueAic(baseInput());
    const receipt = signReceipt({
      cert: r.cert,
      privateKey: r.keyPair.privateKey,
      action: sampleAction(),
      result: sampleResult(),
    });
    const tampered = { ...receipt, result: { ...receipt.result, success: false } };
    expect(verifyReceipt(tampered, { cert: r.cert }).valid).toBe(false);
  });

  test("rejects malformed receipt", () => {
    const r = issueAic(baseInput());
    expect(verifyReceipt(null as never, { cert: r.cert }).valid).toBe(false);
    expect(verifyReceipt({} as never, { cert: r.cert }).valid).toBe(false);
  });
});

describe("receiver counter-signature", () => {
  test("can be added and verified", () => {
    const r = issueAic(baseInput());
    const receiver = generateKeyPair();
    const receipt = signReceipt({
      cert: r.cert,
      privateKey: r.keyPair.privateKey,
      action: sampleAction(),
      result: sampleResult(),
    });
    const counterSigned = addReceiverSignature(receipt, receiver.privateKey, receiver.publicKey);
    expect(counterSigned.receiverSignature?.length).toBe(88);
    const v = verifyReceipt(counterSigned, { cert: r.cert, requireReceiverSignature: true });
    expect(v.valid).toBe(true);
  });

  test("requireReceiverSignature without one fails", () => {
    const r = issueAic(baseInput());
    const receipt = signReceipt({
      cert: r.cert,
      privateKey: r.keyPair.privateKey,
      action: sampleAction(),
      result: sampleResult(),
    });
    const v = verifyReceipt(receipt, { cert: r.cert, requireReceiverSignature: true });
    expect(v.valid).toBe(false);
  });

  test("agent signature stays valid after receiver counter-sign", () => {
    const r = issueAic(baseInput());
    const receiver = generateKeyPair();
    const receipt = signReceipt({
      cert: r.cert,
      privateKey: r.keyPair.privateKey,
      action: sampleAction(),
      result: sampleResult(),
    });
    const counterSigned = addReceiverSignature(receipt, receiver.privateKey, receiver.publicKey);
    expect(verifyReceipt(counterSigned, { cert: r.cert }).valid).toBe(true);
  });

  test("forged receiver signature fails", () => {
    const r = issueAic(baseInput());
    const real = generateKeyPair();
    const fake = generateKeyPair();
    const receipt = signReceipt({
      cert: r.cert,
      privateKey: r.keyPair.privateKey,
      action: sampleAction(),
      result: sampleResult(),
    });
    const cs = addReceiverSignature(receipt, fake.privateKey, real.publicKey);
    const v = verifyReceipt(cs, { cert: r.cert });
    expect(v.valid).toBe(false);
  });
});

describe("receipt log helpers", () => {
  test("filters by certId", () => {
    const a = issueAic(baseInput());
    const b = issueAic(baseInput());
    const r1 = signReceipt({ cert: a.cert, privateKey: a.keyPair.privateKey, action: sampleAction(), result: sampleResult() });
    const r2 = signReceipt({ cert: a.cert, privateKey: a.keyPair.privateKey, action: sampleAction("y"), result: sampleResult() });
    const r3 = signReceipt({ cert: b.cert, privateKey: b.keyPair.privateKey, action: sampleAction(), result: sampleResult() });
    expect(receiptsForCert([r1, r2, r3], a.certId)).toEqual([r1, r2]);
  });
});
