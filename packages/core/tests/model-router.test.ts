/**
 * ModelRouter Tests
 *
 * Tests intelligent task routing to the correct model.
 * OTT Cybersecurity LLC
 */

import { describe, it, expect, beforeEach } from "bun:test";
import { ModelRouter, type TaskType } from "../src/engine/model-router";

describe("ModelRouter", () => {
  let router: ModelRouter;

  beforeEach(async () => {
    router = new ModelRouter();
    await router.initialize();
  });

  it("initializes with default models", () => {
    const models = router.availableModels();
    expect(models.length).toBeGreaterThan(0);
  });

  it("has both cloud and local models configured", () => {
    const models = router.availableModels();
    const cloudModels = models.filter((m) => !m.isLocal);
    const localModels = models.filter((m) => m.isLocal);

    expect(cloudModels.length).toBeGreaterThan(0);
    expect(localModels.length).toBeGreaterThan(0);
  });

  it("routes coding tasks to a coder model", async () => {
    const instance = await router.route("implement a REST API endpoint for user authentication");
    expect(instance.config.taskType).toBe("coder");
  });

  it("routes simple queries to a fast model", async () => {
    const instance = await router.route("what is the status of the server?");
    expect(instance.config.taskType).toBe("fast");
  });

  it("routes analysis tasks to a reasoning model", async () => {
    const instance = await router.route("analyze the architecture trade-offs between microservices and monolith");
    expect(instance.config.taskType).toBe("reasoning");
  });

  it("routes strategy tasks to the brain model", async () => {
    const instance = await router.route("design a launch strategy for our new product");
    expect(instance.config.taskType).toBe("brain");
  });

  it("routes bulk tasks to the bulk model", async () => {
    const instance = await router.route("generate 100 social media posts for our campaign");
    expect(instance.config.taskType).toBe("bulk");
  });

  it("returns a model instance with a complete function", async () => {
    const instance = await router.route("hello");
    expect(typeof instance.complete).toBe("function");
    expect(instance.config).toBeDefined();
    expect(instance.config.id).toBeTruthy();
  });

  it("prefers cloud models by default", async () => {
    router.setPreferLocal(false);
    const instance = await router.route("simple task");
    expect(instance.config.isLocal).toBe(false);
  });

  it("prefers local models when configured", async () => {
    router.setPreferLocal(true);
    // "check" matches the fast task type — there is a local fast model (Gemma 4 31B)
    const instance = await router.route("check the status of the server");
    expect(instance.config.isLocal).toBe(true);
  });

  it("all models have required fields", () => {
    const models = router.availableModels();
    for (const model of models) {
      expect(model.id).toBeTruthy();
      expect(model.name).toBeTruthy();
      expect(model.provider).toBeTruthy();
      expect(model.taskType).toBeTruthy();
      expect(model.contextWindow).toBeGreaterThan(0);
      expect(model.maxTokens).toBeGreaterThan(0);
      expect(typeof model.costPerMTokIn).toBe("number");
      expect(typeof model.costPerMTokOut).toBe("number");
    }
  });

  it("local models have zero cost", () => {
    const models = router.availableModels();
    const localModels = models.filter((m) => m.isLocal);
    for (const model of localModels) {
      expect(model.costPerMTokIn).toBe(0);
      expect(model.costPerMTokOut).toBe(0);
    }
  });

  it("bulk model is among the cheapest cloud models", () => {
    const models = router.availableModels();
    const cloudModels = models.filter((m) => !m.isLocal);
    const bulkModel = cloudModels.find((m) => m.taskType === "bulk");
    const avgCost = cloudModels.reduce((sum, m) => sum + m.costPerMTokIn, 0) / cloudModels.length;
    // Bulk model should be well below the average cloud cost
    expect(bulkModel).toBeDefined();
    expect(bulkModel!.costPerMTokIn).toBeLessThan(avgCost);
  });

  it("handles unknown/general input gracefully", async () => {
    const instance = await router.route("do the thing");
    expect(instance).toBeDefined();
    expect(instance.config.taskType).toBe("general");
  });
});
