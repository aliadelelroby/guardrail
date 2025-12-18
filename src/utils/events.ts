/**
 * Event system for Guardrail
 * @module utils/events
 */

import type { Decision, RuleResult } from "../types/index";

/**
 * Event types
 */
export type GuardrailEventType =
  | "rule.evaluate"
  | "rule.allow"
  | "rule.deny"
  | "decision.allowed"
  | "decision.denied"
  | "storage.error"
  | "ip-lookup.error";

/**
 * Base event interface
 */
export interface GuardrailEvent {
  type: GuardrailEventType;
  timestamp: number;
  decisionId?: string;
}

/**
 * Rule evaluation event
 */
export interface RuleEvaluateEvent extends GuardrailEvent {
  type: "rule.evaluate";
  ruleType: string;
}

/**
 * Rule result event
 */
export interface RuleResultEvent extends GuardrailEvent {
  type: "rule.allow" | "rule.deny";
  ruleType: string;
  result: RuleResult;
}

/**
 * Decision event
 */
export interface DecisionEvent extends GuardrailEvent {
  type: "decision.allowed" | "decision.denied";
  decision: Decision;
}

/**
 * Error event
 */
export interface ErrorEvent extends GuardrailEvent {
  type: "storage.error" | "ip-lookup.error";
  error: Error;
  context?: Record<string, unknown>;
}

/**
 * Union type of all events
 */
export type GuardrailEventUnion = RuleEvaluateEvent | RuleResultEvent | DecisionEvent | ErrorEvent;

/**
 * Event handler function type
 */
export type EventHandler = (event: GuardrailEventUnion) => void | Promise<void>;

/**
 * Event emitter for Guardrail
 */
export class GuardrailEventEmitter {
  private handlers: Map<GuardrailEventType, EventHandler[]> = new Map();

  /**
   * Registers an event handler
   * @param eventType - Event type to listen for
   * @param handler - Event handler function
   * @returns Unsubscribe function
   */
  on(eventType: GuardrailEventType, handler: EventHandler): () => void {
    if (!this.handlers.has(eventType)) {
      this.handlers.set(eventType, []);
    }
    this.handlers.get(eventType)!.push(handler);

    return () => {
      const handlers = this.handlers.get(eventType);
      if (handlers) {
        const index = handlers.indexOf(handler);
        if (index > -1) {
          handlers.splice(index, 1);
        }
      }
    };
  }

  /**
   * Emits an event
   * @param event - Event to emit
   */
  async emit(event: GuardrailEventUnion): Promise<void> {
    const handlers = this.handlers.get(event.type) || [];
    await Promise.all(handlers.map((handler) => handler(event)));
  }

  /**
   * Removes all event handlers
   */
  removeAllListeners(): void {
    this.handlers.clear();
  }
}
