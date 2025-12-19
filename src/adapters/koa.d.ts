import type { Decision } from "../types/index";

declare module "koa" {
  interface BaseContext {
    state: {
      guardrail?: Decision;
    };
  }
}
