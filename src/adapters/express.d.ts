/**
 * Type declarations for Express adapter
 */

import type { Decision } from "../types/index";

declare global {
  namespace Express {
    interface Request {
      guardrail?: Decision;
    }
  }
}
