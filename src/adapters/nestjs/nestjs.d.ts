/**
 * Type declarations for Nest.js adapter
 */

import type { Decision } from "../../types/index";

declare module "@nestjs/common" {
  interface Request {
    guardrail?: Decision;
  }
}
