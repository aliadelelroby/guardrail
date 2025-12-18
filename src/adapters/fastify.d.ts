import { Decision } from "../types/index";

declare module "fastify" {
  interface FastifyRequest {
    guardrail?: Decision;
  }
}
