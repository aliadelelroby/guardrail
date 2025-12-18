import { Injectable, NestMiddleware } from '@nestjs/common';
import { SubscriptionService } from './subscription.service';

@Injectable()
export class SubscriptionMiddleware implements NestMiddleware {
  constructor(private subscriptionService: SubscriptionService) {}

  async use(req: any, res: any, next: () => void) {
    const userId = req.query.userId || req.headers['x-user-id'] || 'user_free';

    // Fetch from "DB"
    const subscription = await this.subscriptionService.getSubscription(userId);

    // Attach to request so Guardrail can see it
    req.subscription = subscription;
    next();
  }
}
