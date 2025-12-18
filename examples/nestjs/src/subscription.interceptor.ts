import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { SubscriptionService } from './subscription.service';

@Injectable()
export class SubscriptionInterceptor implements NestInterceptor {
  constructor(private subscriptionService: SubscriptionService) {}

  async intercept(
    context: ExecutionContext,
    next: CallHandler,
  ): Promise<Observable<any>> {
    const request = context.switchToHttp().getRequest();
    const userId =
      request.query.userId || request.headers['x-user-id'] || 'user_free';

    // Fetch from "DB"
    const subscription = await this.subscriptionService.getSubscription(userId);

    // Attach to request so Guardrail can see it
    request.subscription = subscription;

    return next.handle();
  }
}
