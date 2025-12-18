import { Module, MiddlewareConsumer, NestModule } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { GuardrailModule } from '@guardrail-dev/core/nestjs';
import { SubscriptionService } from './subscription.service';
import { SubscriptionMiddleware } from './subscription.middleware';

@Module({
  imports: [
    GuardrailModule.forRoot({
      autoProtect: true, // Automatically protect all routes with 'api' preset
      useGuard: true,
      debug: true,
      // Tell Guardrail how to find the email in your requests
      emailExtractor: (req) => req.body?.email || req.query?.email,
      // Tell Guardrail how to find the user ID (checking query for demo purposes)
      userExtractor: (req) =>
        req.subscription?.id || req.query?.userId || 'anonymous',
      // Tell Guardrail how to find the requested tokens (for AI routes)
      tokensExtractor: (req) => parseInt(req.query?.tokens) || req.body?.tokens,
      metadataExtractor: (req) => ({
        // Map subscription data to metadata for dynamic limit resolution
        subscription: req.subscription,
        tier: req.subscription?.tier || 'free',
      }),
    }),
  ],
  controllers: [AppController],
  providers: [AppService, SubscriptionService],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(SubscriptionMiddleware).forRoutes('*');
  }
}
