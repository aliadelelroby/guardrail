import { Controller, Get, Post, Body } from '@nestjs/common';
import { AppService } from './app.service';
import {
  Limit,
  Shield,
  Bot,
  Email,
  BlockVPN,
  TokenBucket,
  Filter,
  Result,
  IPInfo,
  Preset,
  SkipGuardrail,
  Tokens,
  byTier,
  Quota,
} from '@guardrail-dev/core/nestjs';
import {
  type Decision as DecisionType,
  type EnhancedIPInfo,
} from '@guardrail-dev/core';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  @Preset('web')
  getHello(): string {
    return this.appService.getHello();
  }

  @Get('profile')
  @Preset('api')
  getProfile(@IPInfo() ip: EnhancedIPInfo, @Result() decision: DecisionType) {
    return {
      message: 'This is your profile info.',
      ip: decision.characteristics['ip.src'],
      location: `${ip.city}, ${ip.countryName}`,
      isVpn: ip.isVpn(),
    };
  }

  @Get('tiered-limit')
  @Limit({
    // Dynamic limit: free gets 2, pro gets 10
    max: byTier({ free: 2, pro: 10 }),
    interval: '1m',
  })
  getTieredData(@Result() decision: DecisionType) {
    return {
      message: `You are accessing this route with ${decision.characteristics.tier} limits.`,
      remaining: decision.reason.getRemaining(),
    };
  }

  @Get('ai/generate')
  @TokenBucket({
    capacity: 1000,
    refillRate: 100,
    interval: '1m',
    by: ['ip.src'],
  })
  generateText(@Tokens() tokens: number = 10) {
    return {
      text: 'This is generated text using token bucket limits.',
      tokensConsumed: tokens,
    };
  }

  @Post('auth/login')
  @Limit({ max: 5, interval: '1m' }) // Prevent brute force
  @Email({ block: ['DISPOSABLE'] })
  login(@Body() body: { email: string }) {
    return {
      success: true,
      user: body.email,
      message: 'Login successful (simulated)',
    };
  }

  @Get('admin')
  @Filter({ allow: ['ip.src.country == "US"'] }) // Only allow US for admin
  @Shield({ mode: 'LIVE' })
  getAdminData(@Result() decision: DecisionType) {
    return {
      message: 'Welcome to the admin panel.',
      allowedBy: decision.results[0].rule,
    };
  }

  @Get('saas/resource')
  @Quota({
    burst: 5,
    daily: 'subscription.dailyQuota',
    monthly: 'subscription.monthlyCap',
  })
  getSaaSResource(@Result() decision: DecisionType) {
    return {
      message: 'Accessing premium SaaS resource.',
      tier: decision.metadata.tier,
      limits: {
        burstRemaining: decision.results.find(
          (r) => r.reset && r.reset - Date.now() <= 60000,
        )?.remaining,
        dailyRemaining: decision.results.find(
          (r) =>
            r.reset &&
            r.reset - Date.now() > 60000 &&
            r.reset - Date.now() <= 86400000,
        )?.remaining,
        monthlyRemaining: decision.results.find(
          (r) => r.reset && r.reset - Date.now() > 86400000,
        )?.remaining,
      },
    };
  }

  @Get('sensitive')
  @Shield()
  @Bot({ allow: [] }) // Block all bots
  @BlockVPN() // Block VPNs/Proxies
  getSensitiveData(@IPInfo() ip: EnhancedIPInfo) {
    return {
      message: 'This is a sensitive endpoint protected by Guardrail.',
      yourLocation: {
        country: ip.countryName,
        city: ip.city,
      },
    };
  }

  @Post('payment')
  @Limit({ max: 3, interval: '1m' }) // Strict rate limit
  @Email({ block: ['DISPOSABLE', 'INVALID'] })
  processPayment(
    @Body() body: { email: string },
    @Result() decision: DecisionType,
  ) {
    return {
      success: true,
      message: 'Payment processed successfully',
      requestId: decision.id,
    };
  }

  @Get('unprotected')
  @SkipGuardrail()
  getPublic() {
    return { message: 'This route has no security checks.' };
  }
}
