import { Injectable } from '@nestjs/common';

export interface UserSubscription {
  id: string;
  tier: 'free' | 'pro' | 'enterprise';
  dailyQuota: number;
  monthlyCap: number;
  burstLimit: number;
}

@Injectable()
export class SubscriptionService {
  private users: Record<string, UserSubscription> = {
    user_free: {
      id: 'user_free',
      tier: 'free',
      dailyQuota: 5,
      monthlyCap: 50,
      burstLimit: 2,
    },
    user_pro: {
      id: 'user_pro',
      tier: 'pro',
      dailyQuota: 100,
      monthlyCap: 1000,
      burstLimit: 20,
    },
    user_enterprise: {
      id: 'user_enterprise',
      tier: 'enterprise',
      dailyQuota: 10000,
      monthlyCap: 500000,
      burstLimit: 500,
    },
  };

  async getSubscription(userId: string): Promise<UserSubscription> {
    // Simulate DB delay
    await new Promise((resolve) => setTimeout(resolve, 50));
    return this.users[userId] || this.users.user_free;
  }
}
