/**
 * Core types and interfaces for Guardrail
 * @module types
 */

/**
 * Operation mode for rules
 * - LIVE: Rules are enforced and can deny requests
 * - DRY_RUN: Rules are evaluated but always allow requests
 */
export type Mode = "LIVE" | "DRY_RUN";

/**
 * Final decision conclusion for a request
 */
export type DecisionConclusion = "ALLOW" | "DENY";

/**
 * Rate limit denial reason
 */
export type RateLimitReason = "RATE_LIMIT";

/**
 * Bot detection denial reason
 */
export type BotReason = "BOT";

/**
 * Email validation denial reason
 */
export type EmailReason = "EMAIL";

/**
 * Shield protection denial reason
 */
export type ShieldReason = "SHIELD";

/**
 * Filter rule denial reason
 */
export type FilterReason = "FILTER";

/**
 * Quota exceeded denial reason
 */
export type QuotaReason = "QUOTA";

/**
 * All possible reasons for denying a request
 */
export type DenialReason =
  | RateLimitReason
  | BotReason
  | EmailReason
  | ShieldReason
  | FilterReason
  | QuotaReason;

/**
 * IP address information from geolocation services
 */
export interface IPInfo {
  /** ISO country code (e.g., "US", "GB") */
  country?: string;
  /** Full country name */
  countryName?: string;
  /** Region or state code */
  region?: string;
  /** City name */
  city?: string;
  /** Continent code */
  continent?: string;
  /** Full continent name */
  continentName?: string;
  /** Latitude coordinate */
  latitude?: number;
  /** Longitude coordinate */
  longitude?: number;
  /** Postal/ZIP code */
  postalCode?: string;
  /** Timezone identifier */
  timezone?: string;
  /** Accuracy radius in kilometers */
  accuracyRadius?: number;
  /** Autonomous System Number */
  asn?: number;
  /** ASN organization name */
  asnName?: string;
  /** ASN domain */
  asnDomain?: string;
  /** ASN country code */
  asnCountry?: string;
  /** Type of ASN organization */
  asnType?: "isp" | "hosting" | "business" | "education";
  /** Service provider name */
  service?: string;
  /** Whether IP is from a hosting provider */
  isHosting?: boolean;
  /** Whether IP is from a VPN */
  isVpn?: boolean;
  /** Whether IP is from a proxy */
  isProxy?: boolean;
  /** Whether IP is from a relay service */
  isRelay?: boolean;
  /** Whether IP is from Tor network */
  isTor?: boolean;
}

/**
 * Enhanced IP information with helper methods for checking property existence
 */
export interface EnhancedIPInfo extends Omit<
  IPInfo,
  "isHosting" | "isVpn" | "isProxy" | "isRelay" | "isTor"
> {
  /** Checks if country code is available */
  hasCountry(): boolean;
  /** Checks if country name is available */
  hasCountryName(): boolean;
  /** Checks if region is available */
  hasRegion(): boolean;
  /** Checks if city is available */
  hasCity(): boolean;
  /** Checks if continent code is available */
  hasContinent(): boolean;
  /** Checks if continent name is available */
  hasContinentName(): boolean;
  /** Checks if latitude is available */
  hasLatitude(): boolean;
  /** Checks if longitude is available */
  hasLongitude(): boolean;
  /** Checks if postal code is available */
  hasPostalCode(): boolean;
  /** Checks if timezone is available */
  hasTimezone(): boolean;
  /** Checks if ASN is available */
  hasASN(): boolean;
  /** Checks if ASN name is available */
  hasASNName(): boolean;
  /** Checks if ASN domain is available */
  hasASNDomain(): boolean;
  /** Checks if ASN country is available */
  hasASNCountry(): boolean;
  /** Checks if service is available */
  hasService(): boolean;
  /** Checks if IP is from a hosting provider */
  isHosting(): boolean;
  /** Checks if IP is from a VPN */
  isVpn(): boolean;
  /** Checks if IP is from a proxy */
  isProxy(): boolean;
  /** Checks if IP is from a relay service */
  isRelay(): boolean;
  /** Checks if IP is from Tor network */
  isTor(): boolean;
}

/**
 * Decision reason with helper methods to check denial type
 */
export interface DecisionReason {
  /** Checks if denial is due to rate limiting */
  isRateLimit(): boolean;
  /** Checks if denial is due to bot detection */
  isBot(): boolean;
  /** Checks if denial is due to email validation */
  isEmail(): boolean;
  /** Checks if denial is due to shield protection */
  isShield(): boolean;
  /** Checks if denial is due to filter rule */
  isFilter(): boolean;
  /** Checks if denial is due to quota exceeded */
  isQuota(): boolean;
  /** Gets remaining quota/rate limit if applicable */
  getRemaining(): number | undefined;
}

/**
 * Final decision result from guardrail protection evaluation
 */
export interface Decision {
  /** Unique decision identifier */
  id: string;
  /** Final conclusion: ALLOW or DENY */
  conclusion: DecisionConclusion;
  /** Decision reason with helper methods */
  reason: DecisionReason;
  /** Results from all evaluated rules */
  results: RuleResult[];
  /** Enhanced IP information */
  ip: EnhancedIPInfo;
  /** Request characteristics used for evaluation */
  characteristics: Record<string, string | number | undefined>;
  /** Checks if request is allowed */
  isAllowed(): boolean;
  /** Checks if request is denied */
  isDenied(): boolean;
}

/**
 * Result from evaluating a single rule
 */
export interface RuleResult {
  /** Rule type identifier */
  rule: string;
  /** Rule conclusion */
  conclusion: DecisionConclusion;
  /** Denial reason if conclusion is DENY */
  reason?: DenialReason;
  /** Remaining quota/limit if applicable */
  remaining?: number;
  /** Reset timestamp in milliseconds if applicable */
  reset?: number;
}

/**
 * Options for protect method evaluation
 */
export interface ProtectOptions {
  /** Number of tokens/units requested (for token bucket) */
  requested?: number;
  /** Email address to validate */
  email?: string;
  /** User identifier */
  userId?: string;
  /** Additional custom characteristics */
  [key: string]: string | number | undefined;
}

/**
 * Error handling mode
 */
export type ErrorHandlingMode = "FAIL_OPEN" | "FAIL_CLOSED";

/**
 * Evaluation strategy
 */
export type EvaluationStrategy = "SEQUENTIAL" | "PARALLEL" | "SHORT_CIRCUIT";

/**
 * Configuration for Guardrail instance
 */
export interface GuardrailConfig {
  /** Optional key identifier for this guardrail instance */
  key?: string;
  /** Default mode for rules (can be overridden per rule) */
  mode?: Mode;
  /** Array of rules to evaluate */
  rules: GuardrailRule[];
  /** Default characteristics to use for rate limiting */
  characteristics?: string[];
  /** Storage adapter for rate limiting (defaults to MemoryStorage) */
  storage?: StorageAdapter;
  /** IP geolocation service (defaults to IPGeolocation) */
  ipService?: IPGeolocationService;
  /** Error handling mode (default: FAIL_OPEN) */
  errorHandling?: ErrorHandlingMode;
  /** Evaluation strategy (default: SEQUENTIAL) */
  evaluationStrategy?: EvaluationStrategy;
  /** Enable debug mode */
  debug?: boolean;
  /** Whitelist configuration */
  whitelist?: WhitelistConfig;
  /** Blacklist configuration */
  blacklist?: BlacklistConfig;
}

/**
 * Whitelist configuration
 */
export interface WhitelistConfig {
  /** Allowed IP addresses */
  ips?: string[];
  /** Allowed user IDs */
  userIds?: string[];
  /** Allowed countries */
  countries?: string[];
  /** Allowed email domains */
  emailDomains?: string[];
}

/**
 * Blacklist configuration
 */
export interface BlacklistConfig {
  /** Blocked IP addresses */
  ips?: string[];
  /** Blocked user IDs */
  userIds?: string[];
  /** Blocked countries */
  countries?: string[];
  /** Blocked email domains */
  emailDomains?: string[];
}

/**
 * Base interface for all rule types
 */
export interface Rule {
  /** Rule operation mode */
  mode: Mode;
  /** Rule type identifier */
  type: GuardrailRuleType;
}

/**
 * All possible rule type identifiers
 */
export type GuardrailRuleType =
  | "tokenBucket"
  | "slidingWindow"
  | "detectBot"
  | "validateEmail"
  | "shield"
  | "filter"
  | "custom";

/**
 * Storage adapter interface for rate limiting data persistence
 */
export interface StorageAdapter {
  /** Gets a value by key */
  get(key: string): Promise<string | null>;
  /** Sets a value with optional TTL in milliseconds */
  set(key: string, value: string, ttl?: number): Promise<void>;
  /** Increments a numeric value (default: 1) */
  increment(key: string, amount?: number): Promise<number>;
  /** Decrements a numeric value (default: 1) */
  decrement(key: string, amount?: number): Promise<number>;
  /** Deletes a key */
  delete(key: string): Promise<void>;
}

/**
 * IP geolocation service interface
 */
export interface IPGeolocationService {
  /** Looks up IP information */
  lookup(ip: string): Promise<IPInfo>;
}

/**
 * Token bucket rate limiting configuration
 */
export interface TokenBucketConfig extends Rule {
  type: "tokenBucket";
  /** Characteristics to use for rate limiting key generation */
  characteristics: string[];
  /** Number of tokens to refill per interval */
  refillRate: number;
  /** Refill interval (e.g., "1h", "30m", "5s") */
  interval: string;
  /** Maximum bucket capacity */
  capacity: number;
}

/**
 * Sliding window rate limiting configuration
 */
export interface SlidingWindowConfig extends Rule {
  type: "slidingWindow";
  /** Characteristics to use for rate limiting key generation */
  characteristics?: string[];
  /** Time window interval (e.g., "1h", "30m", "5s") */
  interval: string;
  /** Maximum requests allowed in the window */
  max: number;
}

/**
 * Bot detection configuration
 */
export interface BotDetectionConfig extends Rule {
  type: "detectBot";
  /** User agents to explicitly allow */
  allow: string[];
  /** User agents to explicitly block */
  block?: string[];
}

/**
 * Email validation configuration
 */
export interface EmailValidationConfig extends Rule {
  type: "validateEmail";
  /** Email block reasons to enforce */
  block: EmailBlockReason[];
}

/**
 * Reasons for blocking an email address
 */
export type EmailBlockReason = 
  | "DISPOSABLE" 
  | "INVALID" 
  | "NO_MX_RECORDS" 
  | "FREE"
  | "ROLE_BASED"
  | "CATCH_ALL"
  | "UNVERIFIABLE"
  | "TYPO_DOMAIN";

/**
 * Shield protection configuration
 */
export interface ShieldConfig extends Rule {
  type: "shield";
}

/**
 * Filter rule configuration
 */
export interface FilterConfig extends Rule {
  type: "filter";
  /** Allow list criteria */
  allow?: string[];
  /** Deny list criteria */
  deny?: string[];
  /** Characteristics to use for filtering */
  characteristics?: string[];
}

/**
 * Union type of all supported guardrail rule configurations
 */
export type GuardrailRule =
  | TokenBucketConfig
  | SlidingWindowConfig
  | BotDetectionConfig
  | EmailValidationConfig
  | ShieldConfig
  | FilterConfig
  | CustomRuleConfig;

/**
 * Custom rule configuration
 */
export interface CustomRuleConfig extends Rule {
  type: "custom";
  ruleType: string;
  config: Record<string, unknown>;
}
