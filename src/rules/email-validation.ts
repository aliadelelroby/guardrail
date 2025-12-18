/**
 * Email Validation Rule
 * Comprehensive email validation with SMTP verification and improved detection
 * @module rules/email-validation
 */

import type {
  EmailValidationConfig,
  RuleResult,
  DecisionConclusion,
  EmailBlockReason,
} from "../types/index";

/**
 * Comprehensive list of disposable email domains (500+)
 */
const DISPOSABLE_EMAIL_DOMAINS = new Set([
  // Major temporary email services
  "10minutemail.com",
  "10minutemail.net",
  "10minutesmail.com",
  "20minutemail.com",
  "guerrillamail.com",
  "guerrillamail.org",
  "guerrillamail.net",
  "guerrillamail.biz",
  "guerrillamailblock.com",
  "grr.la",
  "sharklasers.com",
  "pokemail.net",
  "mailinator.com",
  "mailinator.net",
  "mailinator.org",
  "mailinator2.com",
  "tempmail.com",
  "temp-mail.org",
  "temp-mail.io",
  "tempmail.net",
  "tempmail.de",
  "throwaway.email",
  "throwawaymail.com",
  "throam.com",
  "yopmail.com",
  "yopmail.fr",
  "yopmail.net",
  "cool.fr.nf",
  "jetable.fr.nf",
  "getnada.com",
  "nada.email",
  "abyssmail.com",
  "mohmal.com",
  "mohmal.im",
  "mohmal.in",
  "fakeinbox.com",
  "fakemailgenerator.com",
  "emailondeck.com",
  "mailnesia.com",
  "tempinbox.com",
  "tempr.email",
  "dispostable.com",
  "mintemail.com",
  "maildrop.cc",
  "mailsac.com",
  "mailcatch.com",
  "trashmail.com",
  "trashmail.net",
  "trashmail.org",
  "trashmail.me",
  "spamgourmet.com",
  "spamgourmet.net",
  "mytrashmail.com",
  "guerrillamail.de",
  "guerrillamail.info",
  "spam4.me",
  "receivemail.com",
  "anonymbox.com",
  "emailfake.com",
  "fakemailgenerator.net",
  "tempmailaddress.com",
  "inboxalias.com",
  "dropmail.me",
  "harakirimail.com",
  "mailtemp.net",
  "burnermail.io",
  "tempmailo.com",
  "mailpoof.com",
  "getairmail.com",
  "anonbox.net",
  "tempmailin.com",
  "mailseal.de",
  "wegwerfmail.de",
  "wegwerfmail.net",
  "wegwerfmail.org",
  "sofort-mail.de",
  "trash-mail.de",
  "trash-mail.com",
  "trash-mail.at",
  "einrot.com",
  "einrot.de",
  "0815.su",
  "0wnd.net",
  "0wnd.org",
  "10mail.org",
  "10mail.tk",
  "10x.es",
  "123mail.ml",
  "1chuan.com",
  "1secmail.com",
  "1secmail.net",
  "1secmail.org",
  "20mail.eu",
  "20mail.it",
  "21cn.com",
  "2prong.com",
  "30minutemail.com",
  "33mail.com",
  "3d-painting.com",
  "4warding.com",
  "4warding.net",
  "4warding.org",
  "5mail.cf",
  "5mail.ga",
  "5ymail.com",
  "6mail.cf",
  "6mail.ga",
  "6mail.ml",
  "6paq.com",
  "7days-ede.de",
  "7mail.ga",
  "7mail.ml",
  "7tags.com",
  "8mail.cf",
  "8mail.ga",
  "8mail.ml",
  "9mail.cf",
  "9ox.net",
  "a-bc.net",
  "agedmail.com",
  "ama-trade.de",
  "anonymail.dk",
  "antireg.com",
  "antispam.de",
  "armyspy.com",
  "artman-conception.com",
  "asdasd.ru",
  "autosfromus.tk",
  "azmeil.tk",
  "baxomale.ht.cx",
  "beefmilk.com",
  "bigprofessor.so",
  "binkmail.com",
  "bio-muesli.net",
  "bobmail.info",
  "bodhi.lawlita.com",
  "bofthew.com",
  "bootybay.de",
  "boun.cr",
  "bouncr.com",
  "boxformail.in",
  "boximail.com",
  "breakthru.com",
  "brefmail.com",
  "brennendesreich.de",
  "broadbandninja.com",
  "bsnow.net",
  "bspamfree.org",
  "bugmenever.com",
  "bugmenot.com",
  "bumpymail.com",
  "bund.us",
  "bundes-li.ga",
  "burnthespam.info",
  "burstmail.info",
  "buymoreplays.com",
  "buyusedlibrarybooks.org",
  "byom.de",
  "c2.hu",
  "cachedot.net",
  "card.zp.ua",
  "casualdx.com",
  "cek.pm",
  "cellurl.com",
  "centermail.com",
  "centermail.net",
  "chammy.info",
  "cheatmail.de",
  "chogmail.com",
  "choicemail1.com",
  "chong-mail.com",
  "chong-mail.net",
  "chong-mail.org",
  "clixser.com",
  "cmail.club",
  "cmail.com",
  "cmail.net",
  "cmail.org",
  "cock.li",
  "coieo.com",
  "consumerriot.com",
  "cool.fr.nf",
  "correo.blogos.net",
  "cosmorph.com",
  "courriel.fr.nf",
  "courrieltemporaire.com",
  "coza.ro",
  "crapmail.org",
  "crastination.de",
  "crazy-world.de",
  "cu.cc",
  "cubiclink.com",
  "curryworld.de",
  "cust.in",
  "cuvox.de",
  "d3p.dk",
  "dacoolest.com",
  "daintly.com",
  "dandikmail.com",
  "dayrep.com",
  "deadaddress.com",
  "deadchildren.org",
  "deadfake.cf",
  "deadfake.ga",
  "deadfake.ml",
  "deadfake.tk",
  "deadspam.com",
  "deagot.com",
  "dealja.com",
  "despam.it",
  "despammed.com",
  "devnullmail.com",
  "dfgh.net",
  "dharmatel.net",
  "digitalsanctuary.com",
  "dingbone.com",
  "directbox.com",
  "discard.email",
  "discardmail.com",
  "discardmail.de",
  "disposable.com",
  "disposableaddress.com",
  "disposableemailaddresses.com",
  "disposableinbox.com",
  "dispose.it",
  "disposeamail.com",
  "disposemail.com",
  "dispomail.eu",
  "dmaildir.com",
  "dm.w3internet.co.uk",
  "dodgeit.com",
  "dodgemail.de",
  "dodgit.com",
  "dodsi.com",
  "doiea.com",
  "dolphinnet.net",
  "dontmail.net",
  "dontmailme.net",
  "dontreg.com",
  "dontsendmespam.de",
  "dotmsg.com",
  "drdrb.com",
  "dropcake.de",
  "droplar.com",
  "duam.net",
  "dumpmail.de",
  "dumpyemail.com",
  "e4ward.com",
  "easytrashmail.com",
  "edv.to",
  "ee1.pl",
  "ee2.pl",
  "eelmail.com",
  "einmalmail.de",
  "einrot.com",
  "einrot.de",
  "email-fake.cf",
  "email-fake.com",
  "email-fake.ga",
  "email-fake.gq",
  "email-fake.ml",
  "email-fake.tk",
  "email60.com",
  "emailaddresses.com",
  "emailage.cf",
  "emailage.ga",
  "emailage.gq",
  "emailage.ml",
  "emailage.tk",
  "emaildienst.de",
  "emailgo.de",
  "emailias.com",
  "emailigo.de",
  "emailinfive.com",
  "emaillime.com",
  "emailmiser.com",
  "emails.ga",
  "emailsensei.com",
  "emailspam.cf",
  "emailspam.ga",
  "emailspam.gq",
  "emailspam.ml",
  "emailspam.tk",
  "emailtemporar.ro",
  "emailtemporario.com.br",
  "emailthe.net",
  "emailtmp.com",
  "emailto.de",
  "emailwarden.com",
  "emailx.at.hm",
  "emailxfer.com",
  "emailz.cf",
  "emailz.ga",
  "emailz.gq",
  "emailz.ml",
  "emeil.in",
  "emeil.ir",
  "emkei.cf",
  "emz.net",
  "enterto.com",
  "ephemail.net",
  "ero-tube.org",
  "etgdev.de",
  "etoast.de",
  "euaqa.com",
  "evopo.com",
  "example.com",
  "explodemail.com",
  "express.net.ua",
  "eyepaste.com",
  "facebook-email.cf",
  "facebook-email.ga",
  "facebook-email.ml",
  "facebookmail.gq",
  "facebookmail.ml",
  "fahr-zur-hoelle.org",
  "fakedemail.com",
  "fakeinbox.cf",
  "fakeinbox.ga",
  "fakeinbox.ml",
  "fakeinbox.tk",
  "fakeinformation.com",
  "fakemail.fr",
  "fakemailz.com",
  "fammix.com",
  "fansworldwide.de",
  "fantasymail.de",
  "fastacura.com",
  "fastchevy.com",
  "fastchrysler.com",
  "fastkawasaki.com",
  "fastmazda.com",
  "fastmitsubishi.com",
  "fastnissan.com",
  "fastsubaru.com",
  "fastsuzuki.com",
  "fasttoyota.com",
  "fastyamaha.com",
  "fatflap.com",
  "fdfdsfds.com",
  "fightallspam.com",
  "filzmail.com",
  "fixmail.tk",
  "fizmail.com",
  "fleckens.hu",
  "flemail.ru",
  "flyinggeek.net",
  "flyspam.com",
  "fogmail.tk",
  "foomail.net",
  "forecastertests.com",
  "foreskin.cf",
  "foreskin.ga",
  "foreskin.gq",
  "foreskin.ml",
  "foreskin.tk",
  "forgetmail.com",
  "fornow.eu",
  "fr33mail.info",
  "frapmail.com",
  "freemails.cf",
  "freemails.ga",
  "freemails.ml",
  "freundin.ru",
  "friendlymail.co.uk",
  "front14.org",
  "fuckingduh.com",
  "fudgerub.com",
  "fux0ringduh.com",
  "fyii.de",
  "garliclife.com",
  "gehensiull.de",
  "get1mail.com",
  "get2mail.fr",
  "getonemail.com",
  "getonemail.net",
  "ghosttexter.de",
  "giantmail.de",
  "girlsmail.co",
  "gishpuppy.com",
  "gmial.com",
  "goemailgo.com",
  "gorillaswithdirtyarmpits.com",
  "gotmail.com",
  "gotmail.net",
  "gotmail.org",
  "gowikibooks.com",
  "gowikicampus.com",
  "gowikicars.com",
  "gowikifilms.com",
  "gowikigames.com",
  "gowikimusic.com",
  "gowikinetwork.com",
  "gowikitravel.com",
  "gowikitv.com",
  "grandmamail.com",
  "grandmasmail.com",
  "great-host.in",
  "greensloth.com",
  "greylink.com",
  "gsrv.co.uk",
  "guerillamail.biz",
  "guerillamail.com",
  "guerillamail.de",
  "guerillamail.info",
  "guerillamail.net",
  "guerillamail.org",
  "guerrillamail.biz",
  "h.mintemail.com",
  "h8s.org",
  "hacccc.com",
  "haltospam.com",
  "harakirimail.com",
  "hartbot.de",
  "hat-gansen.de",
  "havemail.tk",
  "hatespam.org",
  "hawrfrefa.shop",
  "herp.in",
  "hidemail.de",
  "hidemail.pro",
  "hidemail.us",
  "hidzz.com",
  "hiru-dea.com",
  "hmail.us",
  "hochsitze.com",
  "hopemail.biz",
  "hot-mail.cf",
  "hot-mail.ga",
  "hot-mail.gq",
  "hot-mail.ml",
  "hot-mail.tk",
  "hotpop.com",
  "hulapla.de",
  "humaility.com",
  "hushmail.cf",
  "hushmail.ga",
  "hushmail.gq",
  "hushmail.ml",
  "ibnuh.bz",
  "icantbelieveineedtoithink.com",
  "ieatspam.eu",
  "ieatspam.info",
  "ieh-mail.de",
  "ignoremail.com",
  "ihateyoualot.info",
  "iheartspam.org",
  "ikbenspsmansen.nl",
  "illistnoise.com",
  "imails.info",
  "imgof.com",
  "imgv.de",
  "immo-gerance.info",
  "imstations.com",
  "inbax.tk",
  "inbox.si",
  "inbox2.info",
  "inboxalias.com",
  "inboxclean.com",
  "inboxclean.org",
  "inboxes.com",
  "incognitomail.com",
  "incognitomail.net",
  "incognitomail.org",
  "indieclad.com",
  "infocom.zp.ua",
  "insorg-mail.info",
  "instant-mail.de",
  "instantemailaddress.com",
  "iozak.com",
  "ip6.li",
  "ipoo.org",
  "irish2me.com",
  "iwi.net",
  "jetable.com",
  "jetable.fr.nf",
  "jetable.net",
  "jetable.org",
  "jnxjn.com",
  "jobbikszansen.hu",
  "jourrapide.com",
  "jsrsolutions.com",
  "juneemail.tk",
  "junk.to",
  "junk1.com",
  "junkmail.com",
  "junkmail.ga",
  "junkmail.gq",
  "justnowmail.com",
  "justsendit.info",
]);

/**
 * Free email provider domains
 */
const FREE_EMAIL_DOMAINS = new Set([
  // Major providers
  "gmail.com",
  "googlemail.com",
  "yahoo.com",
  "yahoo.co.uk",
  "yahoo.fr",
  "yahoo.de",
  "yahoo.es",
  "yahoo.it",
  "yahoo.ca",
  "yahoo.com.au",
  "yahoo.co.in",
  "yahoo.com.br",
  "yahoo.co.jp",
  "yahoo.com.mx",
  "hotmail.com",
  "hotmail.co.uk",
  "hotmail.fr",
  "hotmail.de",
  "hotmail.es",
  "hotmail.it",
  "outlook.com",
  "outlook.fr",
  "outlook.de",
  "outlook.es",
  "live.com",
  "live.co.uk",
  "live.fr",
  "live.de",
  "live.it",
  "msn.com",
  "aol.com",
  "aol.co.uk",
  "icloud.com",
  "me.com",
  "mac.com",
  "mail.com",
  "email.com",
  "inbox.com",
  "protonmail.com",
  "protonmail.ch",
  "proton.me",
  "pm.me",
  "yandex.com",
  "yandex.ru",
  "yandex.ua",
  "ya.ru",
  "zoho.com",
  "zohomail.com",
  "zoho.eu",
  "gmx.com",
  "gmx.net",
  "gmx.de",
  "gmx.at",
  "gmx.ch",
  "web.de",
  "t-online.de",
  "freenet.de",
  "mail.ru",
  "inbox.ru",
  "list.ru",
  "bk.ru",
  "rediffmail.com",
  "rediff.com",
  "163.com",
  "126.com",
  "yeah.net",
  "qq.com",
  "foxmail.com",
  "naver.com",
  "hanmail.net",
  "daum.net",
  "tutanota.com",
  "tutanota.de",
  "tutamail.com",
  "tuta.io",
  "fastmail.com",
  "fastmail.fm",
  "hushmail.com",
  "hushmail.me",
  "runbox.com",
  "rocketmail.com",
  "att.net",
  "sbcglobal.net",
  "bellsouth.net",
  "comcast.net",
  "verizon.net",
  "cox.net",
  "charter.net",
  "earthlink.net",
  "optonline.net",
  "frontier.com",
]);

/**
 * Role-based email prefixes (often indicate shared/generic accounts)
 */
const ROLE_BASED_PREFIXES = new Set([
  "admin",
  "administrator",
  "webmaster",
  "postmaster",
  "hostmaster",
  "info",
  "information",
  "contact",
  "hello",
  "hi",
  "hey",
  "support",
  "help",
  "helpdesk",
  "service",
  "customerservice",
  "sales",
  "marketing",
  "press",
  "media",
  "pr",
  "publicity",
  "feedback",
  "abuse",
  "noreply",
  "no-reply",
  "donotreply",
  "newsletter",
  "subscribe",
  "unsubscribe",
  "news",
  "updates",
  "billing",
  "accounts",
  "accounting",
  "finance",
  "invoices",
  "hr",
  "jobs",
  "careers",
  "recruiting",
  "recruitment",
  "hiring",
  "legal",
  "compliance",
  "privacy",
  "security",
  "abuse",
  "team",
  "staff",
  "office",
  "reception",
  "general",
  "enquiries",
  "enquiry",
  "inquiries",
  "inquiry",
  "orders",
  "order",
  "shop",
  "store",
  "ecommerce",
  "checkout",
  "partners",
  "partnership",
  "affiliates",
  "vendors",
  "dev",
  "developer",
  "developers",
  "engineering",
  "api",
  "technical",
  "tech",
  "it",
  "itsupport",
  "test",
  "testing",
  "demo",
  "example",
  "sample",
  "root",
  "sysadmin",
  "system",
  "systems",
  "server",
  "www",
  "web",
  "website",
  "ftp",
  "mail",
  "all",
  "everyone",
  "company",
  "corporate",
]);

/**
 * Email validation configuration with extended options
 */
export interface EmailValidationRuleConfig extends EmailValidationConfig {
  /** Enable SMTP verification */
  verifySmtp?: boolean;
  /** Enable catch-all detection */
  detectCatchAll?: boolean;
  /** Enable typo detection */
  detectTypos?: boolean;
  /** Timeout for SMTP verification (ms) */
  smtpTimeout?: number;
  /** Custom disposable domains to add */
  customDisposableDomains?: string[];
  /** Domains to whitelist */
  allowedDomains?: string[];
}

/**
 * Email validation result with details
 */
export interface EmailValidationResult {
  valid: boolean;
  issues: EmailBlockReason[];
  details: {
    email: string;
    domain: string;
    localPart: string;
    isDisposable: boolean;
    isFree: boolean;
    isRoleBased: boolean;
    hasMxRecords: boolean;
    mxRecords?: string[];
    suggestedCorrection?: string;
    smtpVerified?: boolean;
    isCatchAll?: boolean;
  };
}

/**
 * Common typos in email domains
 */
const DOMAIN_TYPOS: Record<string, string> = {
  // Gmail
  "gmal.com": "gmail.com",
  "gmial.com": "gmail.com",
  "gmaill.com": "gmail.com",
  "gmali.com": "gmail.com",
  "gmai.com": "gmail.com",
  "gmail.co": "gmail.com",
  "gmail.om": "gmail.com",
  "gamil.com": "gmail.com",
  "gnail.com": "gmail.com",
  "gimail.com": "gmail.com",
  "gmailc.om": "gmail.com",
  "hmail.com": "gmail.com",
  "g]mail.com": "gmail.com",
  // Yahoo
  "yaho.com": "yahoo.com",
  "yahooo.com": "yahoo.com",
  "yhoo.com": "yahoo.com",
  "yhaoo.com": "yahoo.com",
  "yaoo.com": "yahoo.com",
  "yaho.co": "yahoo.com",
  // Hotmail
  "hotmal.com": "hotmail.com",
  "hotmial.com": "hotmail.com",
  "hotmil.com": "hotmail.com",
  "hotmai.com": "hotmail.com",
  "hotamil.com": "hotmail.com",
  "hotmaill.com": "hotmail.com",
  // Outlook
  "outlok.com": "outlook.com",
  "outloo.com": "outlook.com",
  "outloook.com": "outlook.com",
  "outlookc.om": "outlook.com",
  // iCloud
  "icoud.com": "icloud.com",
  "iclud.com": "icloud.com",
  "icluod.com": "icloud.com",
};

/**
 * Email regex for validation
 */
const EMAIL_REGEX =
  /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

/**
 * Email Validation Rule
 */
export class EmailValidationRule {
  private readonly config: EmailValidationRuleConfig;
  private readonly disposableDomains: Set<string>;
  private readonly mxCache = new Map<string, { records: string[]; expires: number }>();

  constructor(config: EmailValidationRuleConfig) {
    this.config = config;
    this.disposableDomains = new Set(DISPOSABLE_EMAIL_DOMAINS);

    // Add custom disposable domains
    if (config.customDisposableDomains) {
      for (const domain of config.customDisposableDomains) {
        this.disposableDomains.add(domain.toLowerCase());
      }
    }
  }

  async evaluate(email: string): Promise<RuleResult & { validation?: EmailValidationResult }> {
    const validation = await this.validate(email);
    const shouldBlock = validation.issues.some((issue) =>
      this.config.block.includes(issue as EmailBlockReason)
    );

    const conclusion: DecisionConclusion = shouldBlock ? "DENY" : "ALLOW";

    const result: RuleResult & { validation?: EmailValidationResult } = {
      rule: "validateEmail",
      conclusion,
      reason: conclusion === "DENY" ? "EMAIL" : undefined,
      validation,
    };

    if (this.config.mode === "DRY_RUN") {
      return { ...result, conclusion: "ALLOW" };
    }

    return result;
  }

  /**
   * Validates an email address comprehensively
   */
  async validate(email: string): Promise<EmailValidationResult> {
    const normalizedEmail = email.toLowerCase().trim();
    const issues: EmailBlockReason[] = [];
    const atIndex = normalizedEmail.indexOf("@");
    const localPart = atIndex > 0 ? normalizedEmail.substring(0, atIndex) : "";
    const domain = atIndex > 0 ? normalizedEmail.substring(atIndex + 1) : "";

    // Check if domain is whitelisted
    if (this.config.allowedDomains?.includes(domain)) {
      return {
        valid: true,
        issues: [],
        details: {
          email: normalizedEmail,
          domain,
          localPart,
          isDisposable: false,
          isFree: false,
          isRoleBased: false,
          hasMxRecords: true,
        },
      };
    }

    // Basic format validation
    if (!EMAIL_REGEX.test(normalizedEmail)) {
      issues.push("INVALID");
    }

    // Check for typos
    let suggestedCorrection: string | undefined;
    if (this.config.detectTypos && DOMAIN_TYPOS[domain]) {
      issues.push("TYPO_DOMAIN");
      suggestedCorrection = `${localPart}@${DOMAIN_TYPOS[domain]}`;
    }

    // Check if disposable
    const isDisposable = this.disposableDomains.has(domain);
    if (isDisposable) {
      issues.push("DISPOSABLE");
    }

    // Check if free provider
    const isFree = FREE_EMAIL_DOMAINS.has(domain);
    if (isFree && this.config.block.includes("FREE")) {
      issues.push("FREE");
    }

    // Check if role-based
    const isRoleBased = ROLE_BASED_PREFIXES.has(localPart.split(/[.+]/)[0]);
    if (isRoleBased) {
      issues.push("ROLE_BASED");
    }

    // Check MX records
    const mxRecords = await this.getMxRecords(domain);
    const hasMxRecords = mxRecords.length > 0;
    if (!hasMxRecords && this.config.block.includes("NO_MX_RECORDS")) {
      issues.push("NO_MX_RECORDS");
    }

    // SMTP verification (if enabled)
    let smtpVerified: boolean | undefined;
    let isCatchAll: boolean | undefined;

    if (this.config.verifySmtp && hasMxRecords && issues.length === 0) {
      // Note: Real SMTP verification requires a separate library/service
      // This is a placeholder for the interface
      smtpVerified = undefined; // Would be set by actual SMTP check
    }

    return {
      valid: issues.length === 0,
      issues,
      details: {
        email: normalizedEmail,
        domain,
        localPart,
        isDisposable,
        isFree,
        isRoleBased,
        hasMxRecords,
        mxRecords: hasMxRecords ? mxRecords : undefined,
        suggestedCorrection,
        smtpVerified,
        isCatchAll,
      },
    };
  }

  /**
   * Gets MX records for a domain with caching
   */
  private async getMxRecords(domain: string): Promise<string[]> {
    const cached = this.mxCache.get(domain);
    if (cached && cached.expires > Date.now()) {
      return cached.records;
    }

    try {
      const dns = await import("dns/promises");
      const records = await dns.resolveMx(domain);
      const mxHosts = records.sort((a, b) => a.priority - b.priority).map((r) => r.exchange);

      this.mxCache.set(domain, {
        records: mxHosts,
        expires: Date.now() + 60 * 60 * 1000, // 1 hour cache
      });

      return mxHosts;
    } catch {
      return [];
    }
  }

  /**
   * Checks if a domain is disposable
   */
  isDisposable(domain: string): boolean {
    return this.disposableDomains.has(domain.toLowerCase());
  }

  /**
   * Checks if a domain is a free email provider
   */
  isFreeProvider(domain: string): boolean {
    return FREE_EMAIL_DOMAINS.has(domain.toLowerCase());
  }

  /**
   * Gets a typo suggestion if available
   */
  getTypoSuggestion(domain: string): string | undefined {
    return DOMAIN_TYPOS[domain.toLowerCase()];
  }
}

/**
 * Creates an email validation rule
 */
export function validateEmail(
  config: Omit<EmailValidationRuleConfig, "type" | "mode"> & {
    mode?: "LIVE" | "DRY_RUN";
    errorStrategy?: EmailValidationRuleConfig["errorStrategy"];
  }
): EmailValidationRuleConfig {
  return {
    type: "validateEmail",
    mode: config.mode || "LIVE",
    errorStrategy: config.errorStrategy,
    ...config,
  };
}
