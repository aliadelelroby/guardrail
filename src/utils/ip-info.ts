/**
 * Enhanced IPInfo class with helper methods
 * @module utils/ip-info
 */

import type { IPInfo, EnhancedIPInfo as IEnhancedIPInfo } from "../types/index";

/**
 * Enhanced IP information with helper methods for checking property existence
 */
export class EnhancedIPInfo implements IEnhancedIPInfo {
  country?: string;
  countryName?: string;
  region?: string;
  city?: string;
  continent?: string;
  continentName?: string;
  latitude?: number;
  longitude?: number;
  postalCode?: string;
  timezone?: string;
  accuracyRadius?: number;
  asn?: number;
  asnName?: string;
  asnDomain?: string;
  asnCountry?: string;
  asnType?: "isp" | "hosting" | "business" | "education";
  service?: string;
  private _isHosting?: boolean;
  private _isVpn?: boolean;
  private _isProxy?: boolean;
  private _isRelay?: boolean;
  private _isTor?: boolean;

  /**
   * Creates a new EnhancedIPInfo instance
   * @param info - IP information to enhance
   */
  constructor(info: IPInfo) {
    this.country = info.country;
    this.countryName = info.countryName;
    this.region = info.region;
    this.city = info.city;
    this.continent = info.continent;
    this.continentName = info.continentName;
    this.latitude = info.latitude;
    this.longitude = info.longitude;
    this.postalCode = info.postalCode;
    this.timezone = info.timezone;
    this.accuracyRadius = info.accuracyRadius;
    this.asn = info.asn;
    this.asnName = info.asnName;
    this.asnDomain = info.asnDomain;
    this.asnCountry = info.asnCountry;
    this.asnType = info.asnType;
    this.service = info.service;

    this._isHosting = info.isHosting;
    this._isVpn = info.isVpn;
    this._isProxy = info.isProxy;
    this._isRelay = info.isRelay;
    this._isTor = info.isTor;
  }

  hasCountry(): boolean {
    return this.country !== undefined && this.country !== null;
  }

  hasCountryName(): boolean {
    return this.countryName !== undefined && this.countryName !== null;
  }

  hasRegion(): boolean {
    return this.region !== undefined && this.region !== null;
  }

  hasCity(): boolean {
    return this.city !== undefined && this.city !== null;
  }

  hasContinent(): boolean {
    return this.continent !== undefined && this.continent !== null;
  }

  hasContinentName(): boolean {
    return this.continentName !== undefined && this.continentName !== null;
  }

  hasLatitude(): boolean {
    return this.latitude !== undefined && this.latitude !== null;
  }

  hasLongitude(): boolean {
    return this.longitude !== undefined && this.longitude !== null;
  }

  hasPostalCode(): boolean {
    return this.postalCode !== undefined && this.postalCode !== null;
  }

  hasTimezone(): boolean {
    return this.timezone !== undefined && this.timezone !== null;
  }

  hasASN(): boolean {
    return this.asn !== undefined && this.asn !== null;
  }

  hasASNName(): boolean {
    return this.asnName !== undefined && this.asnName !== null;
  }

  hasASNDomain(): boolean {
    return this.asnDomain !== undefined && this.asnDomain !== null;
  }

  hasASNCountry(): boolean {
    return this.asnCountry !== undefined && this.asnCountry !== null;
  }

  hasService(): boolean {
    return this.service !== undefined && this.service !== null;
  }

  isHosting(): boolean {
    return Boolean(this._isHosting);
  }

  isVpn(): boolean {
    return Boolean(this._isVpn);
  }

  isProxy(): boolean {
    return Boolean(this._isProxy);
  }

  isRelay(): boolean {
    return Boolean(this._isRelay);
  }

  isTor(): boolean {
    return Boolean(this._isTor);
  }
}
