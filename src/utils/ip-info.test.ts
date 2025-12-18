import { describe, it, expect } from "vitest";
import { EnhancedIPInfo } from "./ip-info";
import type { IPInfo } from "../types/index";

describe("EnhancedIPInfo", () => {
  it("should check if country exists", () => {
    const info: IPInfo = { country: "US" };
    const enhanced = new EnhancedIPInfo(info);

    expect(enhanced.hasCountry()).toBe(true);
    expect(enhanced.country).toBe("US");
  });

  it("should check if country doesn't exist", () => {
    const info: IPInfo = {};
    const enhanced = new EnhancedIPInfo(info);

    expect(enhanced.hasCountry()).toBe(false);
  });

  it("should check VPN status", () => {
    const info: IPInfo = { isVpn: true };
    const enhanced = new EnhancedIPInfo(info);

    expect(enhanced.isVpn()).toBe(true);
  });

  it("should check proxy status", () => {
    const info: IPInfo = { isProxy: true };
    const enhanced = new EnhancedIPInfo(info);

    expect(enhanced.isProxy()).toBe(true);
  });

  it("should check hosting status", () => {
    const info: IPInfo = { isHosting: true };
    const enhanced = new EnhancedIPInfo(info);

    expect(enhanced.isHosting()).toBe(true);
  });

  it("should check all helper methods", () => {
    const info: IPInfo = {
      country: "US",
      countryName: "United States",
      region: "California",
      city: "San Francisco",
      continent: "NA",
      continentName: "North America",
      latitude: 37.7749,
      longitude: -122.4194,
      postalCode: "94102",
      timezone: "America/Los_Angeles",
      asn: 12345,
      asnName: "Example ASN",
      asnDomain: "example.com",
      asnCountry: "US",
      service: "Example Service",
    };

    const enhanced = new EnhancedIPInfo(info);

    expect(enhanced.hasCountry()).toBe(true);
    expect(enhanced.hasCountryName()).toBe(true);
    expect(enhanced.hasRegion()).toBe(true);
    expect(enhanced.hasCity()).toBe(true);
    expect(enhanced.hasContinent()).toBe(true);
    expect(enhanced.hasContinentName()).toBe(true);
    expect(enhanced.hasLatitude()).toBe(true);
    expect(enhanced.hasLongitude()).toBe(true);
    expect(enhanced.hasPostalCode()).toBe(true);
    expect(enhanced.hasTimezone()).toBe(true);
    expect(enhanced.hasASN()).toBe(true);
    expect(enhanced.hasASNName()).toBe(true);
    expect(enhanced.hasASNDomain()).toBe(true);
    expect(enhanced.hasASNCountry()).toBe(true);
    expect(enhanced.hasService()).toBe(true);
  });
});
