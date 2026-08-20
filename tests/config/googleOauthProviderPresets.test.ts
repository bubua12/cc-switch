import { describe, expect, it } from "vitest";
import { claudeDesktopProviderPresets } from "@/config/claudeDesktopProviderPresets";
import { providerPresets } from "@/config/claudeProviderPresets";
import { codexProviderPresets } from "@/config/codexProviderPresets";
import {
  extractCodexBaseUrl,
  extractCodexModelName,
  extractCodexWireApi,
} from "@/utils/providerConfigUtils";

describe("Google AI OAuth provider presets", () => {
  it("pins the Claude Code preset to managed Gemini Native auth", () => {
    const preset = providerPresets.find(
      (entry) => entry.name === "Google AI (Gemini OAuth)",
    );
    expect(preset).toBeDefined();
    expect(preset).toMatchObject({
      category: "official",
      apiFormat: "gemini_native",
      providerType: "google_oauth",
      requiresOAuth: true,
      icon: "gemini",
    });
    expect((preset!.settingsConfig as Record<string, unknown>).env).toMatchObject({
      ANTHROPIC_BASE_URL: "https://generativelanguage.googleapis.com",
      ANTHROPIC_MODEL: "gemini-2.5-pro",
    });
  });

  it("pins the Claude Desktop preset to proxy Gemini Native mode", () => {
    const preset = claudeDesktopProviderPresets.find(
      (entry) => entry.name === "Google AI (Gemini OAuth)",
    );
    expect(preset).toBeDefined();
    expect(preset).toMatchObject({
      category: "official",
      baseUrl: "https://generativelanguage.googleapis.com",
      mode: "proxy",
      apiFormat: "gemini_native",
      providerType: "google_oauth",
      requiresOAuth: true,
      icon: "gemini",
    });
  });

  it("pins the Codex preset to Google Gemini OAuth", () => {
    const preset = codexProviderPresets.find(
      (entry) => entry.name === "Google Gemini (OAuth)",
    );
    expect(preset).toBeDefined();
    expect(preset).toMatchObject({
      category: "official",
      apiFormat: "openai_chat",
      providerType: "google_oauth",
      requiresOAuth: true,
      icon: "gemini",
    });
    expect(extractCodexBaseUrl(preset!.config)).toBe(
      "https://generativelanguage.googleapis.com",
    );
    expect(extractCodexModelName(preset!.config)).toBe("gemini-2.5-pro");
  });
});
