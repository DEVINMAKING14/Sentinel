import React from 'react';
import { Settings, Shield, Sliders, CheckCircle, Lock, Server, Cpu } from 'lucide-react';

export const SettingsView: React.FC = () => {
  return (
    <div className="p-8 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="bg-white border border-[#E2E5E1] rounded-2xl p-6 shadow-[0_1px_3px_rgba(0,0,0,0.04)]">
        <div className="flex items-center gap-2 mb-1">
          <Settings className="w-5 h-5 text-[#426B57]" />
          <h2 className="text-lg font-bold text-[#202522]">Engine Architecture & Perimeter Security Governance</h2>
        </div>
        <p className="text-xs text-[#747C78]">
          Transparent configuration of Sentinel's isolated scanner sandbox, SSRF protection filters, multi-factor scoring weights, and threat feed integrations.
        </p>
      </div>

      {/* Grid: 2 Columns */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Card 1: SSRF Protection & Sandbox Rules */}
        <div className="bg-white border border-[#E2E5E1] rounded-2xl p-6 shadow-sm space-y-4">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-[#B42318]" />
            <h3 className="text-sm font-bold text-[#202522]">SSRF Defense & Outbound Firewall Rules</h3>
          </div>
          <p className="text-xs text-[#555C57]">
            Because users submit arbitrary target URLs, Sentinel enforces strict zero-trust egress validation prior to establishing any network connection:
          </p>

          <div className="space-y-2 text-xs font-mono">
            <div className="p-3 bg-[#F7F7F4] border border-[#E2E5E1] rounded-xl flex items-center justify-between">
              <span>Loopback Isolation (127.0.0.0/8, ::1)</span>
              <span className="text-emerald-700 font-bold">ENFORCED</span>
            </div>
            <div className="p-3 bg-[#F7F7F4] border border-[#E2E5E1] rounded-xl flex items-center justify-between">
              <span>RFC 1918 Private Ranges (10/8, 172.16/12, 192.168/16)</span>
              <span className="text-emerald-700 font-bold">ENFORCED</span>
            </div>
            <div className="p-3 bg-[#F7F7F4] border border-[#E2E5E1] rounded-xl flex items-center justify-between">
              <span>Cloud Metadata Blocking (169.254.169.254)</span>
              <span className="text-emerald-700 font-bold">ENFORCED</span>
            </div>
            <div className="p-3 bg-[#F7F7F4] border border-[#E2E5E1] rounded-xl flex items-center justify-between">
              <span>Redirect Hop Limits (Max 5 hops with SSRF re-check)</span>
              <span className="text-emerald-700 font-bold">ACTIVE</span>
            </div>
            <div className="p-3 bg-[#F7F7F4] border border-[#E2E5E1] rounded-xl flex items-center justify-between">
              <span>Socket Connection Timeout (5000ms max)</span>
              <span className="text-emerald-700 font-bold">5000ms</span>
            </div>
          </div>
        </div>

        {/* Card 2: Risk Scoring Weights Engine */}
        <div className="bg-white border border-[#E2E5E1] rounded-2xl p-6 shadow-sm space-y-4">
          <div className="flex items-center gap-2">
            <Sliders className="w-5 h-5 text-[#426B57]" />
            <h3 className="text-sm font-bold text-[#202522]">Unified Risk Scoring Dimensional Weights</h3>
          </div>
          <p className="text-xs text-[#555C57]">
            The unified risk score (0 to 100) calibrates four decoupled analytical vectors:
          </p>

          <div className="space-y-3">
            <div>
              <div className="flex justify-between text-xs font-semibold mb-1">
                <span>Intelligent Phishing & Homoglyph Indicators</span>
                <span className="font-mono text-[#426B57]">35%</span>
              </div>
              <div className="w-full h-2 bg-neutral-100 rounded-full overflow-hidden">
                <div className="w-[35%] h-full bg-[#426B57] rounded-full" />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs font-semibold mb-1">
                <span>Collaborative Threat Intelligence Feeds</span>
                <span className="font-mono text-[#426B57]">25%</span>
              </div>
              <div className="w-full h-2 bg-neutral-100 rounded-full overflow-hidden">
                <div className="w-[25%] h-full bg-[#426B57] rounded-full" />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs font-semibold mb-1">
                <span>Website Security & HTTP Header Hardening</span>
                <span className="font-mono text-[#426B57]">20%</span>
              </div>
              <div className="w-full h-2 bg-neutral-100 rounded-full overflow-hidden">
                <div className="w-[20%] h-full bg-[#426B57] rounded-full" />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs font-semibold mb-1">
                <span>SSL/TLS Certificate Trust & Cryptography</span>
                <span className="font-mono text-[#426B57]">20%</span>
              </div>
              <div className="w-full h-2 bg-neutral-100 rounded-full overflow-hidden">
                <div className="w-[20%] h-full bg-[#426B57] rounded-full" />
              </div>
            </div>
          </div>
        </div>

        {/* Card 3: AI Intelligence Stack */}
        <div className="bg-white border border-[#E2E5E1] rounded-2xl p-6 shadow-sm space-y-3">
          <div className="flex items-center gap-2">
            <Cpu className="w-5 h-5 text-[#202522]" />
            <h3 className="text-sm font-bold text-[#202522]">AI Threat Reasoning Engine</h3>
          </div>
          <p className="text-xs text-[#555C57]">
            Powered by <strong>Gemini 3.8 Flash</strong> via the modern <code>@google/genai</code> SDK. Synthesizes lexical anomalies, psychological manipulation tactics, and maps adversarial methods to the MITRE ATT&CK framework.
          </p>
          <div className="p-3 bg-[#F7F7F4] border border-[#E2E5E1] rounded-xl text-xs font-mono space-y-1">
            <div className="flex justify-between">
              <span className="text-[#747C78]">Model Name:</span>
              <span className="text-[#202522] font-bold">gemini-3.8-flash</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#747C78]">SDK Version:</span>
              <span className="text-[#202522] font-bold">@google/genai 2.x</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#747C78]">API Execution Mode:</span>
              <span className="text-emerald-700 font-bold">Server-Side Proxy Route</span>
            </div>
          </div>
        </div>

        {/* Card 4: Threat Intelligence Sources */}
        <div className="bg-white border border-[#E2E5E1] rounded-2xl p-6 shadow-sm space-y-3">
          <div className="flex items-center gap-2">
            <Server className="w-5 h-5 text-[#202522]" />
            <h3 className="text-sm font-bold text-[#202522]">External Feed Connectors</h3>
          </div>
          <div className="space-y-2 text-xs">
            <div className="p-2.5 bg-[#F7F7F4] rounded-lg border border-[#E2E5E1] flex items-center justify-between">
              <span className="font-semibold text-[#202522]">Sentinel Community Threat Exchange</span>
              <span className="text-emerald-700 font-mono text-[11px] font-bold">Connected (Real-time)</span>
            </div>
            <div className="p-2.5 bg-[#F7F7F4] rounded-lg border border-[#E2E5E1] flex items-center justify-between">
              <span className="font-semibold text-[#202522]">URLhaus Malware URLs Feed</span>
              <span className="text-emerald-700 font-mono text-[11px] font-bold">Integrated</span>
            </div>
            <div className="p-2.5 bg-[#F7F7F4] rounded-lg border border-[#E2E5E1] flex items-center justify-between">
              <span className="font-semibold text-[#202522]">Certificate Transparency Logs</span>
              <span className="text-emerald-700 font-mono text-[11px] font-bold">Monitored</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
