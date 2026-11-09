import { GoogleGenAI, Type } from '@google/genai';
import { AiThreatAssessment, Finding, PhishingAnalysis, TlsCertificateAnalysis } from './types';

export async function analyzeThreatWithGemini(
  targetUrl: string,
  domain: string,
  phishing: PhishingAnalysis,
  tlsCert: TlsCertificateAnalysis,
  findings: Finding[],
  riskScore: number,
): Promise<AiThreatAssessment | undefined> {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return undefined;

  try {
    const ai = new GoogleGenAI({
      apiKey,
      httpOptions: { headers: { 'User-Agent': 'aistudio-build' } },
    });
    const promptContext = `
Analyze this cybersecurity target evaluated by the Sentinel Web Trust Platform:
Submitted URL: ${targetUrl}
Canonical hostname: ${domain}
Calculated risk score: ${riskScore}/100
Phishing probability from URL/content heuristics: ${Math.round(phishing.probability * 100)}%
Homoglyphs detected: ${JSON.stringify(phishing.homoglyphsDetected)}
Suspicious URL keywords: ${phishing.suspiciousKeywords.join(', ') || 'None'}
TLS certificate retrieved: ${Boolean(tlsCert.validFrom)}
TLS valid: ${tlsCert.valid}, expired: ${tlsCert.isExpired}, self-signed: ${tlsCert.isSelfSigned}
Observed findings:
${findings.map(f => `- [${f.severity}] ${f.title}: ${f.technicalDetails}`).join('\n')}

Only draw conclusions supported by the evidence above. Clearly state when evidence is insufficient.
`;
    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: promptContext,
      config: {
        systemInstruction: 'You are a cybersecurity analyst. Base every conclusion only on supplied evidence and explicitly disclose uncertainty.',
        responseMimeType: 'application/json',
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            analystSummary: { type: Type.STRING },
            threatActorsOrMotivation: { type: Type.STRING },
            psychologicalTactics: { type: Type.ARRAY, items: { type: Type.STRING } },
            mitreAttackTechniques: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  id: { type: Type.STRING },
                  name: { type: Type.STRING },
                  description: { type: Type.STRING },
                },
                required: ['id', 'name', 'description'],
              },
            },
            userActionGuidance: { type: Type.ARRAY, items: { type: Type.STRING } },
            socRemediationSteps: { type: Type.ARRAY, items: { type: Type.STRING } },
            confidenceLevel: { type: Type.STRING },
          },
          required: [
            'analystSummary',
            'threatActorsOrMotivation',
            'psychologicalTactics',
            'mitreAttackTechniques',
            'userActionGuidance',
            'socRemediationSteps',
            'confidenceLevel',
          ],
        },
      },
    });

    const result = JSON.parse(response.text || '') as AiThreatAssessment;
    if (
      typeof result.analystSummary !== 'string' ||
      typeof result.threatActorsOrMotivation !== 'string' ||
      !Array.isArray(result.psychologicalTactics) ||
      !Array.isArray(result.mitreAttackTechniques) ||
      !Array.isArray(result.userActionGuidance) ||
      !Array.isArray(result.socRemediationSteps) ||
      !['VERY_HIGH', 'HIGH', 'MODERATE', 'LOW'].includes(result.confidenceLevel)
    ) {
      throw new Error('Gemini returned an incomplete threat assessment.');
    }
    return result;
  } catch (error) {
    console.error('Gemini analysis failed:', error);
    return undefined;
  }
}
