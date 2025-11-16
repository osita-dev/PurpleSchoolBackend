// promptUtils.js
export function buildPrompt(recent = [], userMessage) {
  const system = `You are an AI learning assistant for secondary school students...
Output MUST be valid JSON (one JSON object). Example:
{"introduction":"...","key_concepts":["..."],"examples":["..."],"applications":["..."],"summary":"..."}
Be concise, polite, age-appropriate.`;

  const fewShot = `### Example
User: What is photosynthesis?
Assistant: {"introduction":"Photosynthesis is the process by which plants convert light into chemical energy.","key_concepts":["chlorophyll","sunlight","carbon dioxide","oxygen","glucose"],"examples":["A leaf turning sunlight into sugar","Algae in sunlight produce oxygen"],"applications":["Agriculture: optimizing crop growth","Ecology: supporting food chains"],"summary":"Photosynthesis converts light energy into sugars and oxygen, fueling life on Earth."}
### End Example`;

  const recentText = recent
    .slice(-12)
    .map(m => `${m.role === 'assistant' ? 'Assistant' : 'User'}: ${m.content}`)
    .join('\n');

  return [system, fewShot, recentText, `User: ${userMessage}`, 'Assistant:'].filter(Boolean).join('\n\n');
}

export function parseModelJson(text) {
  if (!text) return null;
  // direct try
  try { return JSON.parse(text); } catch (e) {}
  // try to extract JSON substring
  const match = text.match(/\{[\s\S]*\}/);
  if (match) {
    try { return JSON.parse(match[0]); } catch (e) {}
  }
  return null;
}
