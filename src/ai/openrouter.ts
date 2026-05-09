import { OpenAiCompatibleProvider } from "./openaiCompatible.js";

export class OpenRouterProvider extends OpenAiCompatibleProvider {
  constructor(apiKey: string, model: string, baseURL: string) {
    super("openrouter", apiKey, model, baseURL);
  }
}
