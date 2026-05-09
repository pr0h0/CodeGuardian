import { OpenAiCompatibleProvider } from "./openaiCompatible.js";

export class DeepSeekProvider extends OpenAiCompatibleProvider {
  constructor(apiKey: string, model: string, baseURL: string) {
    super("deepseek", apiKey, model, baseURL);
  }
}
