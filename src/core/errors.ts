export class CodeguardianError extends Error {
  constructor(message: string, public readonly code = "CODEGUARDIAN_ERROR") {
    super(message);
  }
}
