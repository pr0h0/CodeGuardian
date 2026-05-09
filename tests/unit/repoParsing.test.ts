import { describe, expect, it } from "vitest";
import { extractImports } from "../../src/repo/importGraph.js";
import { detectRoutes } from "../../src/repo/routeDetector.js";
import { extractSymbols } from "../../src/repo/symbolExtractor.js";

describe("repo parsing", () => {
  it("detects PHP and Ruby imports", () => {
    expect(extractImports("require_once 'lib/bootstrap.php';\nuse App\\Http\\Controller;")).toContain("lib/bootstrap.php");
    expect(extractImports("require_relative 'worker'\nrequire 'json'")).toEqual(expect.arrayContaining(["worker", "json"]));
  });

  it("detects Rails, Sinatra, and Laravel routes", () => {
    const routes = [
      ...detectRoutes("/config/routes.rb", "get '/admin', to: 'admin#index'\npost '/login' do\nend"),
      ...detectRoutes("/routes/web.php", "Route::post('/upload', [UploadController::class, 'store']);")
    ];

    expect(routes.some((route) => route.frameworkGuess === "rails" && route.routePath === "/admin")).toBe(true);
    expect(routes.some((route) => route.frameworkGuess === "sinatra" && route.routePath === "/login")).toBe(true);
    expect(routes.some((route) => route.frameworkGuess === "laravel" && route.routePath === "/upload")).toBe(true);
  });

  it("extracts PHP and Ruby symbols", () => {
    const symbols = extractSymbols([
      "namespace App\\Console;",
      "final class ImportCommand {",
      "  public function handle() {}",
      "}",
      "module Jobs",
      "  def self.run!",
      "  end",
      "end"
    ].join("\n"));

    expect(symbols.some((symbol) => symbol.kind === "namespace" && symbol.name === "App\\Console")).toBe(true);
    expect(symbols.some((symbol) => symbol.kind === "class" && symbol.name === "ImportCommand")).toBe(true);
    expect(symbols.some((symbol) => symbol.kind === "function" && symbol.name === "handle")).toBe(true);
    expect(symbols.some((symbol) => symbol.kind === "module" && symbol.name === "Jobs")).toBe(true);
    expect(symbols.some((symbol) => symbol.kind === "function" && symbol.name === "run!")).toBe(true);
  });
});
