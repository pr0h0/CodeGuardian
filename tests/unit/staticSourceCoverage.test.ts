import { describe, expect, it } from "vitest";
import { auditResponseJsonSchemaForClasses } from "../../src/ai/schemas.js";
import { loadProjectConfig } from "../../src/config/projectConfig.js";
import { detectRoutes } from "../../src/repo/routeDetector.js";
import type { IndexedFile } from "../../src/repo/repoIndexer.js";
import { runSourcePatternChecks } from "../../src/scanners/sourcePatterns.js";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

function file(pathName: string, content: string): IndexedFile {
  return {
    path: pathName,
    absolutePath: `/repo/${pathName}`,
    language: path.extname(pathName).slice(1) || "typescript",
    content,
    lineCount: content.split(/\r?\n/).length
  };
}

describe("static source coverage expansion", () => {
  it("accepts broader vulnerability class steering for static audit", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-static-classes-"));
    fs.writeFileSync(path.join(dir, ".codeguardian.yml"), [
      "vulnerabilityClasses:",
      "  - exposure",
      "  - validation",
      "  - dependency",
      "  - crypto",
      "  - misconfig",
      "  - xxe",
      "  - business-logic"
    ].join("\n"));

    expect(loadProjectConfig(dir).vulnerabilityClasses).toEqual([
      "exposure",
      "validation",
      "dependency",
      "crypto",
      "misconfig",
      "xxe",
      "business-logic"
    ]);
  });

  it("builds class-scoped schemas for XXE and business-logic audits", () => {
    const xxe = auditResponseJsonSchemaForClasses(["xxe"]);
    const business = auditResponseJsonSchemaForClasses(["business-logic"]);

    expect((((xxe.schema.properties as any).findings.items.properties.category.enum) ?? [])).toEqual(["xxe"]);
    expect((((business.schema.properties as any).findings.items.properties.category.enum) ?? [])).toContain("business-logic");
  });

  it("detects Express app.use/app.all route entrypoints for static route review", () => {
    const routes = detectRoutes("src/server.ts", [
      "app.use('/admin', adminRouter);",
      "router.all('/internal/:id', handler);"
    ].join("\n"));

    expect(routes.map((route) => `${route.method} ${route.routePath}`)).toEqual(["USE /admin", "ALL /internal/:id"]);
  });

  it("emits high-signal source-pattern seeds for XXE, Zip Slip, NoSQL injection, and sensitive unauthenticated routes", () => {
    const results = runSourcePatternChecks([
      file("routes/fileUpload.ts", [
        "const data = file.buffer.toString();",
        "const doc = libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true });",
        "stream.pipe(unzipper.Parse()).on('entry', (entry) => {",
        "  const fileName = entry.path;",
        "  entry.pipe(fs.createWriteStream('uploads/' + fileName));",
        "});"
      ].join("\n")),
      file("routes/reviews.ts", [
        "export function show(req, res) {",
        "  const id = req.params.id;",
        "  db.reviewsCollection.find({ $where: 'this.product == ' + id });",
        "}"
      ].join("\n")),
      file("server.ts", [
        "app.get('/rest/admin/application-version', retrieveAppVersion);",
        "app.post('/rest/user/reset-password', resetPassword);"
      ].join("\n"))
    ]);

    expect(results.map((result) => result.ruleId)).toEqual(expect.arrayContaining([
      "source-xxe-unsafe-parser",
      "source-zip-slip-entry-path",
      "source-nosql-where-concat",
      "source-sensitive-route-without-guard"
    ]));
  });

  it("flags request-controlled object identifiers without a visible ownership check", () => {
    const results = runSourcePatternChecks([
      file("routes/orders.ts", [
        "router.post('/orders/:id/refund', async (req, res) => {",
        "  const orderId = req.params.id;",
        "  const order = await Order.findOne({ where: { id: orderId, userId: req.body.userId } });",
        "  await order.refund();",
        "});"
      ].join("\n"))
    ]);

    expect(results.map((result) => result.ruleId)).toContain("source-request-controlled-object-id");
  });

  it("does not flag request-controlled identifiers when server-side user ownership is checked", () => {
    const results = runSourcePatternChecks([
      file("routes/orders.ts", [
        "router.post('/orders/:id/refund', requireAuth, async (req, res) => {",
        "  if (req.params.userId !== req.user.id) return res.sendStatus(403);",
        "  const order = await Order.findOne({ where: { id: req.params.id, userId: req.user.id } });",
        "  await order.refund();",
        "});"
      ].join("\n"))
    ]);

    expect(results.map((result) => result.ruleId)).not.toContain("source-request-controlled-object-id");
  });

  it("keeps open redirect and archive extraction source patterns tied to unsafe data flow", () => {
    const results = runSourcePatternChecks([
      file("routes/redirect.ts", [
        "router.get('/done', (req, res) => {",
        "  res.redirect('/dashboard');",
        "});",
        "router.get('/next', (req, res) => {",
        "  const next = req.query.next;",
        "  res.redirect(next);",
        "});"
      ].join("\n")),
      file("routes/archive.ts", [
        "stream.pipe(unzipper.Parse()).on('entry', (entry) => {",
        "  const target = path.resolve(uploadDir, entry.path);",
        "  if (!target.startsWith(uploadDir)) throw new Error('bad path');",
        "  entry.pipe(fs.createWriteStream(target));",
        "});"
      ].join("\n"))
    ]);

    expect(results.filter((result) => result.ruleId === "source-open-redirect-variable")).toHaveLength(1);
    expect(results.map((result) => result.ruleId)).not.toContain("source-zip-slip-entry-path");
  });

  it("skips reusable examples and generated bundles for source-pattern seeds", () => {
    const results = runSourcePatternChecks([
      file("data/static/codefixes/example.ts", "res.redirect(req.query.next);"),
      file("dist/bundle.min.js", "fetch(req.query.url)")
    ]);

    expect(results).toHaveLength(0);
  });

  it("flags weak login/session lifecycle controls from Shannon-style auth review", () => {
    const results = runSourcePatternChecks([
      file("backend/controllers/AdminController.js", [
        "class AdminController {",
        "  static async loginPost(req, res) {",
        "    const user = await AdminService.findOne({ where: { username: req.body.username } });",
        "    if (!user) return res.render('login', { message: { content: 'User not found' } });",
        "    const valid = await AdminService.comparePassword(req.body.password, user.password);",
        "    if (!valid) return res.render('login', { message: { content: 'Invalid password' } });",
        "    req.session.user = user;",
        "    req.session.save();",
        "  }",
        "  static async logout(req, res) {",
        "    req.session.destroy();",
        "    res.redirect('/login');",
        "  }",
        "}"
      ].join("\n")),
      file("backend/routers/AdminRouter.js", [
        "this.addRoute('post', '/login', AdminController.loginPost);",
        "this.addRoute('get', '/logout', adminGuard, AdminController.logout);"
      ].join("\n")),
      file("backend/routers/BaseRouter.js", [
        "addRoute(method, route, ...handlers) {",
        "  // TODO: Ignore limiter for now beacuse all requests are coming from the same IP",
        "  // if (this.limiter) handlers.unshift(this.limiter);",
        "  this.router[method](route, ...handlers);",
        "}"
      ].join("\n"))
    ]);

    expect(results.map((result) => result.ruleId)).toEqual(expect.arrayContaining([
      "source-session-regenerate-missing",
      "source-login-distinct-failure-messages",
      "source-state-changing-get-logout",
      "source-rate-limiter-disabled"
    ]));
  });

  it("flags request-controlled SSRF and proxy path traversal patterns", () => {
    const results = runSourcePatternChecks([
      file("backend/controllers/ScraperController.js", [
        "static async postImage(req, res) {",
        "  const url = req.body.url;",
        "  const data = await ScraperService.getImage(url);",
        "  return res.jsonSuccess({ data });",
        "}"
      ].join("\n")),
      file("backend/services/HttpService.js", [
        "static async get(url, config = {}) {",
        "  const response = await instance.get(url, config);",
        "  return response.data;",
        "}"
      ].join("\n")),
      file("frontend/app/slike/[id]/route.ts", [
        "export const GET = async (request: NextRequest) => {",
        "  const imgPath = request.nextUrl.pathname;",
        "  const url = smrtovnicaService.prepareUrl(imgPath);",
        "  const response = await fetch(url);",
        "  return new NextResponse(response.body);",
        "};"
      ].join("\n")),
      file("frontend/app/services/HttpService.ts", [
        "class HttpService {",
        "  public prepareUrl(url: string): string {",
        "    return `${API_SCHEME}://${[API_URL, url].join('/').replace(/[//]+/gi, '/')}`;",
        "  }",
        "}"
      ].join("\n"))
    ]);

    expect(results.map((result) => result.ruleId)).toEqual(expect.arrayContaining([
      "source-request-url-to-service-fetch",
      "source-ssrf-wrapper-unvalidated-url",
      "source-next-path-proxy-fetch",
      "source-url-join-collapse-normalization"
    ]));
  });
});
