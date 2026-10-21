module.exports = [{
  files: ["lib/keycloak/**/*.js", "lib/auth/*.js", "lib/middleware/jwtAuthenticator.js", "test/keycloak/**/*.js", "scripts/**/*.js", "index.js"],
  languageOptions: {ecmaVersion: 2022, sourceType: "commonjs", globals: {
    process: "readonly", Buffer: "readonly", URL: "readonly", URLSearchParams: "readonly",
    fetch: "readonly", AbortSignal: "readonly", console: "readonly", __dirname: "readonly"
  }},
  rules: {"no-undef": "error", "no-unused-vars": ["error", {argsIgnorePattern: "^_"}],
    "no-unreachable": "error", "no-constant-condition": "error", "eqeqeq": "error"}
}];
