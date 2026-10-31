# VELTRIX Steering: Coding Standards
**Category:** Code Quality & TypeScript Standards  
**Scope:** Frontend, Backend, Infrastructure, and Test suites  

## 1. Core Principles
- **Strict TypeScript:** All code must pass strict type checking (`strict: true`, `noImplicitAny: true`, `strictNullChecks: true`).
- **No `any` Types:** Use explicit domain types, generics, or `unknown` with runtime type guards (e.g. Zod schemas).
- **Functional & Modular:** Favor pure functions, modular composition, and single-responsibility modules over monolithic classes or gigantic functions.
- **Explicit Return Types:** All public API handlers, domain services, and utility functions must specify explicit return types.

## 2. Formatting & Linting
- **Indentation:** 2 spaces.
- **Quotes:** Single quotes `'` for TypeScript/JavaScript code, double quotes `"` for JSON and JSX attributes.
- **Semicolons:** Always use semicolons.
- **Line Length:** 100 characters maximum where practical.
- **Naming Conventions:**
  - Files & Directories: `kebab-case.ts` or `PascalCase.tsx` for React components.
  - Interfaces & Types: `PascalCase` (e.g., `SecurityEvent`, `IncidentDossier`).
  - Functions & Variables: `camelCase`.
  - Constants & Enums: `UPPER_SNAKE_CASE` (e.g., `DEFAULT_TIME_WINDOW_SECONDS`).

## 3. Error Handling
- Never swallow errors silently. Catch blocks must log structured diagnostic information and return standard error responses.
- Use standardized custom error types (`ValidationError`, `NotFoundError`, `UnauthorizedError`, `ConflictError`).
