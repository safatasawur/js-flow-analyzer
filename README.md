# JS Info Flow

An exploratory JavaScript static information-flow analyzer built with Node.js and Acorn.

## Overview

This project explores how potentially sensitive data can be tracked through JavaScript programs and how unsafe data flows can be identified using static analysis.

The analyzer parses JavaScript into an Abstract Syntax Tree (AST) and applies simplified taint tracking to detect potential flows from configured sources to configured sinks.

## Features

- AST-based JavaScript parsing using Acorn.
- Configurable sensitive-data sources and sinks.
- Taint propagation through variable assignments.
- Basic tracking through selected function calls and return values.
- Manually constructed test cases covering positive and negative examples.

## Getting Started

**Requirements:** Node.js

Install dependencies:

```bash
npm install
```

Run the analyzer:

```bash
node analyzer.js
```

The current prototype analyzes the example program configured in `analyzer.js`.

## Evaluation

The prototype was evaluated using manually constructed test cases covering direct data flows, intermediate variables, helper functions, and constant return values.

See [`test-cases.md`](test-cases.md) for the test cases and evaluation details.

## Limitations

This is an exploratory prototype, not a production-ready security tool. It does not fully model JavaScript semantics, complex control flow, asynchronous behavior, or arbitrary unknown functions. A missing finding does not guarantee that a program is secure.

## Technologies

JavaScript · Node.js · Acorn · ASTs · Static Analysis · Taint Tracking
