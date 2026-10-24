
import * as acorn from "acorn";

// 1. Configure sources and sinks.
const SOURCES = new Set([
    "getSensitiveData",
    "readPassword",
    "getUserToken"
]);

const SINKS = new Set([
    "console.log",
    "sendToServer"
]);

// 2. Test program.
const code = `
function formatMessage(value) {
    return "Hello, world!";
}
const secret = readPassword();
const message = formatMessage(secret);
console.log(message);
`;

// 3. Parse the program into an AST.
const ast = acorn.parse(code, {
    ecmaVersion: "latest",
    sourceType: "module",
    locations: true
});

const taintedVariables = new Set();
const findings = [];
const functions = new Map();
const reportedFindings = new Set();

// Get names such as "sendToServer" and "console.log".
function getCalleeName(node) {
    if (!node) return null;

    if (node.type === "Identifier") {
        return node.name;
    }

    if (
        node.type === "MemberExpression" &&
        !node.computed
    ) {
        const objectName = getCalleeName(node.object);

        return objectName
            ? `${objectName}.${node.property.name}`
            : null;
    }

    return null;
}

// Get the direct AST child nodes.
function getChildNodes(node) {
    const children = [];

    for (const value of Object.values(node)) {
        if (Array.isArray(value)) {
            for (const item of value) {
                if (item && typeof item.type === "string") {
                    children.push(item);
                }
            }
        } else if (
            value &&
            typeof value.type === "string"
        ) {
            children.push(value);
        }
    }

    return children;
}

// Visit nodes in an AST subtree.
function walk(node, callback) {
    if (!node || typeof node.type !== "string") return;

    callback(node);

    for (const child of getChildNodes(node)) {
        walk(child, callback);
    }
}

// Record each destination and line only once.
function reportFinding(destination, line) {
    const key = `${destination}:${line}`;

    if (reportedFindings.has(key)) return;

    reportedFindings.add(key);
    findings.push({ destination, line });
}

// 4. Determine whether an expression carries sensitive data.
function containsTaintedData(
    node,
    localTainted = new Set(),
    callStack = new Set()
) {
    if (!node) return false;

    if (node.type === "Identifier") {
        return (
            localTainted.has(node.name) ||
            taintedVariables.has(node.name)
        );
    }

    if (node.type === "CallExpression") {
        const name = getCalleeName(node.callee);

        if (SOURCES.has(name)) {
            return true;
        }

        if (functions.has(name) && !callStack.has(name)) {
            return analyzeFunctionCall(
                node,
                callStack,
                localTainted
            );
        }

        // Unknown function return values are not assumed
        // to contain sensitive data.
        return false;
    }

    // Handle expressions such as value + "text".
    return getChildNodes(node).some(child =>
        containsTaintedData(
            child,
            localTainted,
            callStack
        )
    );
}

// 5. Analyze a function call using its actual arguments.
function analyzeFunctionCall(
    call,
    callStack = new Set(),
    callerLocalTainted = new Set()
) {
    const name = getCalleeName(call.callee);
    const fn = functions.get(name);

    if (!fn || callStack.has(name)) {
        return false;
    }

    const localTainted = new Set();

    // Transfer sensitive arguments to parameters.
    for (let i = 0; i < fn.params.length; i++) {
        const parameter = fn.params[i];
        const argument = call.arguments[i];

        if (
            parameter.type === "Identifier" &&
            containsTaintedData(
                argument,
                callerLocalTainted,
                callStack
            )
        ) {
            localTainted.add(parameter.name);
        }
    }

    const nextCallStack = new Set(callStack);
    nextCallStack.add(name);

    // Process statements in order, updating local taint
    // before inspecting sinks in each statement.
    for (const statement of fn.body.body) {

        // Handle declarations such as: const copy = value;
        if (statement.type === "VariableDeclaration") {
            for (const declaration of statement.declarations) {
                if (declaration.id.type !== "Identifier") {
                    continue;
                }

                const variableName = declaration.id.name;

                if (
                    containsTaintedData(
                        declaration.init,
                        localTainted,
                        nextCallStack
                    )
                ) {
                    localTainted.add(variableName);
                } else {
                    localTainted.delete(variableName);
                }
            }
        }

        // Inspect calls in this statement using the
        // current local taint state.
        walk(statement, innerNode => {
            if (innerNode.type !== "CallExpression") {
                return;
            }

            const destination = getCalleeName(
                innerNode.callee
            );

            if (!SINKS.has(destination)) return;

            for (const argument of innerNode.arguments) {
                if (
                    containsTaintedData(
                        argument,
                        localTainted,
                        nextCallStack
                    )
                ) {
                    reportFinding(
                        destination,
                        innerNode.loc.start.line
                    );
                    break;
                }
            }
        });

        // Propagate sensitive return values to callers.
        if (statement.type === "ReturnStatement") {
            return containsTaintedData(
                statement.argument,
                localTainted,
                nextCallStack
            );
        }
    }

    return false;
}

// 6. Register function declarations before analysis.
for (const statement of ast.body) {
    if (
        statement.type === "FunctionDeclaration" &&
        statement.id
    ) {
        functions.set(statement.id.name, statement);
    }
}

// 7. Analyze top-level statements in order.
for (const statement of ast.body) {

    // Track top-level variables.
    if (statement.type === "VariableDeclaration") {
        for (const declaration of statement.declarations) {
            if (declaration.id.type !== "Identifier") {
                continue;
            }

            const variableName = declaration.id.name;

            if (containsTaintedData(declaration.init)) {
                taintedVariables.add(variableName);
            } else {
                taintedVariables.delete(variableName);
            }
        }
    }

    // Find configured sinks at the top level.
    // Skip function declarations here: their bodies
    // are analyzed using call-site parameter values.
    if (statement.type !== "FunctionDeclaration") {
        walk(statement, node => {
            if (node.type !== "CallExpression") return;

            const destination = getCalleeName(node.callee);

            if (!SINKS.has(destination)) return;

            for (const argument of node.arguments) {
                if (containsTaintedData(argument)) {
                    reportFinding(
                        destination,
                        node.loc.start.line
                    );
                    break;
                }
            }
        });
    }

    // Analyze known function calls to inspect their bodies.
    walk(statement, node => {
        if (node.type !== "CallExpression") return;

        const name = getCalleeName(node.callee);

        if (functions.has(name)) {
            analyzeFunctionCall(node, new Set());
        }
    });
}

// 8. Print the results.
console.log(
    "Sensitive variables:",
    [...taintedVariables]
);

console.log("Findings:", findings);
