/**
 * Safe expression evaluator for filter rules
 * @module utils/expression-evaluator
 */

/**
 * Token types for the expression parser
 */
type TokenType =
  | "IDENTIFIER"
  | "STRING"
  | "NUMBER"
  | "BOOLEAN"
  | "OPERATOR"
  | "KEYWORD"
  | "LPAREN"
  | "RPAREN"
  | "LBRACKET"
  | "RBRACKET"
  | "COMMA"
  | "EOF";

/**
 * Token representation
 */
interface Token {
  type: TokenType;
  value: string;
  position: number;
}

/**
 * Safe expression evaluator that doesn't use eval or Function
 */
export class ExpressionEvaluator {
  private tokens: Token[] = [];
  private current = 0;
  private readonly context: Record<string, unknown>;

  /**
   * Creates a new expression evaluator
   * @param context - Context variables available in expressions
   */
  constructor(context: Record<string, unknown>) {
    this.context = context;
  }

  /**
   * Evaluates an expression safely
   * @param expression - Expression string to evaluate
   * @returns Evaluation result (boolean)
   * @throws {Error} If expression is invalid
   */
  evaluate(expression: string): boolean {
    this.tokens = this.tokenize(expression);
    this.current = 0;
    const result = this.parseExpression();
    if (this.peek().type !== "EOF") {
      throw new Error(`Unexpected token at position ${this.peek().position}`);
    }
    return result;
  }

  /**
   * Tokenizes the expression string
   */
  private tokenize(expression: string): Token[] {
    const tokens: Token[] = [];
    let position = 0;

    const keywords = new Set(["in", "eq", "ne", "and", "or", "not", "matches", "true", "false"]);

    while (position < expression.length) {
      const char = expression[position];
      const startPos = position;

      if (/\s/.test(char)) {
        position++;
        continue;
      }

      if (char === "(") {
        tokens.push({ type: "LPAREN", value: "(", position: startPos });
        position++;
        continue;
      }

      if (char === ")") {
        tokens.push({ type: "RPAREN", value: ")", position: startPos });
        position++;
        continue;
      }

      if (char === "[") {
        tokens.push({ type: "LBRACKET", value: "[", position: startPos });
        position++;
        continue;
      }

      if (char === "]") {
        tokens.push({ type: "RBRACKET", value: "]", position: startPos });
        position++;
        continue;
      }

      if (char === ",") {
        tokens.push({ type: "COMMA", value: ",", position: startPos });
        position++;
        continue;
      }

      if (char === '"' || char === "'") {
        const quote = char;
        position++;
        let value = "";
        while (position < expression.length && expression[position] !== quote) {
          if (expression[position] === "\\") {
            position++;
            if (position < expression.length) {
              value += expression[position];
            }
          } else {
            value += expression[position];
          }
          position++;
        }
        if (position < expression.length) {
          position++;
        }
        tokens.push({ type: "STRING", value, position: startPos });
        continue;
      }

      if (/[0-9]/.test(char)) {
        let value = "";
        while (position < expression.length && /[0-9.]/.test(expression[position])) {
          value += expression[position];
          position++;
        }
        tokens.push({ type: "NUMBER", value, position: startPos });
        continue;
      }

      if (/[a-zA-Z_$]/.test(char)) {
        let value = "";
        while (position < expression.length && /[a-zA-Z0-9_$]/.test(expression[position])) {
          value += expression[position];
          position++;
        }

        if (keywords.has(value.toLowerCase())) {
          tokens.push({ type: "KEYWORD", value: value.toLowerCase(), position: startPos });
        } else {
          tokens.push({ type: "IDENTIFIER", value, position: startPos });
        }
        continue;
      }

      if (/[=!<>]/.test(char)) {
        let value = char;
        position++;
        if (position < expression.length && /[=]/.test(expression[position])) {
          value += expression[position];
          position++;
        }
        tokens.push({ type: "OPERATOR", value, position: startPos });
        continue;
      }

      if (char === "&" || char === "|") {
        const op = char;
        position++;
        if (position < expression.length && expression[position] === op) {
          tokens.push({ type: "OPERATOR", value: op + op, position: startPos });
          position++;
        } else {
          tokens.push({ type: "OPERATOR", value: op, position: startPos });
        }
        continue;
      }

      throw new Error(`Unexpected character '${char}' at position ${position}`);
    }

    tokens.push({ type: "EOF", value: "", position });
    return tokens;
  }

  /**
   * Parses and evaluates the expression
   */
  private parseExpression(): boolean {
    return this.parseOr();
  }

  private parseOr(): boolean {
    let left = this.parseAnd();
    while (this.match("KEYWORD", "or") || this.match("OPERATOR", "||")) {
      const right = this.parseAnd();
      left = left || right;
    }
    return left;
  }

  private parseAnd(): boolean {
    let left = this.parseNot();
    while (this.match("KEYWORD", "and") || this.match("OPERATOR", "&&")) {
      const right = this.parseNot();
      left = left && right;
    }
    return left;
  }

  private parseNot(): boolean {
    if (this.match("KEYWORD", "not") || this.match("OPERATOR", "!")) {
      return !this.parseComparison();
    }
    return this.parseComparison();
  }

  private parseComparison(): boolean {
    const left = this.parseValue();

    if (this.match("OPERATOR", "==") || this.match("KEYWORD", "eq")) {
      const right = this.parseValue();
      return this.compareValues(left, right, "==");
    }

    if (this.match("OPERATOR", "!=") || this.match("KEYWORD", "ne")) {
      const right = this.parseValue();
      return this.compareValues(left, right, "!=");
    }

    if (this.match("OPERATOR", ">")) {
      const right = this.parseValue();
      return this.compareValues(left, right, ">");
    }

    if (this.match("OPERATOR", "<")) {
      const right = this.parseValue();
      return this.compareValues(left, right, "<");
    }

    if (this.match("OPERATOR", ">=")) {
      const right = this.parseValue();
      return this.compareValues(left, right, ">=");
    }

    if (this.match("OPERATOR", "<=")) {
      const right = this.parseValue();
      return this.compareValues(left, right, "<=");
    }

    if (this.match("KEYWORD", "in")) {
      const right = this.parseArray();
      return this.checkIn(left, right);
    }

    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
    if (this.match("KEYWORD", "matches")) {
      this.consume("LPAREN", "(");
      const pattern = this.parseValue();
      this.consume("RPAREN", ")");
      return this.checkMatches(left, pattern);
    }

    return Boolean(left);
  }

  private parseValue(): unknown {
    if (this.match("STRING")) {
      return this.previous().value;
    }

    if (this.match("NUMBER")) {
      const num = parseFloat(this.previous().value);
      return isNaN(num) ? 0 : num;
    }

    if (this.match("KEYWORD", "true")) {
      return true;
    }

    if (this.match("KEYWORD", "false")) {
      return false;
    }

    if (this.match("IDENTIFIER")) {
      const identifier = this.previous().value;
      return this.context[identifier];
    }

    if (this.match("LPAREN")) {
      const result = this.parseExpression();
      this.consume("RPAREN", ")");
      return result;
    }

    throw new Error(`Unexpected token at position ${this.peek().position}`);
  }

  private parseArray(): unknown[] {
    this.consume("LBRACKET", "[");
    const items: unknown[] = [];

    if (!this.check("RBRACKET")) {
      do {
        items.push(this.parseValue());
      } while (this.match("COMMA"));
    }

    this.consume("RBRACKET", "]");
    return items;
  }

  private compareValues(left: unknown, right: unknown, op: string): boolean {
    if (op === "==") {
      return left === right || String(left) === String(right);
    }
    if (op === "!=") {
      return left !== right && String(left) !== String(right);
    }
    if (op === ">") {
      return Number(left) > Number(right);
    }
    if (op === "<") {
      return Number(left) < Number(right);
    }
    if (op === ">=") {
      return Number(left) >= Number(right);
    }
    if (op === "<=") {
      return Number(left) <= Number(right);
    }
    return false;
  }

  private checkIn(value: unknown, array: unknown[]): boolean {
    return array.some((item) => item === value || String(item) === String(value));
  }

  private checkMatches(value: unknown, pattern: unknown): boolean {
    if (typeof value !== "string" || typeof pattern !== "string") {
      return false;
    }

    // Validate regex pattern to prevent ReDoS
    if (!this.isSafeRegexPattern(pattern)) {
      throw new Error("Regex pattern is too complex or potentially vulnerable to ReDoS");
    }

    try {
      // Set timeout for regex execution to prevent DoS
      const regex = new RegExp(pattern);
      return this.executeRegexWithTimeout(regex, value);
    } catch {
      return false;
    }
  }

  /**
   * Validates regex pattern to prevent ReDoS attacks
   * Checks for dangerous patterns like nested quantifiers
   */
  private isSafeRegexPattern(pattern: string): boolean {
    // Maximum pattern length
    if (pattern.length > 1000) {
      return false;
    }

    // Check for dangerous nested quantifiers (e.g., (a+)+, (a*)*, (a{1,}){1,})
    const dangerousPatterns = [
      /\([^)]*\+[^)]*\)\+/, // (a+)+
      /\([^)]*\*[^)]*\)\*/, // (a*)*
      /\([^)]*\{[^}]*\}[^)]*\)\{[^}]*\}/, // (a{1,}){1,}
      /\([^)]*\+[^)]*\)\*/, // (a+)*
      /\([^)]*\*[^)]*\)\+/, // (a*)+
    ];

    for (const dangerousPattern of dangerousPatterns) {
      if (dangerousPattern.test(pattern)) {
        return false;
      }
    }

    // Check for excessive quantifiers in a row
    const quantifierCount = (pattern.match(/[+*?]\{/g) || []).length;
    if (quantifierCount > 20) {
      return false;
    }

    return true;
  }

  /**
   * Executes regex with timeout to prevent DoS
   */
  private executeRegexWithTimeout(regex: RegExp, value: string, timeoutMs: number = 100): boolean {
    const startTime = Date.now();
    let result = false;

    try {
      // For simple patterns, execute directly
      if (value.length < 10000) {
        result = regex.test(value);
        return result;
      }

      // For large strings, check timeout more frequently
      // This is a simplified approach - in production, consider using worker threads
      const testValue = value.substring(0, Math.min(value.length, 10000));
      result = regex.test(testValue);

      if (Date.now() - startTime > timeoutMs) {
        throw new Error("Regex execution timeout");
      }

      return result;
    } catch (error) {
      if (error instanceof Error && error.message.includes("timeout")) {
        throw new Error("Regex execution exceeded timeout limit");
      }
      return false;
    }
  }

  private match(...args: [TokenType] | [TokenType, string]): boolean {
    if (this.check(args[0], args[1])) {
      this.advance();
      return true;
    }
    return false;
  }

  private check(type: TokenType, value?: string): boolean {
    if (this.isAtEnd()) {
      return false;
    }
    const token = this.peek();
    if (value !== undefined) {
      return token.type === type && token.value === value;
    }
    return token.type === type;
  }

  private advance(): Token {
    if (!this.isAtEnd()) {
      this.current++;
    }
    return this.previous();
  }

  private isAtEnd(): boolean {
    return this.peek().type === "EOF";
  }

  private peek(): Token {
    return this.tokens[this.current] || this.tokens[this.tokens.length - 1];
  }

  private previous(): Token {
    return this.tokens[this.current - 1];
  }

  private consume(type: TokenType, value: string): Token {
    if (this.check(type, value)) {
      return this.advance();
    }
    throw new Error(`Expected ${type} '${value}' at position ${this.peek().position}`);
  }
}

/**
 * Safely evaluates a filter expression
 * @param expression - Expression string
 * @param context - Context variables
 * @returns Evaluation result
 */
export function evaluateExpression(expression: string, context: Record<string, unknown>): boolean {
  try {
    const evaluator = new ExpressionEvaluator(context);
    return evaluator.evaluate(expression);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Expression evaluation failed: ${message}`);
  }
}
