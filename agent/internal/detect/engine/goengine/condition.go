package goengine

import (
	"fmt"
	"strings"
)

// ConditionContext used during evaluation.
type ConditionContext struct {
	StringIDs    []string
	Matches      map[string]PatternMatch
	Placeholders map[string]bool
}

// Node describes boolean expression for rule condition.
type Node interface {
	Eval(ctx *ConditionContext) bool
}

type boolConst struct {
	value bool
}

func (b boolConst) Eval(_ *ConditionContext) bool { return b.value }

type placeholderRef struct {
	name string
}

func (p placeholderRef) Eval(ctx *ConditionContext) bool {
	if ctx.Placeholders == nil {
		return false
	}
	return ctx.Placeholders[p.name]
}

type stringRef struct {
	id string
}

func (s stringRef) Eval(ctx *ConditionContext) bool {
	_, ok := ctx.Matches[s.id]
	return ok
}

type unaryNode struct {
	op string
	x  Node
}

func (u unaryNode) Eval(ctx *ConditionContext) bool {
	switch u.op {
	case "not":
		return !u.x.Eval(ctx)
	default:
		return false
	}
}

type binaryNode struct {
	op          string
	left, right Node
}

func (b binaryNode) Eval(ctx *ConditionContext) bool {
	switch b.op {
	case "and":
		return b.left.Eval(ctx) && b.right.Eval(ctx)
	case "or":
		return b.left.Eval(ctx) || b.right.Eval(ctx)
	default:
		return false
	}
}

type quantifierType int

const (
	quantAny quantifierType = iota + 1
	quantAll
	quantAtLeast
)

type quantifierNode struct {
	kind     quantifierType
	amount   int
	group    []string
	groupRaw []string
}

func (q quantifierNode) Eval(ctx *ConditionContext) bool {
	targetIDs := q.resolveGroup(ctx)
	if len(targetIDs) == 0 {
		return false
	}
	hits := 0
	for _, id := range targetIDs {
		if _, ok := ctx.Matches[id]; ok {
			hits++
		}
	}
	switch q.kind {
	case quantAny:
		return hits > 0
	case quantAll:
		return hits == len(targetIDs)
	case quantAtLeast:
		return hits >= q.amount
	default:
		return false
	}
}

func (q quantifierNode) resolveGroup(ctx *ConditionContext) []string {
	if len(q.group) > 0 {
		return q.group
	}
	results := make([]string, 0)
	for _, raw := range q.groupRaw {
		if raw == "them" {
			results = append(results, ctx.StringIDs...)
			continue
		}
		if strings.Contains(raw, "*") {
			prefix := strings.TrimSuffix(raw, "*")
			for _, id := range ctx.StringIDs {
				if strings.HasPrefix(id, prefix) {
					results = append(results, id)
				}
			}
			continue
		}
		results = append(results, raw)
	}
	return results
}

// Precondition describes header or metadata constraints extracted from condition string.
type Precondition struct {
	Placeholder string
	Eval        func(data []byte) bool
}

// expression parser --------------------------------------------------------

type tokenType int

const (
	tokenEOF tokenType = iota
	tokenIdentifier
	tokenNumber
	tokenOperator
	tokenLParen
	tokenRParen
	tokenComma
	tokenUnknown
)

type token struct {
	typ tokenType
	val string
}

type lexer struct {
	input string
	pos   int
}

func newLexer(input string) *lexer {
	return &lexer{input: input}
}

func (l *lexer) next() token {
	l.skipWhitespace()
	if l.pos >= len(l.input) {
		return token{typ: tokenEOF}
	}
	ch := l.input[l.pos]
	switch ch {
	case '(':
		l.pos++
		return token{typ: tokenLParen, val: "("}
	case ')':
		l.pos++
		return token{typ: tokenRParen, val: ")"}
	case ',':
		l.pos++
		return token{typ: tokenComma, val: ","}
	}
	if isDigit(ch) {
		return l.scanNumber()
	}
	if isIdentifierStart(ch) || ch == '$' || ch == '_' {
		return l.scanIdentifier()
	}
	if ch == '&' || ch == '|' || ch == '!' {
		l.pos++
		return token{typ: tokenOperator, val: string(ch)}
	}
	l.pos++
	return token{typ: tokenUnknown, val: string(ch)}
}

func (l *lexer) skipWhitespace() {
	for l.pos < len(l.input) {
		if l.input[l.pos] == ' ' || l.input[l.pos] == '\t' || l.input[l.pos] == '\n' || l.input[l.pos] == '\r' {
			l.pos++
		} else {
			break
		}
	}
}

func (l *lexer) scanNumber() token {
	start := l.pos
	for l.pos < len(l.input) && isDigit(l.input[l.pos]) {
		l.pos++
	}
	return token{typ: tokenNumber, val: l.input[start:l.pos]}
}

func (l *lexer) scanIdentifier() token {
	start := l.pos
	l.pos++
	for l.pos < len(l.input) && (isIdentifierPart(l.input[l.pos]) || l.input[l.pos] == '.' || l.input[l.pos] == '$' || l.input[l.pos] == '_') {
		l.pos++
	}
	return token{typ: tokenIdentifier, val: l.input[start:l.pos]}
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

func isIdentifierStart(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isIdentifierPart(b byte) bool {
	return isIdentifierStart(b) || isDigit(b)
}

type exprParser struct {
	lex  *lexer
	look token
}

func newConditionParser(input string) *exprParser {
	p := &exprParser{lex: newLexer(input)}
	p.look = p.lex.next()
	return p
}

func (p *exprParser) consume(expected tokenType) (token, error) {
	if p.look.typ != expected {
		return token{}, fmt.Errorf("unexpected token %s", p.look.val)
	}
	current := p.look
	p.look = p.lex.next()
	return current, nil
}

func (p *exprParser) match(expected tokenType) bool {
	return p.look.typ == expected
}

func (p *exprParser) parseExpression() (Node, error) {
	return p.parseOr()
}

func (p *exprParser) parseOr() (Node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.look.val, "or") {
		p.consume(tokenIdentifier)
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = binaryNode{op: "or", left: left, right: right}
	}
	return left, nil
}

func (p *exprParser) parseAnd() (Node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.look.val, "and") {
		p.consume(tokenIdentifier)
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = binaryNode{op: "and", left: left, right: right}
	}
	return left, nil
}

func (p *exprParser) parseUnary() (Node, error) {
	if strings.EqualFold(p.look.val, "not") {
		p.consume(tokenIdentifier)
		node, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return unaryNode{op: "not", x: node}, nil
	}
	return p.parsePrimary()
}

func (p *exprParser) parsePrimary() (Node, error) {
	switch p.look.typ {
	case tokenLParen:
		p.consume(tokenLParen)
		node, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		if _, err := p.consume(tokenRParen); err != nil {
			return nil, err
		}
		return node, nil
	case tokenIdentifier:
		return p.parseIdentifierExpression()
	case tokenNumber:
		return p.parseQuantifierByNumber()
	default:
		return nil, fmt.Errorf("unexpected token %s", p.look.val)
	}
}

func (p *exprParser) parseIdentifierExpression() (Node, error) {
	value := p.look.val
	lower := strings.ToLower(value)
	switch lower {
	case "any", "all":
		return p.parseQuantifier(lower)
	case "true":
		p.consume(tokenIdentifier)
		return boolConst{value: true}, nil
	case "false":
		p.consume(tokenIdentifier)
		return boolConst{value: false}, nil
	}
	if strings.HasPrefix(value, "__pc") {
		p.consume(tokenIdentifier)
		return placeholderRef{name: value}, nil
	}
	if strings.HasPrefix(value, "$") {
		p.consume(tokenIdentifier)
		return stringRef{id: value}, nil
	}
	return nil, fmt.Errorf("unsupported identifier expression %s", value)
}

func (p *exprParser) parseQuantifier(kind string) (Node, error) {
	p.consume(tokenIdentifier) // consume 'any' or 'all'
	if !strings.EqualFold(p.look.val, "of") {
		return nil, fmt.Errorf("expected 'of' after %s", kind)
	}
	p.consume(tokenIdentifier)
	list, err := p.parseGroupList()
	if err != nil {
		return nil, err
	}
	node := quantifierNode{
		groupRaw: list,
	}
	switch kind {
	case "any":
		node.kind = quantAny
	case "all":
		node.kind = quantAll
	}
	return node, nil
}

func (p *exprParser) parseQuantifierByNumber() (Node, error) {
	numTok, _ := p.consume(tokenNumber)
	if !strings.EqualFold(p.look.val, "of") {
		return nil, fmt.Errorf("expected 'of' after number in quantifier")
	}
	p.consume(tokenIdentifier)
	list, err := p.parseGroupList()
	if err != nil {
		return nil, err
	}
	node := quantifierNode{
		kind:     quantAtLeast,
		amount:   atoi(numTok.val),
		groupRaw: list,
	}
	return node, nil
}

func (p *exprParser) parseGroupList() ([]string, error) {
	if strings.EqualFold(p.look.val, "them") {
		p.consume(tokenIdentifier)
		return []string{"them"}, nil
	}
	if p.look.typ != tokenLParen {
		return nil, fmt.Errorf("expected '(' for group list")
	}
	p.consume(tokenLParen)
	list := make([]string, 0)
	for {
		if p.look.typ == tokenRParen {
			break
		}
		if p.look.typ != tokenIdentifier {
			return nil, fmt.Errorf("invalid group element %s", p.look.val)
		}
		val := p.look.val
		p.consume(tokenIdentifier)
		list = append(list, val)
		if p.look.typ == tokenComma {
			p.consume(tokenComma)
			continue
		}
		if p.look.typ == tokenRParen {
			break
		}
	}
	if p.look.typ != tokenRParen {
		return nil, fmt.Errorf("missing ')'")
	}
	p.consume(tokenRParen)
	return list, nil
}

func atoi(str string) int {
	n := 0
	for _, ch := range str {
		if ch >= '0' && ch <= '9' {
			n = n*10 + int(ch-'0')
		} else {
			break
		}
	}
	return n
}
