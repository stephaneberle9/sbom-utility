// SPDX-License-Identifier: Apache-2.0
/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package schema

import (
	"strings"

)

type CompoundExpression   struct {
	SimpleLeft            string
	LeftPolicy            LicensePolicy
	LeftUsagePolicy       string
	SimpleRight           string
	SimpleRightHasPlus    bool
	RightPolicy           LicensePolicy
	RightUsagePolicy      string
	Conjunction           string
	SubsequentConjunction string
	CompoundLeft          *CompoundExpression
	CompoundRight         *CompoundExpression
	CompoundUsagePolicy   string
}

// Tokens
const (
	LEFT_PARENS                 string = "("
	RIGHT_PARENS                string = ")"
	LEFT_PARENS_WITH_SEPARATOR  string = "( "
	RIGHT_PARENS_WITH_SEPARATOR string = " )"
	PLUS_OPERATOR               string = "+"
)

const (
	MSG_LICENSE_INVALID_EXPRESSION             = "invalid license expression"
	MSG_LICENSE_EXPRESSION_INVALID_CONJUNCTION = "invalid conjunction"
	MSG_LICENSE_EXPRESSION_UNDEFINED_POLICY    = "contains an undefined policy"
	MSG_LICENSE_EXPRESSION                     = "license expression"
)

func NewCompoundExpression() *CompoundExpression {
	ce := new(CompoundExpression)
	ce.LeftUsagePolicy = POLICY_UNDEFINED
	ce.RightUsagePolicy = POLICY_UNDEFINED
	ce.CompoundUsagePolicy = POLICY_UNDEFINED
	return ce
}

func CopyCompoundExpression(expression *CompoundExpression) *CompoundExpression {
	ce := new(CompoundExpression)
	ce.SimpleLeft = expression.SimpleLeft
	ce.LeftPolicy = expression.LeftPolicy
	ce.CompoundLeft = expression.CompoundLeft
	ce.LeftUsagePolicy = expression.LeftUsagePolicy
	ce.Conjunction = expression.Conjunction
	ce.SimpleRight = expression.SimpleRight
	ce.RightPolicy = expression.RightPolicy
	ce.CompoundRight = expression.CompoundRight
	ce.RightUsagePolicy = expression.RightUsagePolicy
	ce.CompoundUsagePolicy = expression.CompoundUsagePolicy
	return ce
}


func tokenizeExpression(expression string) (tokens []string) {
	// Add spaces to assure proper tokenization with whitespace bw/ tokens
	expression = strings.ReplaceAll(expression, LEFT_PARENS, LEFT_PARENS_WITH_SEPARATOR)
	expression = strings.ReplaceAll(expression, RIGHT_PARENS, RIGHT_PARENS_WITH_SEPARATOR)
	// fields are, by default, separated by whitespace
	tokens = strings.Fields(expression)
	return
}

func ParseExpression(policyConfig *LicensePolicyConfig, rawExpression string) (ce *CompoundExpression, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	ce = NewCompoundExpression()

	tokens := tokenizeExpression(rawExpression)
	getLogger().Debugf("Tokens: %v", tokens)

	finalIndex, err := parseCompoundExpression(policyConfig, ce, tokens, 0)
	getLogger().Debugf("Parsed expression (%v): %v", finalIndex, ce)

	return ce, err
}

func parseCompoundExpression(policyConfig *LicensePolicyConfig, expression *CompoundExpression, tokens []string, index int) (i int, err error) {
	getLogger().Enter("expression:", expression)
	defer getLogger().Exit()
	defer func() {
		if expression.CompoundUsagePolicy == POLICY_UNDEFINED {
			getLogger().Warningf("%s: %s: expression: left term: %s, right term: %s",
				MSG_LICENSE_EXPRESSION,
				MSG_LICENSE_EXPRESSION_UNDEFINED_POLICY,
				expression.LeftUsagePolicy,
				expression.RightUsagePolicy,
			)
		}
	}()
	var token string
	for index < len(tokens) {
		token = tokens[index]
		switch token {
		case LEFT_PARENS:
			getLogger().Debugf("[%v] LEFT_PARENS: `%v`", index, token)
			childExpression := NewCompoundExpression()

			// if we have no conjunction, this token represents the "left" operand
			if expression.Conjunction == "" {
				expression.CompoundLeft = childExpression
			} else {
				// otherwise it is the "right" operand
				expression.CompoundRight = childExpression
			}

			index, err = parseCompoundExpression(policyConfig, childExpression, tokens, index+1)
			if err != nil {
				return
			}

			// retrieve the resolved policy from the child
			childPolicy := childExpression.CompoundUsagePolicy
			if expression.Conjunction == "" {
				expression.LeftUsagePolicy = childPolicy
			} else {
				// otherwise it is the "right" operand
				expression.RightUsagePolicy = childPolicy
			}

		case RIGHT_PARENS:
			getLogger().Debugf("[%v] RIGHT_PARENS: `%v`", index, token)
			err = FinalizeCompoundPolicy(expression)
			return index, err // Do NOT Increment, parent caller will do that
		case AND:
			getLogger().Debugf("[%v] AND (Conjunction): `%v`", index, token)
			if expression.Conjunction == "" {
				expression.Conjunction = token
			} else {
				expression.SubsequentConjunction = token
			}
		case OR:
			getLogger().Debugf("[%v] OR (Conjunction): `%v`", index, token)
			if expression.Conjunction == "" {
				expression.Conjunction = token
			} else {
				expression.SubsequentConjunction = token
			}
		case WITH:
			getLogger().Debugf("[%v] WITH (Conjunction): `%v`", index, token)
			if expression.Conjunction == "" {
				expression.Conjunction = token
			} else {
				expression.SubsequentConjunction = token
			}
		default:
			getLogger().Debugf("[%v] Simple Expression: `%v`", index, token)
			// if we have no conjunction, this token represents the "left" operand
			if expression.Conjunction == CONJUNCTION_UNDEFINED {
				expression.SimpleLeft = token
				// Lookup policy in hashmap
				expression.LeftUsagePolicy, expression.LeftPolicy, err = policyConfig.FindPolicyBySpdxId(token)
				if err != nil {
					return
				}
			} else {
				// if we have a single conjunction, this token represents the "right" operand
				if expression.SubsequentConjunction == "" {
					expression.SimpleRight = token
					// Lookup policy in hashmap
					expression.RightUsagePolicy, expression.RightPolicy, err = policyConfig.FindPolicyBySpdxId(token)
					if err != nil {
						return
					}
				} else {
					// if we have a subsequent conjunction, we must fold the expression taking into account the natural operator precedence;
					// depending on the case, this token represents the "right" operand of either the expression itself or its right-side child expression
					if expression.Conjunction == AND && expression.SubsequentConjunction == AND {
						// left AND right AND another-> (left AND right) AND another
						LeftFoldCompoundExpression(policyConfig, expression, AND, token)
					} else if expression.Conjunction == AND && expression.SubsequentConjunction == OR {
						// left AND right OR another-> (left AND right) OR another
						LeftFoldCompoundExpression(policyConfig, expression, OR, token)
					} else if expression.Conjunction == AND && expression.SubsequentConjunction == WITH {
						// left AND right WITH another-> left AND (right WITH another)
						RightFoldCompoundExpression(policyConfig, expression, WITH, token)
					} else if expression.Conjunction == OR && expression.SubsequentConjunction == AND {
						// left OR right AND another-> left OR (right AND another)
						RightFoldCompoundExpression(policyConfig, expression, AND, token)
					} else if expression.Conjunction == OR && expression.SubsequentConjunction == OR {
						// left OR right OR another-> left OR (right OR another)
						RightFoldCompoundExpression(policyConfig, expression, OR, token)
					} else if expression.Conjunction == OR && expression.SubsequentConjunction == WITH {
						// left OR right WITH another-> left OR (right WITH another)
						RightFoldCompoundExpression(policyConfig, expression, WITH, token)
					} else if expression.Conjunction == WITH && expression.SubsequentConjunction == AND {
						// left WITH right AND another -> (left WITH right) AND another
						LeftFoldCompoundExpression(policyConfig, expression, AND, token)
					} else if expression.Conjunction == WITH && expression.SubsequentConjunction == OR {
						// left WITH right OR another -> (left WITH right) OR another
						LeftFoldCompoundExpression(policyConfig, expression, OR, token)
					} else if expression.Conjunction == WITH && expression.SubsequentConjunction == WITH {
						// left WITH right WITH another -> left WITH (right OR another)
						RightFoldCompoundExpression(policyConfig, expression, OR, token)
					}
				}
			}
		}
		
		index = index + 1
	}
	
	err = FinalizeCompoundPolicy(expression)
	return index, err
}

func LeftFoldCompoundExpression(policyConfig *LicensePolicyConfig, expression *CompoundExpression, conjunction string, token string) (err error) {
	childExpression := CopyCompoundExpression(expression)
	err = FinalizeCompoundPolicy(childExpression)
	if err != nil {
		return
	}

	expression.SimpleLeft = ""
	expression.LeftPolicy = LicensePolicy{}
	expression.CompoundLeft = childExpression
	expression.LeftUsagePolicy = childExpression.CompoundUsagePolicy

	expression.Conjunction = conjunction
	expression.SubsequentConjunction = ""

	expression.SimpleRight = token
	expression.RightUsagePolicy, expression.RightPolicy, err = policyConfig.FindPolicyBySpdxId(token)
		if err != nil {
		return
	}
	
	return nil
}

func RightFoldCompoundExpression(policyConfig *LicensePolicyConfig, expression *CompoundExpression, conjunction string, token string) (err error) {
	childExpression := NewCompoundExpression()

	childExpression.SimpleLeft = expression.SimpleRight
	childExpression.LeftPolicy = expression.RightPolicy
	childExpression.CompoundLeft = expression.CompoundRight
	childExpression.LeftUsagePolicy = expression.RightUsagePolicy

	childExpression.Conjunction = conjunction

	childExpression.SimpleRight = token
	childExpression.RightUsagePolicy, childExpression.RightPolicy, err = policyConfig.FindPolicyBySpdxId(token)
	if err != nil {
		return
	}

	err = FinalizeCompoundPolicy(childExpression)
	if err != nil {
		return
	}

	expression.SubsequentConjunction = ""

	expression.SimpleRight = ""
	expression.RightPolicy = LicensePolicy{}
	expression.CompoundRight = childExpression
	expression.RightUsagePolicy = childExpression.CompoundUsagePolicy

	return nil
}

func FinalizeCompoundPolicy(expression *CompoundExpression) (err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	if expression == nil {
		return getLogger().Errorf("Expression is nil")
	}

	getLogger().Debugf("Evaluating policy: (`%s` `%s` `%s`)",
		expression.LeftUsagePolicy,
		expression.Conjunction,
		expression.RightUsagePolicy)

	// The policy config. has 3 states: { "allow", "deny", "needs-review" }; n=3
	// which are always paired with a conjunctions; r=2
	// and for evaluation, we do not care about order.  This means we have to
	// account for 6 combinations with unique results (policy determinations)
	switch expression.Conjunction {
	// The AND case, is considered "pessimistic"; that is, we want to quickly identify "negative" usage policies.
	// This means we first look for any "deny" policy as this overrides any other state's value
	// then look for any "needs-review" policy as we assume it COULD be a "deny" determination upon review
	// this leaves the remaining state which is "allow" (both sides) as the only "positive" outcome
	case AND:
		// Undefined Short-circuit:
		// If either left or right policy is UNDEFINED with the AND conjunction,
		// take the pessimistic value (DENY) result if offered by either term
		if expression.LeftUsagePolicy == POLICY_UNDEFINED ||
			expression.RightUsagePolicy == POLICY_UNDEFINED {

			if expression.LeftUsagePolicy == POLICY_DENY ||
				expression.RightUsagePolicy == POLICY_DENY {
				expression.CompoundUsagePolicy = POLICY_DENY

			} else {
				expression.CompoundUsagePolicy = POLICY_UNDEFINED
			}
			return nil
		}

		// This "deny" comparator block covers 3 of the 6 combinations:
		// 1. POLICY_DENY AND POLICY_ALLOW
		// 2. POLICY_DENY AND POLICY_NEEDS_REVIEW
		// 3. POLICY_DENY AND POLICY_DENY
		if expression.LeftUsagePolicy == POLICY_DENY ||
			expression.RightUsagePolicy == POLICY_DENY {
			expression.CompoundUsagePolicy = POLICY_DENY
		} else if expression.LeftUsagePolicy == POLICY_NEEDS_REVIEW ||
			expression.RightUsagePolicy == POLICY_NEEDS_REVIEW {
			// This "needs-review" comparator covers 2 of the 6 combinations:
			// 4. POLICY_NEEDS_REVIEW AND POLICY_ALLOW
			// 5. POLICY_NEEDS_REVIEW AND POLICY_NEEDS_REVIEW
			expression.CompoundUsagePolicy = POLICY_NEEDS_REVIEW
		} else {
			// This leaves the only remaining combination:
			// 6. POLICY_ALLOW AND POLICY_ALLOW
			expression.CompoundUsagePolicy = POLICY_ALLOW
		}
	// The OR case, is considered "optimistic"; that is, we want to quickly identify "positive" usage policies.
	// This means we first look for any "allow" policy as this overrides any other state's value
	// then look for any "needs-review" policy as we assume it COULD be an "allow" determination upon review
	// this leaves the remaining state which is "allow" (both sides) as the only "positive" outcome
	case OR:
		// Undefined Short-circuit:
		// If either left or right policy is UNDEFINED with the OR conjunction,
		// take the result offered by the other term (which could also be UNDEFINED)
		if expression.LeftUsagePolicy == POLICY_UNDEFINED {
			// default to right policy (regardless of value)
			expression.CompoundUsagePolicy = expression.RightUsagePolicy
			getLogger().Debugf("Left usage policy is UNDEFINED")
			return nil
		} else if expression.RightUsagePolicy == POLICY_UNDEFINED {
			// default to left policy (regardless of value)
			expression.CompoundUsagePolicy = expression.LeftUsagePolicy
			getLogger().Debugf("Right usage policy is UNDEFINED")
			return nil
		}

		// This "allow" comparator block covers 3 of the 6 combinations:
		// 1. POLICY_ALLOW OR POLICY_DENY
		// 2. POLICY_ALLOW OR POLICY_NEEDS_REVIEW
		// 3. POLICY_ALLOW OR POLICY_ALLOW
		if expression.LeftUsagePolicy == POLICY_ALLOW ||
			expression.RightUsagePolicy == POLICY_ALLOW {
			expression.CompoundUsagePolicy = POLICY_ALLOW
		} else if expression.LeftUsagePolicy == POLICY_NEEDS_REVIEW ||
			expression.RightUsagePolicy == POLICY_NEEDS_REVIEW {
			// This "needs-review" comparator covers 2 of the 6 combinations:
			// 4. POLICY_NEEDS_REVIEW OR POLICY_DENY
			// 5. POLICY_NEEDS_REVIEW OR POLICY_NEEDS_REVIEW
			expression.CompoundUsagePolicy = POLICY_NEEDS_REVIEW
		} else {
			// This leaves the only remaining combination:
			// 6. POLICY_DENY OR POLICY_DENY
			expression.CompoundUsagePolicy = POLICY_DENY
		}
	case WITH:
		// Undefined Short-circuit:
		// If either left or right policy is UNDEFINED with the WITH conjunction,
		// take the result offered by the other term (which could also be UNDEFINED)
		if expression.LeftUsagePolicy == POLICY_UNDEFINED {
			// default to right policy (regardless of value)
			expression.CompoundUsagePolicy = expression.RightUsagePolicy
			getLogger().Debugf("Left usage policy is UNDEFINED")
			return nil
		} else if expression.RightUsagePolicy == POLICY_UNDEFINED {
			// default to left policy (regardless of value)
			expression.CompoundUsagePolicy = expression.LeftUsagePolicy
			getLogger().Debugf("Right usage policy is UNDEFINED")
			return nil
		}

		// This "allow" comparator block covers 3 of the 9 combinations:
		// 1. POLICY_ALLOW WITH POLICY_ALLOW
		// 2. POLICY_NEEDS_REVIEW WITH POLICY_ALLOW
		// 3. POLICY_DENY WITH POLICY_ALLOW
		if expression.RightUsagePolicy == POLICY_ALLOW {
			expression.CompoundUsagePolicy = POLICY_ALLOW
		} else if expression.RightUsagePolicy == POLICY_NEEDS_REVIEW {
			// This "needs-review" comparator covers 2 of the 6 combinations:
			// 4. POLICY_ALLOW WITH POLICY_NEEDS_REVIEW
			// 5. POLICY_NEEDS_REVIEW WITH POLICY_NEEDS_REVIEW
			// 6. POLICY_DENY WITH POLICY_NEEDS_REVIEW
			expression.CompoundUsagePolicy = POLICY_NEEDS_REVIEW
		} else {
			// This leaves the only remaining combination:
			// 7. POLICY_ALLOW WITH POLICY_DENY
			// 8. POLICY_NEEDS_REVIEW WITH POLICY_DENY
			// 9. POLICY_DENY WITH POLICY_DENY
			expression.CompoundUsagePolicy = POLICY_DENY
		}
	case CONJUNCTION_UNDEFINED:
		// Test for simple expression (i.e., "(" compound-expression ")" )
		// which is the only valid one that does not have an AND, OR or WITH conjunction
		if expression.LeftUsagePolicy != POLICY_UNDEFINED &&
			expression.RightUsagePolicy == POLICY_UNDEFINED {
			expression.CompoundUsagePolicy = expression.LeftUsagePolicy
		} // else default expression.CompoundUsagePolicy is UNDEFINED
	default:
		expression.CompoundUsagePolicy = POLICY_UNDEFINED
		return getLogger().Errorf("%s: %s: `%s`",
			MSG_LICENSE_INVALID_EXPRESSION,
			MSG_LICENSE_EXPRESSION_INVALID_CONJUNCTION,
			expression.Conjunction)

	}
	getLogger().Debugf("(%s (%s) %s %s (%s)) == %s",
		expression.SimpleLeft,
		expression.LeftUsagePolicy,
		expression.Conjunction,
		expression.SimpleRight,
		expression.RightUsagePolicy,
		expression.CompoundUsagePolicy)

	return nil
}
