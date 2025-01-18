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

type CompoundExpression struct {
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
	CompoundName          string
	CompoundUsagePolicy   string
	Urls                  []string
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
	ce.CompoundName = expression.CompoundName
	ce.Urls = append(ce.Urls, expression.Urls...)
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

func findPolicy(policyConfig *LicensePolicyConfig, token string) (matchedUsagePolicy string, matchedPolicy LicensePolicy, err error) {
	if IsUrlish(token) {
		matchedPolicy = policyConfig.FindPolicyByUrl(token, policyConfig.PolicyList)
		matchedUsagePolicy = matchedPolicy.UsagePolicy
		return
	}

	matchedPolicy, err = policyConfig.FindPolicyBySpdxId(token)
	if err != nil {
		return
	}
	if matchedPolicy.UsagePolicy != POLICY_UNDEFINED {
		matchedUsagePolicy = matchedPolicy.UsagePolicy
		return
	}
	
	matchedPolicy = policyConfig.FindPolicyByName(token, policyConfig.PolicyList)
	matchedUsagePolicy = matchedPolicy.UsagePolicy
	return
}

func renderPolicyName(policy LicensePolicy) string {
	if policy.UsagePolicy == POLICY_UNDEFINED {
		return NAME_NO_ASSERTION
	}
	return policy.Name
}

func ParseExpression(policyConfig *LicensePolicyConfig, rawExpression string) (expression *CompoundExpression, err error) {
	getLogger().Enter()
	defer getLogger().Exit()

	expression = NewCompoundExpression()

	tokens := tokenizeExpression(rawExpression)
	getLogger().Debugf("Tokens: %v", tokens)

	finalIndex, err := expression.Parse(policyConfig, tokens, 0)
	getLogger().Debugf("Parsed expression (%v): %v", finalIndex, expression)

	return expression, err
}

func (expression *CompoundExpression) Parse(policyConfig *LicensePolicyConfig, tokens []string, index int) (i int, err error) {
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
		switch strings.ToUpper(token) {
		case LEFT_PARENS:
			getLogger().Debugf("[%v] LEFT_PARENS: `%v`", index, token)
			childExpression := NewCompoundExpression()

			index, err = childExpression.Parse(policyConfig, tokens, index+1)
			if err != nil {
				return
			}

			// if we have no conjunction, this token represents the "left" operand
			if expression.Conjunction == "" {
				expression.CompoundLeft = childExpression
				expression.CompoundName = LEFT_PARENS + " " + childExpression.CompoundName + " " + RIGHT_PARENS
				expression.Urls = append(expression.Urls, childExpression.Urls...)
				expression.LeftUsagePolicy = childExpression.CompoundUsagePolicy
			} else {
				// otherwise it is the "right" operand
				expression.CompoundRight = childExpression
				if expression.SubsequentConjunction != "" {
					expression.CompoundName += " " + expression.SubsequentConjunction
				}
				expression.CompoundName += " " + LEFT_PARENS + " " + childExpression.CompoundName + " " + RIGHT_PARENS
				expression.Urls = append(expression.Urls, childExpression.Urls...)
				expression.RightUsagePolicy = childExpression.CompoundUsagePolicy
			}

		case RIGHT_PARENS:
			getLogger().Debugf("[%v] RIGHT_PARENS: `%v`", index, token)
			err = expression.EvaluateUsagePolicies()
			return index, err // Do NOT Increment, parent caller will do that
		case AND:
			getLogger().Debugf("[%v] AND (Conjunction): `%v`", index, token)
			if expression.Conjunction == "" {
				expression.Conjunction = AND
				expression.CompoundName += " " + AND
			} else {
				expression.SubsequentConjunction = AND
			}
		case OR:
			getLogger().Debugf("[%v] OR (Conjunction): `%v`", index, token)
			if expression.Conjunction == "" {
				expression.Conjunction = OR
				expression.CompoundName += " " + OR
			} else {
				expression.SubsequentConjunction = OR
			}
		case WITH:
			getLogger().Debugf("[%v] WITH (Conjunction): `%v`", index, token)
			if expression.Conjunction == "" {
				expression.Conjunction = WITH
				expression.CompoundName += " " + WITH
			} else {
				expression.SubsequentConjunction = WITH
			}
		default:
			getLogger().Debugf("[%v] Simple Expression: `%v`", index, token)
			// if we have no conjunction, this token represents the "left" operand
			if expression.Conjunction == CONJUNCTION_UNDEFINED {
				expression.SimpleLeft = token
				// Lookup policy in hashmap
				expression.LeftUsagePolicy, expression.LeftPolicy, err = findPolicy(policyConfig, token)
				if err != nil {
					return
				}
				expression.CompoundName = renderPolicyName(expression.LeftPolicy)
				if len(expression.LeftPolicy.Urls) > 0 {
					expression.Urls = append(expression.Urls, expression.LeftPolicy.Urls[0])
				}
			} else {
				// if we have a single conjunction, this token represents the "right" operand
				if expression.SubsequentConjunction == "" {
					expression.SimpleRight = token
					// Lookup policy in hashmap
					expression.RightUsagePolicy, expression.RightPolicy, err = findPolicy(policyConfig, token)
					if err != nil {
						return
					}
					expression.CompoundName += " " + renderPolicyName(expression.RightPolicy)
					if len(expression.RightPolicy.Urls) > 0 {
						expression.Urls = append(expression.Urls, expression.RightPolicy.Urls[0])
					}
				} else {
					// if we have a subsequent conjunction, we must fold the expression taking into account the natural operator precedence;
					// depending on the case, this token represents the "right" operand of either the expression itself or its right-side child expression
					if expression.Conjunction == AND && expression.SubsequentConjunction == AND {
						// left AND right AND another-> (left AND right) AND another
						expression.FoldLeftAndAppendRight(policyConfig, AND, token)
					} else if expression.Conjunction == AND && expression.SubsequentConjunction == OR {
						// left AND right OR another-> (left AND right) OR another
						expression.FoldLeftAndAppendRight(policyConfig, OR, token)
					} else if expression.Conjunction == AND && expression.SubsequentConjunction == WITH {
						// left AND right WITH another-> left AND (right WITH another)
						expression.FoldAndAppendRight(policyConfig, WITH, token)
					} else if expression.Conjunction == OR && expression.SubsequentConjunction == AND {
						// left OR right AND another-> left OR (right AND another)
						expression.FoldAndAppendRight(policyConfig, AND, token)
					} else if expression.Conjunction == OR && expression.SubsequentConjunction == OR {
						// left OR right OR another-> left OR (right OR another)
						expression.FoldAndAppendRight(policyConfig, OR, token)
					} else if expression.Conjunction == OR && expression.SubsequentConjunction == WITH {
						// left OR right WITH another-> left OR (right WITH another)
						expression.FoldAndAppendRight(policyConfig, WITH, token)
					} else if expression.Conjunction == WITH && expression.SubsequentConjunction == AND {
						// left WITH right AND another -> (left WITH right) AND another
						expression.FoldLeftAndAppendRight(policyConfig, AND, token)
					} else if expression.Conjunction == WITH && expression.SubsequentConjunction == OR {
						// left WITH right OR another -> (left WITH right) OR another
						expression.FoldLeftAndAppendRight(policyConfig, OR, token)
					} else if expression.Conjunction == WITH && expression.SubsequentConjunction == WITH {
						// left WITH right WITH another -> left WITH (right OR another)
						expression.FoldAndAppendRight(policyConfig, OR, token)
					}
				}
			}
		}

		index = index + 1
	}

	err = expression.EvaluateUsagePolicies()
	return index, err
}

func (expression *CompoundExpression) FoldLeftAndAppendRight(policyConfig *LicensePolicyConfig, conjunction string, token string) (err error) {
	childExpression := CopyCompoundExpression(expression)
	err = childExpression.EvaluateUsagePolicies()
	if err != nil {
		return
	}

	expression.SimpleLeft = ""
	expression.LeftPolicy = LicensePolicy{}
	expression.CompoundLeft = childExpression
	expression.LeftUsagePolicy = childExpression.CompoundUsagePolicy

	expression.Conjunction = conjunction

	expression.SimpleRight = token
	expression.RightUsagePolicy, expression.RightPolicy, err = findPolicy(policyConfig, token)
	if err != nil {
		return
	}

	expression.CompoundName += " " + expression.SubsequentConjunction + " " + renderPolicyName(expression.RightPolicy)
	expression.SubsequentConjunction = ""
	if len(expression.RightPolicy.Urls) > 0 {
		expression.Urls = append(expression.Urls, expression.RightPolicy.Urls[0])
	}

	return nil
}

func (expression *CompoundExpression) FoldAndAppendRight(policyConfig *LicensePolicyConfig, conjunction string, token string) (err error) {
	childExpression := NewCompoundExpression()

	childExpression.SimpleLeft = expression.SimpleRight
	childExpression.LeftPolicy = expression.RightPolicy
	childExpression.CompoundLeft = expression.CompoundRight
	childExpression.LeftUsagePolicy = expression.RightUsagePolicy

	childExpression.Conjunction = conjunction

	childExpression.SimpleRight = token
	childExpression.RightUsagePolicy, childExpression.RightPolicy, err = findPolicy(policyConfig, token)
	if err != nil {
		return
	}

	if expression.CompoundRight != nil {
		childExpression.CompoundName = expression.CompoundRight.CompoundName
		childExpression.Urls = append(childExpression.Urls, expression.CompoundRight.Urls...)
	} else {
		childExpression.CompoundName = renderPolicyName(expression.RightPolicy)
		if len(expression.RightPolicy.Urls) > 0 {
			childExpression.Urls = append(expression.Urls, expression.RightPolicy.Urls[0])
		}
	}
	childExpression.CompoundName = " " + expression.SubsequentConjunction + " " + renderPolicyName(childExpression.RightPolicy)
	if len(childExpression.RightPolicy.Urls) > 0 {
		childExpression.Urls = append(expression.Urls, childExpression.RightPolicy.Urls[0])
	}
	err = childExpression.EvaluateUsagePolicies()
	if err != nil {
		return
	}

	expression.SimpleRight = ""
	expression.RightPolicy = LicensePolicy{}
	expression.CompoundRight = childExpression
	expression.RightUsagePolicy = childExpression.CompoundUsagePolicy

	expression.CompoundName += " " + expression.SubsequentConjunction + " " + renderPolicyName(childExpression.RightPolicy)
	expression.SubsequentConjunction = ""
	if len(childExpression.RightPolicy.Urls) > 0 {
		expression.Urls = append(expression.Urls, childExpression.RightPolicy.Urls[0])
	}

	return nil
}

func (expression *CompoundExpression) EvaluateUsagePolicies() (err error) {
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
