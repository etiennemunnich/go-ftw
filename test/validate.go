// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"fmt"
)

// ValidateTestsHeaders rejects tests whose stage request headers contain a raw
// CR or LF character. A common source is an unquoted YAML block scalar (`|`),
// which silently appends a trailing newline; left unchecked, ftw check would
// report the file as valid while ftw run fails when building the request
// (see coreruleset/go-ftw#662 and the follow-up noted in #682).
func ValidateTestsHeaders(tests []*FTWTest) error {
	for _, ftwTest := range tests {
		for _, testCase := range ftwTest.Tests {
			for stageIdx := range testCase.Stages {
				stage := &testCase.Stages[stageIdx]
				headers := NewInput(&stage.Input).GetHeaders()
				if err := headers.ValidateNoCRLF(); err != nil {
					return fmt.Errorf("%s (test %s, stage %d): %w", ftwTest.FileName, testCase.IdString(), stageIdx+1, err)
				}
			}
		}
	}
	return nil
}
