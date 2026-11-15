// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type validateTestSuite struct {
	suite.Suite
}

func TestValidateTestSuite(t *testing.T) {
	suite.Run(t, new(validateTestSuite))
}

func (s *validateTestSuite) TestValidateTestsHeaders_OK() {
	yaml := `---
meta:
  author: "go-ftw"
tests:
  - test_id: 1
    stages:
      - input:
          headers:
            Host: "localhost"
            User-Agent: "OWASP CRS test agent"
        output:
          status: 200
`
	ftwTest, err := GetTestFromYaml([]byte(yaml), "920100.yaml")
	s.Require().NoError(err)
	s.Require().NoError(ValidateTestsHeaders([]*FTWTest{ftwTest}))
}

func (s *validateTestSuite) TestValidateTestsHeaders_RejectsTrailingLFFromBlockScalar() {
	// Mirrors the regression fixture for coreruleset/go-ftw#662: a YAML block
	// scalar appends a trailing "\n" that would corrupt header framing.
	yaml := `---
meta:
  author: "go-ftw"
tests:
  - test_id: 10
    stages:
      - input:
          headers:
            Host: "localhost"
            sec-ch-ua-full-version-list: |
              "Google Chrome";v="149.0.0.0"
        output:
          status: 200
`
	ftwTest, err := GetTestFromYaml([]byte(yaml), "920274.yaml")
	s.Require().NoError(err)
	err = ValidateTestsHeaders([]*FTWTest{ftwTest})
	s.Require().Error(err)
	s.Contains(err.Error(), "920274.yaml")
	s.Contains(err.Error(), "test 920274-10")
	s.Contains(err.Error(), "stage 1")
	s.Contains(err.Error(), "CR or LF")
	s.Contains(err.Error(), "sec-ch-ua-full-version-list")
}

func (s *validateTestSuite) TestValidateTestsHeaders_RejectsCRLFInName() {
	yaml := "---\n" +
		"meta:\n" +
		"  author: \"go-ftw\"\n" +
		"tests:\n" +
		"  - test_id: 2\n" +
		"    stages:\n" +
		"      - input:\n" +
		"          ordered_headers:\n" +
		"            - name: \"X-Test\\r\\nInjected\"\n" +
		"              value: \"ok\"\n" +
		"        output:\n" +
		"          status: 200\n"
	ftwTest, err := GetTestFromYaml([]byte(yaml), "123456.yaml")
	s.Require().NoError(err)
	err = ValidateTestsHeaders([]*FTWTest{ftwTest})
	s.Require().Error(err)
	s.Contains(err.Error(), "CR or LF")
}

func (s *validateTestSuite) TestValidateTestsHeaders_Empty() {
	s.Require().NoError(ValidateTestsHeaders(nil))
	s.Require().NoError(ValidateTestsHeaders([]*FTWTest{}))
}
