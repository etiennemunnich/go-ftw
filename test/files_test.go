// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"regexp"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/utils"
)

var yamlTest = `
---
meta:
  author: "tester"
  description: "Description"
rule_id: 911100
tests:
  - test_id: 1
    stages:
      - input:
          autocomplete_headers: false
          dest_addr: "127.0.0.1"
          port: 80
          headers:
            User-Agent: "ModSecurity CRS 3 Tests"
            Host: "localhost"
        output:
          no_log_contains: "id \"911100\""
  - test_id: 2
    stages:
      - input:
          dest_addr: "127.0.0.1"
          port: 80
          method: "OPTIONS"
          headers:
            User-Agent: "ModSecurity CRS 3 Tests"
            Host: "localhost"
        output:
          no_log_contains: "id \"911100\""
`

var wrongYamlTest = `
this is not yaml
`

type filesTestSuite struct {
	suite.Suite
}

func (s *filesTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func TestFilesTestSuite(t *testing.T) {
	suite.Run(t, new(filesTestSuite))
}

func (s *filesTestSuite) TestGetTestFromYAML() {
	filename, _ := utils.CreateTempFileWithContent("", yamlTest, "test-yaml-*")
	tests, _ := GetTestsFromFiles(filename)

	for _, ft := range tests {
		s.Equal("tester", ft.Meta.Author)
		s.Equal("Description", ft.Meta.Description)

		re := regexp.MustCompile("911100.*")

		for _, test := range ft.Tests {
			s.True(re.MatchString(test.IdString()), "Can't read test identifier")
		}
	}
}

func (s *filesTestSuite) TestGetFromBadYAML() {
	filename, _ := utils.CreateTempFileWithContent("", wrongYamlTest, "test-yaml-*")
	_, err := GetTestsFromFiles(filename)

	s.Error(err, "reading yaml should fail")
}
