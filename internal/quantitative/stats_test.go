// Copyright 2024 OWASP CRS Project
// SPDX-License-Identifier: Apache-2.0

package quantitative

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/suite"

	"github.com/coreruleset/go-ftw/output"
)

type statsTestSuite struct {
	suite.Suite
}

func (s *statsTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

func TestStatsTestSuite(t *testing.T) {
	suite.Run(t, new(statsTestSuite))
}

func (s *statsTestSuite) TestNewQuantitativeStats() {
	tests := []struct {
		name string
		want *QuantitativeRunStats
	}{
		{
			name: "Test 1",
			want: &QuantitativeRunStats{
				count_:                0,
				falsePositives:        0,
				falsePositivesPerRule: make(map[int]int),
				totalTime:             0,
			},
		},
	}
	for _, tt := range tests {
		s.Run(tt.name, func() {
			got := NewQuantitativeStats()
			s.Require().Equal(got, tt.want)
		})
	}
}

func (s *statsTestSuite) TestQuantitativeRunStats_MarshalJSON() {
	type fields struct {
		count_                int
		totalTime             time.Duration
		falsePositives        int
		falsePositivesPerRule map[int]int
	}
	tests := []struct {
		name    string
		fields  fields
		want    []byte
		wantErr bool
	}{
		{
			name: "Test 1",
			fields: fields{
				count_:                1,
				totalTime:             time.Second,
				falsePositives:        1,
				falsePositivesPerRule: map[int]int{920010: 1},
			},
			want:    []byte(`{"count":1,"falsePositives":1,"falsePositivesPerRule":{"920010":1},"skipped":0,"totalTimeSeconds":1}`),
			wantErr: false,
		},
		{
			name: "Test 2",
			fields: fields{
				count_:                2,
				totalTime:             time.Second * 2,
				falsePositives:        2,
				falsePositivesPerRule: map[int]int{933100: 2},
			},
			want:    []byte(`{"count":2,"falsePositives":2,"falsePositivesPerRule":{"933100":2},"skipped":0,"totalTimeSeconds":2}`),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		s.Run(tt.name, func() {
			q := &QuantitativeRunStats{
				count_:                tt.fields.count_,
				totalTime:             tt.fields.totalTime,
				falsePositives:        tt.fields.falsePositives,
				falsePositivesPerRule: tt.fields.falsePositivesPerRule,
			}
			got, err := q.MarshalJSON()
			s.Require().NoError(err)
			s.Require().Equal(got, tt.want)
		})
	}
}

func (s *statsTestSuite) TestQuantitativeRunStats_functions() {
	q := NewQuantitativeStats()

	q.incrementRun()
	s.Require().Equal(q.Count(), 1)

	q.addFalsePositive(920100)
	s.Require().Equal(q.FalsePositives(), 1)

	q.incrementRun()
	s.Require().Equal(q.Count(), 2)

	q.addFalsePositive(920200)
	s.Require().Equal(q.FalsePositives(), 2)

	duration := time.Duration(5000)
	q.SetTotalTime(duration)
	s.Require().Equal(q.TotalTime(), duration)
}

func (s *statsTestSuite) TestQuantitativeRunStats_printSummary() {
	var b bytes.Buffer
	out := output.NewOutput("plain", &b)
	q := NewQuantitativeStats()

	q.incrementRun()
	s.Require().Equal(q.Count(), 1)

	q.addFalsePositive(920100)
	s.Require().Equal(q.FalsePositives(), 1)
	s.Require().Equal(q.Skipped(), 0)

	q.printSummary(out)
	s.Require().Equal("Run 1 payloads (0 skipped) in 0s\nTotal False positive ratio: 1/1 = 1.0000\nFalse positives per rule id:\n  920100: 1 false positives. FP Ratio: 1/1 = 1.0000\n", b.String())
}

// FIXME: can we drop this thest? It has no success / fail condition
func (s *statsTestSuite) TestAddFalsePositiveRace() {
	stats := &QuantitativeRunStats{
		falsePositivesPerRule: make(map[int]int),
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(rule int) {
			defer wg.Done()
			stats.addFalsePositive(rule)
		}(i % 10) // Few rules are getting hit to make the concurrency issue more likely
	}
	wg.Wait()
}
