//
// Copyright 2023 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package extended_vex

import (
	"context"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
)

func Test_ExtendedVEXParser_Parse(t *testing.T) {
	type args struct {
		ctx context.Context
		doc *processor.Document
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "test",
			args: args{
				ctx: context.Background(),
				doc: &processor.Document{Blob: testdata.ExtendedVexSmallExample},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newParser := NewExtendedVEXParser()
			if err := newParser.Parse(tt.args.ctx, tt.args.doc); (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_ExtendedVEXParser_GetPredicates(t *testing.T) {
	type fields struct {
		doc *processor.Document
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *assembler.IngestPredicates
	}{
		{
			name: "valid case",
			fields: fields{
				doc: &processor.Document{
					Blob:   testdata.ExtendedVexSmallExample,
					Format: processor.FormatJSON,
					Type:   processor.DocumentExtendedVEX,
					SourceInformation: processor.SourceInformation{
						Collector: "TestCollector",
						Source:    "TestSource",
					},
				},
			},
			args: args{
				ctx: context.Background(),
			},
			want: &assembler.IngestPredicates{
				Vex:         testdata.ExtendedVexIngest,
				CertifyVuln: testdata.ExtendedVexCertifyVulnIngest,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewExtendedVEXParser()

			err := c.Parse(tt.args.ctx, tt.fields.doc)
			if err != nil {
				t.Errorf("Parse() error = %v, wantErr %v", err, false)
				return
			}

			got := c.GetPredicates(tt.args.ctx)

			if d := cmp.Diff(tt.want, got, testdata.IngestPredicatesCmpOpts...); len(d) != 0 {
				t.Errorf("csaf.GetPredicate mismatch values (+got, -expected): %s", d)
			}
		})
	}
}

func Test_ExtendedVEXParser_GetIdentities(t *testing.T) {
	type fields struct {
		identifierStrings *common.IdentifierStrings
	}
	type args struct {
		ctx context.Context
	}
	test := struct {
		name   string
		fields fields
		args   args
		want   []common.TrustInformation
	}{
		name: "default case",
		want: nil,
	}
	c := &ExtendedVEXParser{
		identifierStrings: test.fields.identifierStrings,
	}
	if got := c.GetIdentities(test.args.ctx); !reflect.DeepEqual(got, test.want) {
		t.Errorf("GetIdentities() = %v, want %v", got, test.want)
	}
}

func Test_ExtendedVEXParser_GetIdentifiers(t *testing.T) {
	type fields struct {
		doc               *processor.Document
		identifierStrings *common.IdentifierStrings
	}
	test := struct {
		name    string
		fields  fields
		ctx     context.Context
		want    *common.IdentifierStrings
		wantErr bool
	}{
		name: "default case",
		fields: fields{
			doc: &processor.Document{
				Blob:   testdata.ExtendedVexSmallExample,
				Format: processor.FormatJSON,
				Type:   processor.DocumentExtendedVEX,
				SourceInformation: processor.SourceInformation{
					Collector: "TestCollector",
					Source:    "TestSource",
				},
			},
			identifierStrings: &common.IdentifierStrings{},
		},
		ctx: context.Background(),
		want: &common.IdentifierStrings{
			PurlStrings: []string{
				"pkg:npm/fast-xml-parser@4.1.2",
			},
		},
	}

	c := NewExtendedVEXParser()

	err := c.Parse(test.ctx, test.fields.doc)
	if err != nil {
		t.Errorf("Parse() error = %v, wantErr %v", err, false)
		return
	}

	_ = c.GetPredicates(test.ctx)

	got, err := c.GetIdentifiers(test.ctx)
	if (err != nil) != test.wantErr {
		t.Errorf("GetIdentifiers() error = %v, wantErr %v", err, test.wantErr)
		return
	}
	if d := cmp.Diff(test.want, got, testdata.IngestPredicatesCmpOpts...); len(d) != 0 {
		t.Errorf("csaf.GetPredicate mismatch values (+got, -expected): %s", d)
	}
}
