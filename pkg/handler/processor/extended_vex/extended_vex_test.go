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
	"reflect"
	"testing"

	"github.com/guacsec/guac/internal/testing/testdata"
	"github.com/guacsec/guac/pkg/handler/processor"
)

func TestExtendedVEXProcessor_ValidateSchema(t *testing.T) {
	type args struct {
		d *processor.Document
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "default Extended VEX document",
			args: args{
				d: &processor.Document{
					Blob:   testdata.ExtendedVexSmallExample,
					Type:   processor.DocumentExtendedVEX,
					Format: processor.FormatJSON,
				},
			},
			wantErr: false,
		},
		{
			name: "incorrect type",
			args: args{
				d: &processor.Document{
					Blob:   testdata.ExtendedVexSmallExample,
					Type:   processor.DocumentUnknown,
					Format: processor.FormatJSON,
				},
			},
			wantErr: true,
		},
		{
			name: "invalid Extended VEX document",
			args: args{
				d: &processor.Document{
					Blob:   []byte("invalid"),
					Type:   processor.DocumentExtendedVEX,
					Format: processor.FormatJSON,
				},
			},
			wantErr: true,
		},
		{
			name: "invalid Extended VEX document format",
			args: args{
				d: &processor.Document{
					Blob:   testdata.ExtendedVexSmallExample,
					Type:   processor.DocumentExtendedVEX,
					Format: processor.FormatUnknown,
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &ExtendedVEXProcessor{}
			if err := p.ValidateSchema(tt.args.d); (err != nil) != tt.wantErr {
				t.Errorf("ValidateSchema() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExtendedVEXProcessor_Unpack(t *testing.T) {
	type args struct {
		d *processor.Document
	}
	tests := []struct {
		name    string
		args    args
		want    []*processor.Document
		wantErr bool
	}{
		{
			name: "ExtendedVEX document",
			args: args{
				d: &processor.Document{
					Type: processor.DocumentExtendedVEX,
				},
			},
			want: []*processor.Document{},
		},
		{
			name: "Incorrect type",
			args: args{
				d: &processor.Document{
					Type: processor.DocumentUnknown,
				},
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &ExtendedVEXProcessor{}
			got, err := p.Unpack(tt.args.d)
			if (err != nil) != tt.wantErr {
				t.Errorf("Unpack() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Unpack() got = %v, want %v", got, tt.want)
			}
		})
	}
}
