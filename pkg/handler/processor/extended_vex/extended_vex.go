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
	"fmt"

	json "github.com/json-iterator/go"

	vex "github.com/guacsec/guac/pkg/evex"
	"github.com/guacsec/guac/pkg/handler/processor"
)

// ExtendedVEXProcessor processes eVEX documents.
// Currently only supports eVEX JSON documents.
type ExtendedVEXProcessor struct{}

func (p *ExtendedVEXProcessor) ValidateSchema(d *processor.Document) error {
	if d.Type != processor.DocumentExtendedVEX {
		return fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentExtendedVEX, d.Type)
	}

	switch d.Format {
	case processor.FormatJSON:
		var decoded vex.ExtendedVEX
		err := json.Unmarshal(d.Blob, &decoded)
		return err
	}

	return fmt.Errorf("unable to support parsing of eVEX document format: %v", d.Format)
}

// Unpack takes in the document and tries to unpack it
// if there is a valid decomposition of sub-documents.
//
// Returns empty list and nil error if nothing to unpack
// Returns unpacked list and nil error if successfully unpacked
func (p *ExtendedVEXProcessor) Unpack(d *processor.Document) ([]*processor.Document, error) {
	if d.Type != processor.DocumentExtendedVEX {
		return nil, fmt.Errorf("expected document type: %v, actual document type: %v", processor.DocumentExtendedVEX, d.Type)
	}

	return []*processor.Document{}, nil
}
