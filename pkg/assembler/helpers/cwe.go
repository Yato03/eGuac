package helpers

import (
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/evex"
)

func CreatePotentialMitigations(cwe evex.CWE) []*generated.PotentialMitigationsInput {
	var potentialMitigations []*generated.PotentialMitigationsInput
	for _, mitigation := range cwe.PotentialMitigations {
		potentialMitigations = append(potentialMitigations, &generated.PotentialMitigationsInput{
			Phase:              &mitigation.Phase,
			Description:        &mitigation.Description,
			Effectiveness:      &mitigation.Effectiveness,
			EffectivenessNotes: &mitigation.EffectivenessNotes,
		})
	}
	return potentialMitigations
}

func CreateConsequences(cwe evex.CWE) []*generated.ConsequencesInput {
	var consequences []*generated.ConsequencesInput
	for _, consequence := range cwe.Consequences {
		consequences = append(consequences, &generated.ConsequencesInput{
			Scope:      *ConvertToPointerSliceString(consequence.Scope),
			Impact:     *ConvertToPointerSliceString(consequence.Impact),
			Notes:      &consequence.Note,
			Likelihood: &consequence.Likelihood,
		})
	}
	return consequences
}

func CreateDetectionMethods(cwe evex.CWE) []*generated.DetectionMethodsInput {
	var detectionMethods []*generated.DetectionMethodsInput
	for _, detectionMethod := range cwe.DetectionMethods {
		detectionMethods = append(detectionMethods, &generated.DetectionMethodsInput{
			Id:            &detectionMethod.ID,
			Method:        &detectionMethod.Method,
			Description:   &detectionMethod.Description,
			Effectiveness: &detectionMethod.Effectiveness,
		})
	}
	return detectionMethods
}

func CreateUsedArtifacts(artifacts []evex.Artifact) []*generated.UsedArtifactInputSpec {
	var usedArtifacts []*generated.UsedArtifactInputSpec
	for _, artifact := range artifacts {
		usedArtifacts = append(usedArtifacts, &generated.UsedArtifactInputSpec{
			Name:        &artifact.ArtifactName,
			UsedInLines: *ConvertToPointerSliceInt(artifact.UsedInLines),
		})
	}
	return usedArtifacts
}

func ConvertToPointerSliceString(slice []string) *[]*string {
	result := make([]*string, len(slice))
	for i, v := range slice {
		result[i] = &v
	}
	return &result
}

func ConvertToPointerSliceInt(slice []int) *[]*int {
	result := make([]*int, len(slice))
	for i, v := range slice {
		result[i] = &v
	}
	return &result
}
