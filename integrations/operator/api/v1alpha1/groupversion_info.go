// Package v1alpha1 contains the API schema for the himitsu.io group.
// +kubebuilder:object:generate=true
// +groupName=himitsu.io
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is the group/version for these types.
	GroupVersion = schema.GroupVersion{Group: "himitsu.io", Version: "v1alpha1"}

	// SchemeBuilder registers the types into a runtime scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the types in this group-version to a scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)
