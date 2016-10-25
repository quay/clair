// Package genomics provides access to the Genomics API.
//
// See https://developers.google.com/genomics/v1beta2/reference
//
// Usage example:
//
//   import "google.golang.org/api/genomics/v1beta2"
//   ...
//   genomicsService, err := genomics.New(oauthHttpClient)
package genomics // import "google.golang.org/api/genomics/v1beta2"

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/net/context"
	"golang.org/x/net/context/ctxhttp"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/internal"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Always reference these packages, just in case the auto-generated code
// below doesn't.
var _ = bytes.NewBuffer
var _ = strconv.Itoa
var _ = fmt.Sprintf
var _ = json.NewDecoder
var _ = io.Copy
var _ = url.Parse
var _ = googleapi.Version
var _ = errors.New
var _ = strings.Replace
var _ = internal.MarshalJSON
var _ = context.Canceled
var _ = ctxhttp.Do

const apiId = "genomics:v1beta2"
const apiName = "genomics"
const apiVersion = "v1beta2"
const basePath = "https://www.googleapis.com/genomics/v1beta2/"

// OAuth2 scopes used by this API.
const (
	// View and manage your data in Google BigQuery
	BigqueryScope = "https://www.googleapis.com/auth/bigquery"

	// View and manage your data across Google Cloud Platform services
	CloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"

	// Manage your data in Google Cloud Storage
	DevstorageReadWriteScope = "https://www.googleapis.com/auth/devstorage.read_write"

	// View and manage Genomics data
	GenomicsScope = "https://www.googleapis.com/auth/genomics"

	// View Genomics data
	GenomicsReadonlyScope = "https://www.googleapis.com/auth/genomics.readonly"
)

func New(client *http.Client) (*Service, error) {
	if client == nil {
		return nil, errors.New("client is nil")
	}
	s := &Service{client: client, BasePath: basePath}
	s.AnnotationSets = NewAnnotationSetsService(s)
	s.Annotations = NewAnnotationsService(s)
	s.Callsets = NewCallsetsService(s)
	s.Datasets = NewDatasetsService(s)
	s.Experimental = NewExperimentalService(s)
	s.Jobs = NewJobsService(s)
	s.Readgroupsets = NewReadgroupsetsService(s)
	s.Reads = NewReadsService(s)
	s.References = NewReferencesService(s)
	s.Referencesets = NewReferencesetsService(s)
	s.Variants = NewVariantsService(s)
	s.Variantsets = NewVariantsetsService(s)
	return s, nil
}

type Service struct {
	client    *http.Client
	BasePath  string // API endpoint base URL
	UserAgent string // optional additional User-Agent fragment

	AnnotationSets *AnnotationSetsService

	Annotations *AnnotationsService

	Callsets *CallsetsService

	Datasets *DatasetsService

	Experimental *ExperimentalService

	Jobs *JobsService

	Readgroupsets *ReadgroupsetsService

	Reads *ReadsService

	References *ReferencesService

	Referencesets *ReferencesetsService

	Variants *VariantsService

	Variantsets *VariantsetsService
}

func (s *Service) userAgent() string {
	if s.UserAgent == "" {
		return googleapi.UserAgent
	}
	return googleapi.UserAgent + " " + s.UserAgent
}

func NewAnnotationSetsService(s *Service) *AnnotationSetsService {
	rs := &AnnotationSetsService{s: s}
	return rs
}

type AnnotationSetsService struct {
	s *Service
}

func NewAnnotationsService(s *Service) *AnnotationsService {
	rs := &AnnotationsService{s: s}
	return rs
}

type AnnotationsService struct {
	s *Service
}

func NewCallsetsService(s *Service) *CallsetsService {
	rs := &CallsetsService{s: s}
	return rs
}

type CallsetsService struct {
	s *Service
}

func NewDatasetsService(s *Service) *DatasetsService {
	rs := &DatasetsService{s: s}
	return rs
}

type DatasetsService struct {
	s *Service
}

func NewExperimentalService(s *Service) *ExperimentalService {
	rs := &ExperimentalService{s: s}
	rs.Jobs = NewExperimentalJobsService(s)
	return rs
}

type ExperimentalService struct {
	s *Service

	Jobs *ExperimentalJobsService
}

func NewExperimentalJobsService(s *Service) *ExperimentalJobsService {
	rs := &ExperimentalJobsService{s: s}
	return rs
}

type ExperimentalJobsService struct {
	s *Service
}

func NewJobsService(s *Service) *JobsService {
	rs := &JobsService{s: s}
	return rs
}

type JobsService struct {
	s *Service
}

func NewReadgroupsetsService(s *Service) *ReadgroupsetsService {
	rs := &ReadgroupsetsService{s: s}
	rs.Coveragebuckets = NewReadgroupsetsCoveragebucketsService(s)
	return rs
}

type ReadgroupsetsService struct {
	s *Service

	Coveragebuckets *ReadgroupsetsCoveragebucketsService
}

func NewReadgroupsetsCoveragebucketsService(s *Service) *ReadgroupsetsCoveragebucketsService {
	rs := &ReadgroupsetsCoveragebucketsService{s: s}
	return rs
}

type ReadgroupsetsCoveragebucketsService struct {
	s *Service
}

func NewReadsService(s *Service) *ReadsService {
	rs := &ReadsService{s: s}
	return rs
}

type ReadsService struct {
	s *Service
}

func NewReferencesService(s *Service) *ReferencesService {
	rs := &ReferencesService{s: s}
	rs.Bases = NewReferencesBasesService(s)
	return rs
}

type ReferencesService struct {
	s *Service

	Bases *ReferencesBasesService
}

func NewReferencesBasesService(s *Service) *ReferencesBasesService {
	rs := &ReferencesBasesService{s: s}
	return rs
}

type ReferencesBasesService struct {
	s *Service
}

func NewReferencesetsService(s *Service) *ReferencesetsService {
	rs := &ReferencesetsService{s: s}
	return rs
}

type ReferencesetsService struct {
	s *Service
}

func NewVariantsService(s *Service) *VariantsService {
	rs := &VariantsService{s: s}
	return rs
}

type VariantsService struct {
	s *Service
}

func NewVariantsetsService(s *Service) *VariantsetsService {
	rs := &VariantsetsService{s: s}
	return rs
}

type VariantsetsService struct {
	s *Service
}

// AlignReadGroupSetsRequest: The read group set align request.
type AlignReadGroupSetsRequest struct {
	// BamSourceUris: The BAM source files for alignment. Exactly one of
	// readGroupSetId, bamSourceUris, interleavedFastqSource or
	// pairedFastqSource must be provided. The caller must have READ
	// permissions for these files.
	BamSourceUris []string `json:"bamSourceUris,omitempty"`

	// DatasetId: Required. The ID of the dataset the newly aligned read
	// group sets will belong to. The caller must have WRITE permissions to
	// this dataset.
	DatasetId string `json:"datasetId,omitempty"`

	// InterleavedFastqSource: The interleaved FASTQ source files for
	// alignment, where both members of each pair of reads are found on
	// consecutive records within the same FASTQ file. Exactly one of
	// readGroupSetId, bamSourceUris, interleavedFastqSource or
	// pairedFastqSource must be provided.
	InterleavedFastqSource *InterleavedFastqSource `json:"interleavedFastqSource,omitempty"`

	// PairedFastqSource: The paired end FASTQ source files for alignment,
	// where each member of a pair of reads are found in separate files.
	// Exactly one of readGroupSetId, bamSourceUris, interleavedFastqSource
	// or pairedFastqSource must be provided.
	PairedFastqSource *PairedFastqSource `json:"pairedFastqSource,omitempty"`

	// ReadGroupSetId: The ID of the read group set which will be aligned. A
	// new read group set will be generated to hold the aligned data, the
	// originals will not be modified. The caller must have READ permissions
	// for this read group set. Exactly one of readGroupSetId,
	// bamSourceUris, interleavedFastqSource or pairedFastqSource must be
	// provided.
	ReadGroupSetId string `json:"readGroupSetId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "BamSourceUris") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AlignReadGroupSetsRequest) MarshalJSON() ([]byte, error) {
	type noMethod AlignReadGroupSetsRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// AlignReadGroupSetsResponse: The read group set align response.
type AlignReadGroupSetsResponse struct {
	// JobId: A job ID that can be used to get status information.
	JobId string `json:"jobId,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "JobId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AlignReadGroupSetsResponse) MarshalJSON() ([]byte, error) {
	type noMethod AlignReadGroupSetsResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Annotation: An annotation describes a region of reference genome. The
// value of an annotation may be one of several canonical types,
// supplemented by arbitrary info tags. A variant annotation is
// represented by one or more of these canonical types. An annotation is
// not inherently associated with a specific sample or individual
// (though a client could choose to use annotations in this way).
// Example canonical annotation types are 'Gene' and 'Variant'.
type Annotation struct {
	// AnnotationSetId: The ID of the containing annotation set.
	AnnotationSetId string `json:"annotationSetId,omitempty"`

	// Id: The generated unique ID for this annotation.
	Id string `json:"id,omitempty"`

	// Info: A string which maps to an array of values.
	Info map[string][]string `json:"info,omitempty"`

	// Name: The display name of this annotation.
	Name string `json:"name,omitempty"`

	// Position: The position of this annotation on the reference sequence.
	Position *RangePosition `json:"position,omitempty"`

	// Transcript: A transcript value represents the assertion that a
	// particular region of the reference genome may be transcribed as RNA.
	// An alternative splicing pattern would be represented as a separate
	// transcript object. This field is only set for annotations of type
	// TRANSCRIPT.
	Transcript *Transcript `json:"transcript,omitempty"`

	// Type: The data type for this annotation. Must match the containing
	// annotation set's type.
	//
	// Possible values:
	//   "GENE"
	//   "GENERIC"
	//   "TRANSCRIPT"
	//   "VARIANT"
	Type string `json:"type,omitempty"`

	// Variant: A variant annotation, which describes the effect of a
	// variant on the genome, the coding sequence, and/or higher level
	// consequences at the organism level e.g. pathogenicity. This field is
	// only set for annotations of type VARIANT.
	Variant *VariantAnnotation `json:"variant,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "AnnotationSetId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Annotation) MarshalJSON() ([]byte, error) {
	type noMethod Annotation
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// AnnotationSet: An annotation set is a logical grouping of annotations
// that share consistent type information and provenance. Examples of
// annotation sets include 'all genes from refseq', and 'all variant
// annotations from ClinVar'.
type AnnotationSet struct {
	// DatasetId: The ID of the containing dataset.
	DatasetId string `json:"datasetId,omitempty"`

	// Id: The generated unique ID for this annotation set.
	Id string `json:"id,omitempty"`

	// Info: A string which maps to an array of values.
	Info map[string][]string `json:"info,omitempty"`

	// Name: The display name for this annotation set.
	Name string `json:"name,omitempty"`

	// ReferenceSetId: The ID of the reference set that defines the
	// coordinate space for this set's annotations.
	ReferenceSetId string `json:"referenceSetId,omitempty"`

	// SourceUri: The source URI describing the file from which this
	// annotation set was generated, if any.
	SourceUri string `json:"sourceUri,omitempty"`

	// Type: The type of annotations contained within this set.
	//
	// Possible values:
	//   "GENE"
	//   "GENERIC"
	//   "TRANSCRIPT"
	//   "VARIANT"
	Type string `json:"type,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "DatasetId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *AnnotationSet) MarshalJSON() ([]byte, error) {
	type noMethod AnnotationSet
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type BatchAnnotationsResponse struct {
	// Entries: The resulting per-annotation entries, ordered consistently
	// with the original request.
	Entries []*BatchAnnotationsResponseEntry `json:"entries,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Entries") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *BatchAnnotationsResponse) MarshalJSON() ([]byte, error) {
	type noMethod BatchAnnotationsResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type BatchAnnotationsResponseEntry struct {
	// Annotation: The annotation, if any.
	Annotation *Annotation `json:"annotation,omitempty"`

	// Status: The resulting status for this annotation operation.
	Status *BatchAnnotationsResponseEntryStatus `json:"status,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Annotation") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *BatchAnnotationsResponseEntry) MarshalJSON() ([]byte, error) {
	type noMethod BatchAnnotationsResponseEntry
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type BatchAnnotationsResponseEntryStatus struct {
	// Code: The HTTP status code for this operation.
	Code int64 `json:"code,omitempty"`

	// Message: Error message for this status, if any.
	Message string `json:"message,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Code") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *BatchAnnotationsResponseEntryStatus) MarshalJSON() ([]byte, error) {
	type noMethod BatchAnnotationsResponseEntryStatus
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type BatchCreateAnnotationsRequest struct {
	// Annotations: The annotations to be created. At most 4096 can be
	// specified in a single request.
	Annotations []*Annotation `json:"annotations,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Annotations") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *BatchCreateAnnotationsRequest) MarshalJSON() ([]byte, error) {
	type noMethod BatchCreateAnnotationsRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Call: A call represents the determination of genotype with respect to
// a particular variant. It may include associated information such as
// quality and phasing. For example, a call might assign a probability
// of 0.32 to the occurrence of a SNP named rs1234 in a call set with
// the name NA12345.
type Call struct {
	// CallSetId: The ID of the call set this variant call belongs to.
	CallSetId string `json:"callSetId,omitempty"`

	// CallSetName: The name of the call set this variant call belongs to.
	CallSetName string `json:"callSetName,omitempty"`

	// Genotype: The genotype of this variant call. Each value represents
	// either the value of the referenceBases field or a 1-based index into
	// alternateBases. If a variant had a referenceBases value of T and an
	// alternateBases value of ["A", "C"], and the genotype was [2, 1], that
	// would mean the call represented the heterozygous value CA for this
	// variant. If the genotype was instead [0, 1], the represented value
	// would be TA. Ordering of the genotype values is important if the
	// phaseset is present. If a genotype is not called (that is, a . is
	// present in the GT string) -1 is returned.
	Genotype []int64 `json:"genotype,omitempty"`

	// GenotypeLikelihood: The genotype likelihoods for this variant call.
	// Each array entry represents how likely a specific genotype is for
	// this call. The value ordering is defined by the GL tag in the VCF
	// spec. If Phred-scaled genotype likelihood scores (PL) are available
	// and log10(P) genotype likelihood scores (GL) are not, PL scores are
	// converted to GL scores. If both are available, PL scores are stored
	// in info.
	GenotypeLikelihood []float64 `json:"genotypeLikelihood,omitempty"`

	// Info: A string which maps to an array of values.
	Info map[string][]string `json:"info,omitempty"`

	// Phaseset: If this field is present, this variant call's genotype
	// ordering implies the phase of the bases and is consistent with any
	// other variant calls in the same reference sequence which have the
	// same phaseset value. When importing data from VCF, if the genotype
	// data was phased but no phase set was specified this field will be set
	// to *.
	Phaseset string `json:"phaseset,omitempty"`

	// ForceSendFields is a list of field names (e.g. "CallSetId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Call) MarshalJSON() ([]byte, error) {
	type noMethod Call
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CallReadGroupSetsRequest: The read group set call request.
type CallReadGroupSetsRequest struct {
	// DatasetId: Required. The ID of the dataset the called variants will
	// belong to. The caller must have WRITE permissions to this dataset.
	DatasetId string `json:"datasetId,omitempty"`

	// ReadGroupSetId: The IDs of the read group sets which will be called.
	// The caller must have READ permissions for these read group sets. One
	// of readGroupSetId or sourceUris must be provided.
	ReadGroupSetId string `json:"readGroupSetId,omitempty"`

	// SourceUris: A list of URIs pointing at BAM files in Google Cloud
	// Storage which will be called. FASTQ files are not allowed. The caller
	// must have READ permissions for these files. One of readGroupSetId or
	// sourceUris must be provided.
	SourceUris []string `json:"sourceUris,omitempty"`

	// ForceSendFields is a list of field names (e.g. "DatasetId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *CallReadGroupSetsRequest) MarshalJSON() ([]byte, error) {
	type noMethod CallReadGroupSetsRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CallReadGroupSetsResponse: The read group set call response.
type CallReadGroupSetsResponse struct {
	// JobId: A job ID that can be used to get status information.
	JobId string `json:"jobId,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "JobId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *CallReadGroupSetsResponse) MarshalJSON() ([]byte, error) {
	type noMethod CallReadGroupSetsResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CallSet: A call set is a collection of variant calls, typically for
// one sample. It belongs to a variant set.
type CallSet struct {
	// Created: The date this call set was created in milliseconds from the
	// epoch.
	Created int64 `json:"created,omitempty,string"`

	// Id: The Google generated ID of the call set, immutable.
	Id string `json:"id,omitempty"`

	// Info: A string which maps to an array of values.
	Info map[string][]string `json:"info,omitempty"`

	// Name: The call set name.
	Name string `json:"name,omitempty"`

	// SampleId: The sample ID this call set corresponds to.
	SampleId string `json:"sampleId,omitempty"`

	// VariantSetIds: The IDs of the variant sets this call set belongs to.
	VariantSetIds []string `json:"variantSetIds,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Created") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *CallSet) MarshalJSON() ([]byte, error) {
	type noMethod CallSet
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CigarUnit: A single CIGAR operation.
type CigarUnit struct {
	// Possible values:
	//   "ALIGNMENT_MATCH"
	//   "CLIP_HARD"
	//   "CLIP_SOFT"
	//   "DELETE"
	//   "INSERT"
	//   "OPERATION_UNSPECIFIED"
	//   "PAD"
	//   "SEQUENCE_MATCH"
	//   "SEQUENCE_MISMATCH"
	//   "SKIP"
	Operation string `json:"operation,omitempty"`

	// OperationLength: The number of bases that the operation runs for.
	// Required.
	OperationLength int64 `json:"operationLength,omitempty,string"`

	// ReferenceSequence: referenceSequence is only used at mismatches
	// (SEQUENCE_MISMATCH) and deletions (DELETE). Filling this field
	// replaces SAM's MD tag. If the relevant information is not available,
	// this field is unset.
	ReferenceSequence string `json:"referenceSequence,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Operation") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *CigarUnit) MarshalJSON() ([]byte, error) {
	type noMethod CigarUnit
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// CoverageBucket: A bucket over which read coverage has been
// precomputed. A bucket corresponds to a specific range of the
// reference sequence.
type CoverageBucket struct {
	// MeanCoverage: The average number of reads which are aligned to each
	// individual reference base in this bucket.
	MeanCoverage float64 `json:"meanCoverage,omitempty"`

	// Range: The genomic coordinate range spanned by this bucket.
	Range *Range `json:"range,omitempty"`

	// ForceSendFields is a list of field names (e.g. "MeanCoverage") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *CoverageBucket) MarshalJSON() ([]byte, error) {
	type noMethod CoverageBucket
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Dataset: A Dataset is a collection of genomic data.
type Dataset struct {
	// CreateTime: The time this dataset was created, in seconds from the
	// epoch.
	CreateTime int64 `json:"createTime,omitempty,string"`

	// Id: The Google generated ID of the dataset, immutable.
	Id string `json:"id,omitempty"`

	// IsPublic: Flag indicating whether or not a dataset is publicly
	// viewable. If a dataset is not public, it inherits viewing permissions
	// from its project.
	IsPublic *bool `json:"isPublic,omitempty"`

	// Name: The dataset name.
	Name string `json:"name,omitempty"`

	// ProjectNumber: The Google Developers Console project number that this
	// dataset belongs to.
	ProjectNumber int64 `json:"projectNumber,omitempty,string"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "CreateTime") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Dataset) MarshalJSON() ([]byte, error) {
	type noMethod Dataset
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ExperimentalCreateJobRequest: The job creation request.
type ExperimentalCreateJobRequest struct {
	// Align: Specifies whether or not to run the alignment pipeline. Either
	// align or callVariants must be set.
	Align bool `json:"align,omitempty"`

	// CallVariants: Specifies whether or not to run the variant calling
	// pipeline. Either align or callVariants must be set.
	CallVariants bool `json:"callVariants,omitempty"`

	// GcsOutputPath: Specifies where to copy the results of certain
	// pipelines. This should be in the form of gs://bucket/path.
	GcsOutputPath string `json:"gcsOutputPath,omitempty"`

	// PairedSourceUris: A list of Google Cloud Storage URIs of paired end
	// .fastq files to operate upon. If specified, this represents the
	// second file of each paired .fastq file. The first file of each pair
	// should be specified in sourceUris.
	PairedSourceUris []string `json:"pairedSourceUris,omitempty"`

	// ProjectNumber: Required. The Google Cloud Project ID with which to
	// associate the request.
	ProjectNumber int64 `json:"projectNumber,omitempty,string"`

	// SourceUris: A list of Google Cloud Storage URIs of data files to
	// operate upon. These can be .bam, interleaved .fastq, or paired
	// .fastq. If specifying paired .fastq files, the first of each pair of
	// files should be listed here, and the second of each pair should be
	// listed in pairedSourceUris.
	SourceUris []string `json:"sourceUris,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Align") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ExperimentalCreateJobRequest) MarshalJSON() ([]byte, error) {
	type noMethod ExperimentalCreateJobRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ExperimentalCreateJobResponse: The job creation response.
type ExperimentalCreateJobResponse struct {
	// JobId: A job ID that can be used to get status information.
	JobId string `json:"jobId,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "JobId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ExperimentalCreateJobResponse) MarshalJSON() ([]byte, error) {
	type noMethod ExperimentalCreateJobResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ExportReadGroupSetsRequest: The read group set export request.
type ExportReadGroupSetsRequest struct {
	// ExportUri: Required. A Google Cloud Storage URI for the exported BAM
	// file. The currently authenticated user must have write access to the
	// new file. An error will be returned if the URI already contains data.
	ExportUri string `json:"exportUri,omitempty"`

	// ProjectNumber: Required. The Google Developers Console project number
	// that owns this export.
	ProjectNumber int64 `json:"projectNumber,omitempty,string"`

	// ReadGroupSetIds: Required. The IDs of the read group sets to export.
	ReadGroupSetIds []string `json:"readGroupSetIds,omitempty"`

	// ReferenceNames: The reference names to export. If this is not
	// specified, all reference sequences, including unmapped reads, are
	// exported. Use * to export only unmapped reads.
	ReferenceNames []string `json:"referenceNames,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ExportUri") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ExportReadGroupSetsRequest) MarshalJSON() ([]byte, error) {
	type noMethod ExportReadGroupSetsRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ExportReadGroupSetsResponse: The read group set export response.
type ExportReadGroupSetsResponse struct {
	// JobId: A job ID that can be used to get status information.
	JobId string `json:"jobId,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "JobId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ExportReadGroupSetsResponse) MarshalJSON() ([]byte, error) {
	type noMethod ExportReadGroupSetsResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ExportVariantSetRequest: The variant data export request.
type ExportVariantSetRequest struct {
	// BigqueryDataset: Required. The BigQuery dataset to export data to.
	// This dataset must already exist. Note that this is distinct from the
	// Genomics concept of "dataset".
	BigqueryDataset string `json:"bigqueryDataset,omitempty"`

	// BigqueryTable: Required. The BigQuery table to export data to. If the
	// table doesn't exist, it will be created. If it already exists, it
	// will be overwritten.
	BigqueryTable string `json:"bigqueryTable,omitempty"`

	// CallSetIds: If provided, only variant call information from the
	// specified call sets will be exported. By default all variant calls
	// are exported.
	CallSetIds []string `json:"callSetIds,omitempty"`

	// Format: The format for the exported data.
	//
	// Possible values:
	//   "BIGQUERY"
	Format string `json:"format,omitempty"`

	// ProjectNumber: Required. The Google Cloud project number that owns
	// the destination BigQuery dataset. The caller must have WRITE access
	// to this project. This project will also own the resulting export job.
	ProjectNumber int64 `json:"projectNumber,omitempty,string"`

	// ForceSendFields is a list of field names (e.g. "BigqueryDataset") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ExportVariantSetRequest) MarshalJSON() ([]byte, error) {
	type noMethod ExportVariantSetRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ExportVariantSetResponse: The variant data export response.
type ExportVariantSetResponse struct {
	// JobId: A job ID that can be used to get status information.
	JobId string `json:"jobId,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "JobId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ExportVariantSetResponse) MarshalJSON() ([]byte, error) {
	type noMethod ExportVariantSetResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type ExternalId struct {
	// Id: The id used by the source of this data.
	Id string `json:"id,omitempty"`

	// SourceName: The name of the source of this data.
	SourceName string `json:"sourceName,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Id") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ExternalId) MarshalJSON() ([]byte, error) {
	type noMethod ExternalId
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type FastqMetadata struct {
	// LibraryName: Optionally specifies the library name for alignment from
	// FASTQ.
	LibraryName string `json:"libraryName,omitempty"`

	// PlatformName: Optionally specifies the platform name for alignment
	// from FASTQ. For example: CAPILLARY, LS454, ILLUMINA, SOLID, HELICOS,
	// IONTORRENT, PACBIO.
	PlatformName string `json:"platformName,omitempty"`

	// PlatformUnit: Optionally specifies the platform unit for alignment
	// from FASTQ. For example: flowcell-barcode.lane for Illumina or slide
	// for SOLID.
	PlatformUnit string `json:"platformUnit,omitempty"`

	// ReadGroupName: Optionally specifies the read group name for alignment
	// from FASTQ.
	ReadGroupName string `json:"readGroupName,omitempty"`

	// SampleName: Optionally specifies the sample name for alignment from
	// FASTQ.
	SampleName string `json:"sampleName,omitempty"`

	// ForceSendFields is a list of field names (e.g. "LibraryName") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *FastqMetadata) MarshalJSON() ([]byte, error) {
	type noMethod FastqMetadata
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ImportReadGroupSetsRequest: The read group set import request.
type ImportReadGroupSetsRequest struct {
	// DatasetId: Required. The ID of the dataset these read group sets will
	// belong to. The caller must have WRITE permissions to this dataset.
	DatasetId string `json:"datasetId,omitempty"`

	// PartitionStrategy: The partition strategy describes how read groups
	// are partitioned into read group sets.
	//
	// Possible values:
	//   "MERGE_ALL"
	//   "PER_FILE_PER_SAMPLE"
	PartitionStrategy string `json:"partitionStrategy,omitempty"`

	// ReferenceSetId: The reference set to which the imported read group
	// sets are aligned to, if any. The reference names of this reference
	// set must be a superset of those found in the imported file headers.
	// If no reference set id is provided, a best effort is made to
	// associate with a matching reference set.
	ReferenceSetId string `json:"referenceSetId,omitempty"`

	// SourceUris: A list of URIs pointing at BAM files in Google Cloud
	// Storage.
	SourceUris []string `json:"sourceUris,omitempty"`

	// ForceSendFields is a list of field names (e.g. "DatasetId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ImportReadGroupSetsRequest) MarshalJSON() ([]byte, error) {
	type noMethod ImportReadGroupSetsRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ImportReadGroupSetsResponse: The read group set import response.
type ImportReadGroupSetsResponse struct {
	// JobId: A job ID that can be used to get status information.
	JobId string `json:"jobId,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "JobId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ImportReadGroupSetsResponse) MarshalJSON() ([]byte, error) {
	type noMethod ImportReadGroupSetsResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ImportVariantsRequest: The variant data import request.
type ImportVariantsRequest struct {
	// Format: The format of the variant data being imported. If
	// unspecified, defaults to to "VCF".
	//
	// Possible values:
	//   "COMPLETE_GENOMICS"
	//   "VCF"
	Format string `json:"format,omitempty"`

	// NormalizeReferenceNames: Convert reference names to the canonical
	// representation. hg19 haploytypes (those reference names containing
	// "_hap") are not modified in any way. All other reference names are
	// modified according to the following rules: The reference name is
	// capitalized. The "chr" prefix is dropped for all autosomes and sex
	// chromsomes. For example "chr17" becomes "17" and "chrX" becomes "X".
	// All mitochondrial chromosomes ("chrM", "chrMT", etc) become "MT".
	NormalizeReferenceNames bool `json:"normalizeReferenceNames,omitempty"`

	// SourceUris: A list of URIs referencing variant files in Google Cloud
	// Storage. URIs can include wildcards as described here. Note that
	// recursive wildcards ('**') are not supported.
	SourceUris []string `json:"sourceUris,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Format") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ImportVariantsRequest) MarshalJSON() ([]byte, error) {
	type noMethod ImportVariantsRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ImportVariantsResponse: The variant data import response.
type ImportVariantsResponse struct {
	// JobId: A job ID that can be used to get status information.
	JobId string `json:"jobId,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "JobId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ImportVariantsResponse) MarshalJSON() ([]byte, error) {
	type noMethod ImportVariantsResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Int32Value: Wrapper message for `int32`.
//
// The JSON representation for `Int32Value` is JSON number.
type Int32Value struct {
	// Value: The int32 value.
	Value int64 `json:"value,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Value") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Int32Value) MarshalJSON() ([]byte, error) {
	type noMethod Int32Value
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// InterleavedFastqSource: Describes an interleaved FASTQ file source
// for alignment.
type InterleavedFastqSource struct {
	// Metadata: Optionally specifies the metadata to be associated with the
	// final aligned read group set.
	Metadata *FastqMetadata `json:"metadata,omitempty"`

	// SourceUris: A list of URIs pointing at interleaved FASTQ files in
	// Google Cloud Storage which will be aligned. The caller must have READ
	// permissions for these files.
	SourceUris []string `json:"sourceUris,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Metadata") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *InterleavedFastqSource) MarshalJSON() ([]byte, error) {
	type noMethod InterleavedFastqSource
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Job: A Job represents an ongoing process that can be monitored for
// status information.
type Job struct {
	// Created: The date this job was created, in milliseconds from the
	// epoch.
	Created int64 `json:"created,omitempty,string"`

	// DetailedStatus: A more detailed description of this job's current
	// status.
	DetailedStatus string `json:"detailedStatus,omitempty"`

	// Errors: Any errors that occurred during processing.
	Errors []string `json:"errors,omitempty"`

	// Id: The job ID.
	Id string `json:"id,omitempty"`

	// ImportedIds: If this Job represents an import, this field will
	// contain the IDs of the objects that were successfully imported.
	ImportedIds []string `json:"importedIds,omitempty"`

	// ProjectNumber: The Google Developers Console project number to which
	// this job belongs.
	ProjectNumber int64 `json:"projectNumber,omitempty,string"`

	// Request: A summarized representation of the original service request.
	Request *JobRequest `json:"request,omitempty"`

	// Status: The status of this job.
	//
	// Possible values:
	//   "CANCELED"
	//   "FAILURE"
	//   "NEW"
	//   "PENDING"
	//   "RUNNING"
	//   "SUCCESS"
	//   "UNKNOWN_STATUS"
	Status string `json:"status,omitempty"`

	// Warnings: Any warnings that occurred during processing.
	Warnings []string `json:"warnings,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Created") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Job) MarshalJSON() ([]byte, error) {
	type noMethod Job
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// JobRequest: A summary representation of the service request that
// spawned the job.
type JobRequest struct {
	// Destination: The data destination of the request, for example, a
	// Google BigQuery Table or Dataset ID.
	Destination []string `json:"destination,omitempty"`

	// Source: The data source of the request, for example, a Google Cloud
	// Storage object path or Readset ID.
	Source []string `json:"source,omitempty"`

	// Type: The original request type.
	//
	// Possible values:
	//   "ALIGN_READSETS"
	//   "CALL_READSETS"
	//   "EXPERIMENTAL_CREATE_JOB"
	//   "EXPORT_READSETS"
	//   "EXPORT_VARIANTS"
	//   "IMPORT_READSETS"
	//   "IMPORT_VARIANTS"
	//   "UNKNOWN_TYPE"
	Type string `json:"type,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Destination") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *JobRequest) MarshalJSON() ([]byte, error) {
	type noMethod JobRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// KeyValue: Used to hold basic key value information.
type KeyValue struct {
	// Key: A string which maps to an array of values.
	Key string `json:"key,omitempty"`

	// Value: The string values.
	Value []string `json:"value,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Key") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *KeyValue) MarshalJSON() ([]byte, error) {
	type noMethod KeyValue
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// LinearAlignment: A linear alignment can be represented by one CIGAR
// string. Describes the mapped position and local alignment of the read
// to the reference.
type LinearAlignment struct {
	// Cigar: Represents the local alignment of this sequence (alignment
	// matches, indels, etc) against the reference.
	Cigar []*CigarUnit `json:"cigar,omitempty"`

	// MappingQuality: The mapping quality of this alignment. Represents how
	// likely the read maps to this position as opposed to other locations.
	MappingQuality int64 `json:"mappingQuality,omitempty"`

	// Position: The position of this alignment.
	Position *Position `json:"position,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Cigar") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *LinearAlignment) MarshalJSON() ([]byte, error) {
	type noMethod LinearAlignment
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type ListBasesResponse struct {
	// NextPageToken: The continuation token, which is used to page through
	// large result sets. Provide this value in a subsequent request to
	// return the next page of results. This field will be empty if there
	// aren't any additional results.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// Offset: The offset position (0-based) of the given sequence from the
	// start of this Reference. This value will differ for each page in a
	// paginated request.
	Offset int64 `json:"offset,omitempty,string"`

	// Sequence: A substring of the bases that make up this reference.
	Sequence string `json:"sequence,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "NextPageToken") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ListBasesResponse) MarshalJSON() ([]byte, error) {
	type noMethod ListBasesResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type ListCoverageBucketsResponse struct {
	// BucketWidth: The length of each coverage bucket in base pairs. Note
	// that buckets at the end of a reference sequence may be shorter. This
	// value is omitted if the bucket width is infinity (the default
	// behaviour, with no range or targetBucketWidth).
	BucketWidth int64 `json:"bucketWidth,omitempty,string"`

	// CoverageBuckets: The coverage buckets. The list of buckets is sparse;
	// a bucket with 0 overlapping reads is not returned. A bucket never
	// crosses more than one reference sequence. Each bucket has width
	// bucketWidth, unless its end is the end of the reference sequence.
	CoverageBuckets []*CoverageBucket `json:"coverageBuckets,omitempty"`

	// NextPageToken: The continuation token, which is used to page through
	// large result sets. Provide this value in a subsequent request to
	// return the next page of results. This field will be empty if there
	// aren't any additional results.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "BucketWidth") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ListCoverageBucketsResponse) MarshalJSON() ([]byte, error) {
	type noMethod ListCoverageBucketsResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ListDatasetsResponse: The dataset list response.
type ListDatasetsResponse struct {
	// Datasets: The list of matching Datasets.
	Datasets []*Dataset `json:"datasets,omitempty"`

	// NextPageToken: The continuation token, which is used to page through
	// large result sets. Provide this value in a subsequent request to
	// return the next page of results. This field will be empty if there
	// aren't any additional results.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Datasets") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ListDatasetsResponse) MarshalJSON() ([]byte, error) {
	type noMethod ListDatasetsResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type MergeVariantsRequest struct {
	// Variants: The variants to be merged with existing variants.
	Variants []*Variant `json:"variants,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Variants") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *MergeVariantsRequest) MarshalJSON() ([]byte, error) {
	type noMethod MergeVariantsRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Metadata: Metadata describes a single piece of variant call metadata.
// These data include a top level key and either a single value string
// (value) or a list of key-value pairs (info.) Value and info are
// mutually exclusive.
type Metadata struct {
	// Description: A textual description of this metadata.
	Description string `json:"description,omitempty"`

	// Id: User-provided ID field, not enforced by this API. Two or more
	// pieces of structured metadata with identical id and key fields are
	// considered equivalent.
	Id string `json:"id,omitempty"`

	// Info: A string which maps to an array of values.
	Info map[string][]string `json:"info,omitempty"`

	// Key: The top-level key.
	Key string `json:"key,omitempty"`

	// Number: The number of values that can be included in a field
	// described by this metadata.
	Number string `json:"number,omitempty"`

	// Type: The type of data. Possible types include: Integer, Float, Flag,
	// Character, and String.
	//
	// Possible values:
	//   "CHARACTER"
	//   "FLAG"
	//   "FLOAT"
	//   "INTEGER"
	//   "STRING"
	//   "UNKNOWN_TYPE"
	Type string `json:"type,omitempty"`

	// Value: The value field for simple metadata
	Value string `json:"value,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Description") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Metadata) MarshalJSON() ([]byte, error) {
	type noMethod Metadata
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// PairedFastqSource: Describes a paired-end FASTQ file source for
// alignment.
type PairedFastqSource struct {
	// FirstSourceUris: A list of URIs pointing at paired end FASTQ files in
	// Google Cloud Storage which will be aligned. The first of each paired
	// file should be specified here, in an order that matches the second of
	// each paired file specified in secondSourceUris. For example:
	// firstSourceUris: [file1_1.fq, file2_1.fq], secondSourceUris:
	// [file1_2.fq, file2_2.fq]. The caller must have READ permissions for
	// these files.
	FirstSourceUris []string `json:"firstSourceUris,omitempty"`

	// Metadata: Optionally specifies the metadata to be associated with the
	// final aligned read group set.
	Metadata *FastqMetadata `json:"metadata,omitempty"`

	// SecondSourceUris: A list of URIs pointing at paired end FASTQ files
	// in Google Cloud Storage which will be aligned. The second of each
	// paired file should be specified here, in an order that matches the
	// first of each paired file specified in firstSourceUris. For example:
	// firstSourceUris: [file1_1.fq, file2_1.fq], secondSourceUris:
	// [file1_2.fq, file2_2.fq]. The caller must have READ permissions for
	// these files.
	SecondSourceUris []string `json:"secondSourceUris,omitempty"`

	// ForceSendFields is a list of field names (e.g. "FirstSourceUris") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *PairedFastqSource) MarshalJSON() ([]byte, error) {
	type noMethod PairedFastqSource
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Position: An abstraction for referring to a genomic position, in
// relation to some already known reference. For now, represents a
// genomic position as a reference name, a base number on that reference
// (0-based), and a determination of forward or reverse strand.
type Position struct {
	// Position: The 0-based offset from the start of the forward strand for
	// that reference.
	Position int64 `json:"position,omitempty,string"`

	// ReferenceName: The name of the reference in whatever reference set is
	// being used.
	ReferenceName string `json:"referenceName,omitempty"`

	// ReverseStrand: Whether this position is on the reverse strand, as
	// opposed to the forward strand.
	ReverseStrand bool `json:"reverseStrand,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Position") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Position) MarshalJSON() ([]byte, error) {
	type noMethod Position
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// QueryRange: A 0-based half-open genomic coordinate range for search
// requests.
type QueryRange struct {
	// End: The end position of the range on the reference, 0-based
	// exclusive. If specified, referenceId or referenceName must also be
	// specified. If unset or 0, defaults to the length of the reference.
	End int64 `json:"end,omitempty,string"`

	// ReferenceId: The ID of the reference to query. At most one of
	// referenceId and referenceName should be specified.
	ReferenceId string `json:"referenceId,omitempty"`

	// ReferenceName: The name of the reference to query, within the
	// reference set associated with this query. At most one of referenceId
	// and referenceName pshould be specified.
	ReferenceName string `json:"referenceName,omitempty"`

	// Start: The start position of the range on the reference, 0-based
	// inclusive. If specified, referenceId or referenceName must also be
	// specified. Defaults to 0.
	Start int64 `json:"start,omitempty,string"`

	// ForceSendFields is a list of field names (e.g. "End") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *QueryRange) MarshalJSON() ([]byte, error) {
	type noMethod QueryRange
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Range: A 0-based half-open genomic coordinate range over a reference
// sequence.
type Range struct {
	// End: The end position of the range on the reference, 0-based
	// exclusive. If specified, referenceName must also be specified.
	End int64 `json:"end,omitempty,string"`

	// ReferenceName: The reference sequence name, for example chr1, 1, or
	// chrX.
	ReferenceName string `json:"referenceName,omitempty"`

	// Start: The start position of the range on the reference, 0-based
	// inclusive. If specified, referenceName must also be specified.
	Start int64 `json:"start,omitempty,string"`

	// ForceSendFields is a list of field names (e.g. "End") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Range) MarshalJSON() ([]byte, error) {
	type noMethod Range
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// RangePosition: A 0-based half-open genomic coordinate range over a
// reference sequence, for representing the position of a genomic
// resource.
type RangePosition struct {
	// End: The end position of the range on the reference, 0-based
	// exclusive.
	End int64 `json:"end,omitempty,string"`

	// ReferenceId: The ID of the Google Genomics reference associated with
	// this range.
	ReferenceId string `json:"referenceId,omitempty"`

	// ReferenceName: The display name corresponding to the reference
	// specified by referenceId, for example chr1, 1, or chrX.
	ReferenceName string `json:"referenceName,omitempty"`

	// ReverseStrand: Whether this range refers to the reverse strand, as
	// opposed to the forward strand. Note that regardless of this field,
	// the start/end position of the range always refer to the forward
	// strand.
	ReverseStrand bool `json:"reverseStrand,omitempty"`

	// Start: The start position of the range on the reference, 0-based
	// inclusive.
	Start int64 `json:"start,omitempty,string"`

	// ForceSendFields is a list of field names (e.g. "End") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *RangePosition) MarshalJSON() ([]byte, error) {
	type noMethod RangePosition
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Read: A read alignment describes a linear alignment of a string of
// DNA to a reference sequence, in addition to metadata about the
// fragment (the molecule of DNA sequenced) and the read (the bases
// which were read by the sequencer). A read is equivalent to a line in
// a SAM file. A read belongs to exactly one read group and exactly one
// read group set. Generating a reference-aligned sequence string When
// interacting with mapped reads, it's often useful to produce a string
// representing the local alignment of the read to reference. The
// following pseudocode demonstrates one way of doing this:
// out = "" offset = 0 for c in read.alignment.cigar { switch
// c.operation { case "ALIGNMENT_MATCH", "SEQUENCE_MATCH",
// "SEQUENCE_MISMATCH": out +=
// read.alignedSequence[offset:offset+c.operationLength] offset +=
// c.operationLength break case "CLIP_SOFT", "INSERT": offset +=
// c.operationLength break case "PAD": out += repeat("*",
// c.operationLength) break case "DELETE": out += repeat("-",
// c.operationLength) break case "SKIP": out += repeat(" ",
// c.operationLength) break case "CLIP_HARD": break } } return
// out
// Converting to SAM's CIGAR string The following pseudocode generates a
// SAM CIGAR string from the cigar field. Note that this is a lossy
// conversion (cigar.referenceSequence is lost).
// cigarMap = { "ALIGNMENT_MATCH": "M", "INSERT": "I", "DELETE": "D",
// "SKIP": "N", "CLIP_SOFT": "S", "CLIP_HARD": "H", "PAD": "P",
// "SEQUENCE_MATCH": "=", "SEQUENCE_MISMATCH": "X", } cigarStr = "" for
// c in read.alignment.cigar { cigarStr += c.operationLength +
// cigarMap[c.operation] } return cigarStr
type Read struct {
	// AlignedQuality: The quality of the read sequence contained in this
	// alignment record. alignedSequence and alignedQuality may be shorter
	// than the full read sequence and quality. This will occur if the
	// alignment is part of a chimeric alignment, or if the read was
	// trimmed. When this occurs, the CIGAR for this read will begin/end
	// with a hard clip operator that will indicate the length of the
	// excised sequence.
	AlignedQuality []int64 `json:"alignedQuality,omitempty"`

	// AlignedSequence: The bases of the read sequence contained in this
	// alignment record, without CIGAR operations applied. alignedSequence
	// and alignedQuality may be shorter than the full read sequence and
	// quality. This will occur if the alignment is part of a chimeric
	// alignment, or if the read was trimmed. When this occurs, the CIGAR
	// for this read will begin/end with a hard clip operator that will
	// indicate the length of the excised sequence.
	AlignedSequence string `json:"alignedSequence,omitempty"`

	// Alignment: The linear alignment for this alignment record. This field
	// will be unset if the read is unmapped.
	Alignment *LinearAlignment `json:"alignment,omitempty"`

	// DuplicateFragment: The fragment is a PCR or optical duplicate (SAM
	// flag 0x400)
	DuplicateFragment bool `json:"duplicateFragment,omitempty"`

	// FailedVendorQualityChecks: SAM flag 0x200
	FailedVendorQualityChecks bool `json:"failedVendorQualityChecks,omitempty"`

	// FragmentLength: The observed length of the fragment, equivalent to
	// TLEN in SAM.
	FragmentLength int64 `json:"fragmentLength,omitempty"`

	// FragmentName: The fragment name. Equivalent to QNAME (query template
	// name) in SAM.
	FragmentName string `json:"fragmentName,omitempty"`

	// Id: The unique ID for this read. This is a generated unique ID, not
	// to be confused with fragmentName.
	Id string `json:"id,omitempty"`

	// Info: A string which maps to an array of values.
	Info map[string][]string `json:"info,omitempty"`

	// NextMatePosition: The position of the primary alignment of the
	// (readNumber+1)%numberReads read in the fragment. It replaces mate
	// position and mate strand in SAM. This field will be unset if that
	// read is unmapped or if the fragment only has a single read.
	NextMatePosition *Position `json:"nextMatePosition,omitempty"`

	// NumberReads: The number of reads in the fragment (extension to SAM
	// flag 0x1).
	NumberReads int64 `json:"numberReads,omitempty"`

	// ProperPlacement: The orientation and the distance between reads from
	// the fragment are consistent with the sequencing protocol (SAM flag
	// 0x2)
	ProperPlacement bool `json:"properPlacement,omitempty"`

	// ReadGroupId: The ID of the read group this read belongs to. (Every
	// read must belong to exactly one read group.)
	ReadGroupId string `json:"readGroupId,omitempty"`

	// ReadGroupSetId: The ID of the read group set this read belongs to.
	// (Every read must belong to exactly one read group set.)
	ReadGroupSetId string `json:"readGroupSetId,omitempty"`

	// ReadNumber: The read number in sequencing. 0-based and less than
	// numberReads. This field replaces SAM flag 0x40 and 0x80.
	ReadNumber int64 `json:"readNumber,omitempty"`

	// SecondaryAlignment: Whether this alignment is secondary. Equivalent
	// to SAM flag 0x100. A secondary alignment represents an alternative to
	// the primary alignment for this read. Aligners may return secondary
	// alignments if a read can map ambiguously to multiple coordinates in
	// the genome. By convention, each read has one and only one alignment
	// where both secondaryAlignment and supplementaryAlignment are false.
	SecondaryAlignment bool `json:"secondaryAlignment,omitempty"`

	// SupplementaryAlignment: Whether this alignment is supplementary.
	// Equivalent to SAM flag 0x800. Supplementary alignments are used in
	// the representation of a chimeric alignment. In a chimeric alignment,
	// a read is split into multiple linear alignments that map to different
	// reference contigs. The first linear alignment in the read will be
	// designated as the representative alignment; the remaining linear
	// alignments will be designated as supplementary alignments. These
	// alignments may have different mapping quality scores. In each linear
	// alignment in a chimeric alignment, the read will be hard clipped. The
	// alignedSequence and alignedQuality fields in the alignment record
	// will only represent the bases for its respective linear alignment.
	SupplementaryAlignment bool `json:"supplementaryAlignment,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AlignedQuality") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Read) MarshalJSON() ([]byte, error) {
	type noMethod Read
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ReadGroup: A read group is all the data that's processed the same way
// by the sequencer.
type ReadGroup struct {
	// DatasetId: The ID of the dataset this read group belongs to.
	DatasetId string `json:"datasetId,omitempty"`

	// Description: A free-form text description of this read group.
	Description string `json:"description,omitempty"`

	// Experiment: The experiment used to generate this read group.
	Experiment *ReadGroupExperiment `json:"experiment,omitempty"`

	// Id: The generated unique read group ID. Note: This is different than
	// the @RG ID field in the SAM spec. For that value, see the name field.
	Id string `json:"id,omitempty"`

	// Info: A string which maps to an array of values.
	Info map[string][]string `json:"info,omitempty"`

	// Name: The read group name. This corresponds to the @RG ID field in
	// the SAM spec.
	Name string `json:"name,omitempty"`

	// PredictedInsertSize: The predicted insert size of this read group.
	// The insert size is the length the sequenced DNA fragment from
	// end-to-end, not including the adapters.
	PredictedInsertSize int64 `json:"predictedInsertSize,omitempty"`

	// Programs: The programs used to generate this read group. Programs are
	// always identical for all read groups within a read group set. For
	// this reason, only the first read group in a returned set will have
	// this field populated.
	Programs []*ReadGroupProgram `json:"programs,omitempty"`

	// ReferenceSetId: The reference set the reads in this read group are
	// aligned to. Required if there are any read alignments.
	ReferenceSetId string `json:"referenceSetId,omitempty"`

	// SampleId: The sample this read group's data was generated from. Note:
	// This is not an actual ID within this repository, but rather an
	// identifier for a sample which may be meaningful to some external
	// system.
	SampleId string `json:"sampleId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "DatasetId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ReadGroup) MarshalJSON() ([]byte, error) {
	type noMethod ReadGroup
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type ReadGroupExperiment struct {
	// InstrumentModel: The instrument model used as part of this
	// experiment. This maps to sequencing technology in BAM.
	InstrumentModel string `json:"instrumentModel,omitempty"`

	// LibraryId: The library used as part of this experiment. Note: This is
	// not an actual ID within this repository, but rather an identifier for
	// a library which may be meaningful to some external system.
	LibraryId string `json:"libraryId,omitempty"`

	// PlatformUnit: The platform unit used as part of this experiment e.g.
	// flowcell-barcode.lane for Illumina or slide for SOLiD. Corresponds to
	// the
	PlatformUnit string `json:"platformUnit,omitempty"`

	// SequencingCenter: The sequencing center used as part of this
	// experiment.
	SequencingCenter string `json:"sequencingCenter,omitempty"`

	// ForceSendFields is a list of field names (e.g. "InstrumentModel") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ReadGroupExperiment) MarshalJSON() ([]byte, error) {
	type noMethod ReadGroupExperiment
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type ReadGroupProgram struct {
	// CommandLine: The command line used to run this program.
	CommandLine string `json:"commandLine,omitempty"`

	// Id: The user specified locally unique ID of the program. Used along
	// with prevProgramId to define an ordering between programs.
	Id string `json:"id,omitempty"`

	// Name: The name of the program.
	Name string `json:"name,omitempty"`

	// PrevProgramId: The ID of the program run before this one.
	PrevProgramId string `json:"prevProgramId,omitempty"`

	// Version: The version of the program run.
	Version string `json:"version,omitempty"`

	// ForceSendFields is a list of field names (e.g. "CommandLine") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ReadGroupProgram) MarshalJSON() ([]byte, error) {
	type noMethod ReadGroupProgram
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ReadGroupSet: A read group set is a logical collection of read
// groups, which are collections of reads produced by a sequencer. A
// read group set typically models reads corresponding to one sample,
// sequenced one way, and aligned one way.
// - A read group set belongs to one dataset.
// - A read group belongs to one read group set.
// - A read belongs to one read group.
type ReadGroupSet struct {
	// DatasetId: The dataset ID.
	DatasetId string `json:"datasetId,omitempty"`

	// Filename: The filename of the original source file for this read
	// group set, if any.
	Filename string `json:"filename,omitempty"`

	// Id: The read group set ID.
	Id string `json:"id,omitempty"`

	// Info: A string which maps to an array of values.
	Info map[string][]string `json:"info,omitempty"`

	// Name: The read group set name. By default this will be initialized to
	// the sample name of the sequenced data contained in this set.
	Name string `json:"name,omitempty"`

	// ReadGroups: The read groups in this set. There are typically 1-10
	// read groups in a read group set.
	ReadGroups []*ReadGroup `json:"readGroups,omitempty"`

	// ReferenceSetId: The reference set the reads in this read group set
	// are aligned to.
	ReferenceSetId string `json:"referenceSetId,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "DatasetId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ReadGroupSet) MarshalJSON() ([]byte, error) {
	type noMethod ReadGroupSet
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Reference: A reference is a canonical assembled DNA sequence,
// intended to act as a reference coordinate space for other genomic
// annotations. A single reference might represent the human chromosome
// 1 or mitochandrial DNA, for instance. A reference belongs to one or
// more reference sets.
type Reference struct {
	// Id: The Google generated immutable ID of the reference.
	Id string `json:"id,omitempty"`

	// Length: The length of this reference's sequence.
	Length int64 `json:"length,omitempty,string"`

	// Md5checksum: MD5 of the upper-case sequence excluding all whitespace
	// characters (this is equivalent to SQ:M5 in SAM). This value is
	// represented in lower case hexadecimal format.
	Md5checksum string `json:"md5checksum,omitempty"`

	// Name: The name of this reference, for example 22.
	Name string `json:"name,omitempty"`

	// NcbiTaxonId: ID from http://www.ncbi.nlm.nih.gov/taxonomy (e.g.
	// 9606->human) if not specified by the containing reference set.
	NcbiTaxonId int64 `json:"ncbiTaxonId,omitempty"`

	// SourceAccessions: All known corresponding accession IDs in INSDC
	// (GenBank/ENA/DDBJ) ideally with a version number, for example
	// GCF_000001405.26.
	SourceAccessions []string `json:"sourceAccessions,omitempty"`

	// SourceURI: The URI from which the sequence was obtained. Specifies a
	// FASTA format file/string with one name, sequence pair.
	SourceURI string `json:"sourceURI,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Id") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Reference) MarshalJSON() ([]byte, error) {
	type noMethod Reference
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ReferenceBound: ReferenceBound records an upper bound for the
// starting coordinate of variants in a particular reference.
type ReferenceBound struct {
	// ReferenceName: The reference the bound is associate with.
	ReferenceName string `json:"referenceName,omitempty"`

	// UpperBound: An upper bound (inclusive) on the starting coordinate of
	// any variant in the reference sequence.
	UpperBound int64 `json:"upperBound,omitempty,string"`

	// ForceSendFields is a list of field names (e.g. "ReferenceName") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ReferenceBound) MarshalJSON() ([]byte, error) {
	type noMethod ReferenceBound
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// ReferenceSet: A reference set is a set of references which typically
// comprise a reference assembly for a species, such as GRCh38 which is
// representative of the human genome. A reference set defines a common
// coordinate space for comparing reference-aligned experimental data. A
// reference set contains 1 or more references.
type ReferenceSet struct {
	// AssemblyId: Public id of this reference set, such as GRCh37.
	AssemblyId string `json:"assemblyId,omitempty"`

	// Description: Free text description of this reference set.
	Description string `json:"description,omitempty"`

	// Id: The Google generated immutable ID of the reference set.
	Id string `json:"id,omitempty"`

	// Md5checksum: Order-independent MD5 checksum which identifies this
	// reference set. The checksum is computed by sorting all lower case
	// hexidecimal string reference.md5checksum (for all reference in this
	// set) in ascending lexicographic order, concatenating, and taking the
	// MD5 of that value. The resulting value is represented in lower case
	// hexadecimal format.
	Md5checksum string `json:"md5checksum,omitempty"`

	// NcbiTaxonId: ID from http://www.ncbi.nlm.nih.gov/taxonomy (e.g.
	// 9606->human) indicating the species which this assembly is intended
	// to model. Note that contained references may specify a different
	// ncbiTaxonId, as assemblies may contain reference sequences which do
	// not belong to the modeled species, e.g. EBV in a human reference
	// genome.
	NcbiTaxonId int64 `json:"ncbiTaxonId,omitempty"`

	// ReferenceIds: The IDs of the reference objects that are part of this
	// set. Reference.md5checksum must be unique within this set.
	ReferenceIds []string `json:"referenceIds,omitempty"`

	// SourceAccessions: All known corresponding accession IDs in INSDC
	// (GenBank/ENA/DDBJ) ideally with a version number, for example
	// NC_000001.11.
	SourceAccessions []string `json:"sourceAccessions,omitempty"`

	// SourceURI: The URI from which the references were obtained.
	SourceURI string `json:"sourceURI,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "AssemblyId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *ReferenceSet) MarshalJSON() ([]byte, error) {
	type noMethod ReferenceSet
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type SearchAnnotationSetsRequest struct {
	// DatasetIds: The dataset IDs to search within. Caller must have READ
	// access to these datasets.
	DatasetIds []string `json:"datasetIds,omitempty"`

	// Name: Only return annotations sets for which a substring of the name
	// matches this string (case insensitive).
	Name string `json:"name,omitempty"`

	// PageSize: Specifies number of results to return in a single page. If
	// unspecified, it will default to 128. The maximum value is 1024.
	PageSize int64 `json:"pageSize,omitempty"`

	// PageToken: The continuation token, which is used to page through
	// large result sets. To get the next page of results, set this
	// parameter to the value of nextPageToken from the previous response.
	PageToken string `json:"pageToken,omitempty"`

	// ReferenceSetId: If specified, only annotation sets associated with
	// the given reference set are returned.
	ReferenceSetId string `json:"referenceSetId,omitempty"`

	// Types: If specified, only annotation sets that have any of these
	// types are returned.
	//
	// Possible values:
	//   "GENE"
	//   "GENERIC"
	//   "TRANSCRIPT"
	//   "VARIANT"
	Types []string `json:"types,omitempty"`

	// ForceSendFields is a list of field names (e.g. "DatasetIds") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SearchAnnotationSetsRequest) MarshalJSON() ([]byte, error) {
	type noMethod SearchAnnotationSetsRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type SearchAnnotationSetsResponse struct {
	// AnnotationSets: The matching annotation sets.
	AnnotationSets []*AnnotationSet `json:"annotationSets,omitempty"`

	// NextPageToken: The continuation token, which is used to page through
	// large result sets. Provide this value in a subsequent request to
	// return the next page of results. This field will be empty if there
	// aren't any additional results.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "AnnotationSets") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SearchAnnotationSetsResponse) MarshalJSON() ([]byte, error) {
	type noMethod SearchAnnotationSetsResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type SearchAnnotationsRequest struct {
	// AnnotationSetIds: The annotation sets to search within. The caller
	// must have READ access to these annotation sets. Required. All queried
	// annotation sets must have the same type.
	AnnotationSetIds []string `json:"annotationSetIds,omitempty"`

	// PageSize: Specifies number of results to return in a single page. If
	// unspecified, it will default to 256. The maximum value is 2048.
	PageSize int64 `json:"pageSize,omitempty"`

	// PageToken: The continuation token, which is used to page through
	// large result sets. To get the next page of results, set this
	// parameter to the value of nextPageToken from the previous response.
	PageToken string `json:"pageToken,omitempty"`

	// Range: If specified, this query matches only annotations that overlap
	// this range.
	Range *QueryRange `json:"range,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AnnotationSetIds") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SearchAnnotationsRequest) MarshalJSON() ([]byte, error) {
	type noMethod SearchAnnotationsRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type SearchAnnotationsResponse struct {
	// Annotations: The matching annotations.
	Annotations []*Annotation `json:"annotations,omitempty"`

	// NextPageToken: The continuation token, which is used to page through
	// large result sets. Provide this value in a subsequent request to
	// return the next page of results. This field will be empty if there
	// aren't any additional results.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Annotations") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SearchAnnotationsResponse) MarshalJSON() ([]byte, error) {
	type noMethod SearchAnnotationsResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// SearchCallSetsRequest: The call set search request.
type SearchCallSetsRequest struct {
	// Name: Only return call sets for which a substring of the name matches
	// this string.
	Name string `json:"name,omitempty"`

	// PageSize: The maximum number of call sets to return. If unspecified,
	// defaults to 1000.
	PageSize int64 `json:"pageSize,omitempty"`

	// PageToken: The continuation token, which is used to page through
	// large result sets. To get the next page of results, set this
	// parameter to the value of nextPageToken from the previous response.
	PageToken string `json:"pageToken,omitempty"`

	// VariantSetIds: Restrict the query to call sets within the given
	// variant sets. At least one ID must be provided.
	VariantSetIds []string `json:"variantSetIds,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Name") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SearchCallSetsRequest) MarshalJSON() ([]byte, error) {
	type noMethod SearchCallSetsRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// SearchCallSetsResponse: The call set search response.
type SearchCallSetsResponse struct {
	// CallSets: The list of matching call sets.
	CallSets []*CallSet `json:"callSets,omitempty"`

	// NextPageToken: The continuation token, which is used to page through
	// large result sets. Provide this value in a subsequent request to
	// return the next page of results. This field will be empty if there
	// aren't any additional results.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "CallSets") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SearchCallSetsResponse) MarshalJSON() ([]byte, error) {
	type noMethod SearchCallSetsResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// SearchJobsRequest: The jobs search request.
type SearchJobsRequest struct {
	// CreatedAfter: If specified, only jobs created on or after this date,
	// given in milliseconds since Unix epoch, will be returned.
	CreatedAfter int64 `json:"createdAfter,omitempty,string"`

	// CreatedBefore: If specified, only jobs created prior to this date,
	// given in milliseconds since Unix epoch, will be returned.
	CreatedBefore int64 `json:"createdBefore,omitempty,string"`

	// PageSize: Specifies the number of results to return in a single page.
	// Defaults to 128. The maximum value is 256.
	PageSize int64 `json:"pageSize,omitempty"`

	// PageToken: The continuation token which is used to page through large
	// result sets. To get the next page of results, set this parameter to
	// the value of the nextPageToken from the previous response.
	PageToken string `json:"pageToken,omitempty"`

	// ProjectNumber: Required. Only return jobs which belong to this Google
	// Developers Console project.
	ProjectNumber int64 `json:"projectNumber,omitempty,string"`

	// Status: Only return jobs which have a matching status.
	//
	// Possible values:
	//   "CANCELED"
	//   "FAILURE"
	//   "NEW"
	//   "PENDING"
	//   "RUNNING"
	//   "SUCCESS"
	//   "UNKNOWN_STATUS"
	Status []string `json:"status,omitempty"`

	// ForceSendFields is a list of field names (e.g. "CreatedAfter") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SearchJobsRequest) MarshalJSON() ([]byte, error) {
	type noMethod SearchJobsRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// SearchJobsResponse: The job search response.
type SearchJobsResponse struct {
	// Jobs: The list of jobs results, ordered newest to oldest.
	Jobs []*Job `json:"jobs,omitempty"`

	// NextPageToken: The continuation token which is used to page through
	// large result sets. Provide this value is a subsequent request to
	// return the next page of results. This field will be empty if there
	// are no more results.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Jobs") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SearchJobsResponse) MarshalJSON() ([]byte, error) {
	type noMethod SearchJobsResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// SearchReadGroupSetsRequest: The read group set search request.
type SearchReadGroupSetsRequest struct {
	// DatasetIds: Restricts this query to read group sets within the given
	// datasets. At least one ID must be provided.
	DatasetIds []string `json:"datasetIds,omitempty"`

	// Name: Only return read group sets for which a substring of the name
	// matches this string.
	Name string `json:"name,omitempty"`

	// PageSize: Specifies number of results to return in a single page. If
	// unspecified, it will default to 256. The maximum value is 1024.
	PageSize int64 `json:"pageSize,omitempty"`

	// PageToken: The continuation token, which is used to page through
	// large result sets. To get the next page of results, set this
	// parameter to the value of nextPageToken from the previous response.
	PageToken string `json:"pageToken,omitempty"`

	// ForceSendFields is a list of field names (e.g. "DatasetIds") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SearchReadGroupSetsRequest) MarshalJSON() ([]byte, error) {
	type noMethod SearchReadGroupSetsRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// SearchReadGroupSetsResponse: The read group set search response.
type SearchReadGroupSetsResponse struct {
	// NextPageToken: The continuation token, which is used to page through
	// large result sets. Provide this value in a subsequent request to
	// return the next page of results. This field will be empty if there
	// aren't any additional results.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// ReadGroupSets: The list of matching read group sets.
	ReadGroupSets []*ReadGroupSet `json:"readGroupSets,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "NextPageToken") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SearchReadGroupSetsResponse) MarshalJSON() ([]byte, error) {
	type noMethod SearchReadGroupSetsResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// SearchReadsRequest: The read search request.
type SearchReadsRequest struct {
	// End: The end position of the range on the reference, 0-based
	// exclusive. If specified, referenceName must also be specified.
	End int64 `json:"end,omitempty,string"`

	// PageSize: Specifies number of results to return in a single page. If
	// unspecified, it will default to 256. The maximum value is 2048.
	PageSize int64 `json:"pageSize,omitempty"`

	// PageToken: The continuation token, which is used to page through
	// large result sets. To get the next page of results, set this
	// parameter to the value of nextPageToken from the previous response.
	PageToken string `json:"pageToken,omitempty"`

	// ReadGroupIds: The IDs of the read groups within which to search for
	// reads. All specified read groups must belong to the same read group
	// sets. Must specify one of readGroupSetIds or readGroupIds.
	ReadGroupIds []string `json:"readGroupIds,omitempty"`

	// ReadGroupSetIds: The IDs of the read groups sets within which to
	// search for reads. All specified read group sets must be aligned
	// against a common set of reference sequences; this defines the genomic
	// coordinates for the query. Must specify one of readGroupSetIds or
	// readGroupIds.
	ReadGroupSetIds []string `json:"readGroupSetIds,omitempty"`

	// ReferenceName: The reference sequence name, for example chr1, 1, or
	// chrX. If set to *, only unmapped reads are returned.
	ReferenceName string `json:"referenceName,omitempty"`

	// Start: The start position of the range on the reference, 0-based
	// inclusive. If specified, referenceName must also be specified.
	Start int64 `json:"start,omitempty,string"`

	// ForceSendFields is a list of field names (e.g. "End") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SearchReadsRequest) MarshalJSON() ([]byte, error) {
	type noMethod SearchReadsRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// SearchReadsResponse: The read search response.
type SearchReadsResponse struct {
	// Alignments: The list of matching alignments sorted by mapped genomic
	// coordinate, if any, ascending in position within the same reference.
	// Unmapped reads, which have no position, are returned contiguously and
	// are sorted in ascending lexicographic order by fragment name.
	Alignments []*Read `json:"alignments,omitempty"`

	// NextPageToken: The continuation token, which is used to page through
	// large result sets. Provide this value in a subsequent request to
	// return the next page of results. This field will be empty if there
	// aren't any additional results.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "Alignments") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SearchReadsResponse) MarshalJSON() ([]byte, error) {
	type noMethod SearchReadsResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type SearchReferenceSetsRequest struct {
	// Accessions: If present, return references for which the accession
	// matches any of these strings. Best to give a version number, for
	// example GCF_000001405.26. If only the main accession number is given
	// then all records with that main accession will be returned, whichever
	// version. Note that different versions will have different sequences.
	Accessions []string `json:"accessions,omitempty"`

	// AssemblyId: If present, return reference sets for which a substring
	// of their assemblyId matches this string (case insensitive).
	AssemblyId string `json:"assemblyId,omitempty"`

	// Md5checksums: If present, return references for which the md5checksum
	// matches. See ReferenceSet.md5checksum for details.
	Md5checksums []string `json:"md5checksums,omitempty"`

	// PageSize: Specifies the maximum number of results to return in a
	// single page.
	PageSize int64 `json:"pageSize,omitempty"`

	// PageToken: The continuation token, which is used to page through
	// large result sets. To get the next page of results, set this
	// parameter to the value of nextPageToken from the previous response.
	PageToken string `json:"pageToken,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Accessions") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SearchReferenceSetsRequest) MarshalJSON() ([]byte, error) {
	type noMethod SearchReferenceSetsRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type SearchReferenceSetsResponse struct {
	// NextPageToken: The continuation token, which is used to page through
	// large result sets. Provide this value in a subsequent request to
	// return the next page of results. This field will be empty if there
	// aren't any additional results.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// ReferenceSets: The matching references sets.
	ReferenceSets []*ReferenceSet `json:"referenceSets,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "NextPageToken") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SearchReferenceSetsResponse) MarshalJSON() ([]byte, error) {
	type noMethod SearchReferenceSetsResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type SearchReferencesRequest struct {
	// Accessions: If present, return references for which the accession
	// matches this string. Best to give a version number, for example
	// GCF_000001405.26. If only the main accession number is given then all
	// records with that main accession will be returned, whichever version.
	// Note that different versions will have different sequences.
	Accessions []string `json:"accessions,omitempty"`

	// Md5checksums: If present, return references for which the md5checksum
	// matches. See Reference.md5checksum for construction details.
	Md5checksums []string `json:"md5checksums,omitempty"`

	// PageSize: Specifies the maximum number of results to return in a
	// single page.
	PageSize int64 `json:"pageSize,omitempty"`

	// PageToken: The continuation token, which is used to page through
	// large result sets. To get the next page of results, set this
	// parameter to the value of nextPageToken from the previous response.
	PageToken string `json:"pageToken,omitempty"`

	// ReferenceSetId: If present, return only references which belong to
	// this reference set.
	ReferenceSetId string `json:"referenceSetId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "Accessions") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SearchReferencesRequest) MarshalJSON() ([]byte, error) {
	type noMethod SearchReferencesRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type SearchReferencesResponse struct {
	// NextPageToken: The continuation token, which is used to page through
	// large result sets. Provide this value in a subsequent request to
	// return the next page of results. This field will be empty if there
	// aren't any additional results.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// References: The matching references.
	References []*Reference `json:"references,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "NextPageToken") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SearchReferencesResponse) MarshalJSON() ([]byte, error) {
	type noMethod SearchReferencesResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// SearchVariantSetsRequest: The search variant sets request.
type SearchVariantSetsRequest struct {
	// DatasetIds: Exactly one dataset ID must be provided here. Only
	// variant sets which belong to this dataset will be returned.
	DatasetIds []string `json:"datasetIds,omitempty"`

	// PageSize: The maximum number of variant sets to return in a request.
	PageSize int64 `json:"pageSize,omitempty"`

	// PageToken: The continuation token, which is used to page through
	// large result sets. To get the next page of results, set this
	// parameter to the value of nextPageToken from the previous response.
	PageToken string `json:"pageToken,omitempty"`

	// ForceSendFields is a list of field names (e.g. "DatasetIds") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SearchVariantSetsRequest) MarshalJSON() ([]byte, error) {
	type noMethod SearchVariantSetsRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// SearchVariantSetsResponse: The search variant sets response.
type SearchVariantSetsResponse struct {
	// NextPageToken: The continuation token, which is used to page through
	// large result sets. Provide this value in a subsequent request to
	// return the next page of results. This field will be empty if there
	// aren't any additional results.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// VariantSets: The variant sets belonging to the requested dataset.
	VariantSets []*VariantSet `json:"variantSets,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "NextPageToken") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SearchVariantSetsResponse) MarshalJSON() ([]byte, error) {
	type noMethod SearchVariantSetsResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// SearchVariantsRequest: The variant search request.
type SearchVariantsRequest struct {
	// CallSetIds: Only return variant calls which belong to call sets with
	// these ids. Leaving this blank returns all variant calls. If a variant
	// has no calls belonging to any of these call sets, it won't be
	// returned at all. Currently, variants with no calls from any call set
	// will never be returned.
	CallSetIds []string `json:"callSetIds,omitempty"`

	// End: The end of the window, 0-based exclusive. If unspecified or 0,
	// defaults to the length of the reference.
	End int64 `json:"end,omitempty,string"`

	// MaxCalls: The maximum number of calls to return. However, at least
	// one variant will always be returned, even if it has more calls than
	// this limit. If unspecified, defaults to 5000.
	MaxCalls int64 `json:"maxCalls,omitempty"`

	// PageSize: The maximum number of variants to return. If unspecified,
	// defaults to 5000.
	PageSize int64 `json:"pageSize,omitempty"`

	// PageToken: The continuation token, which is used to page through
	// large result sets. To get the next page of results, set this
	// parameter to the value of nextPageToken from the previous response.
	PageToken string `json:"pageToken,omitempty"`

	// ReferenceName: Required. Only return variants in this reference
	// sequence.
	ReferenceName string `json:"referenceName,omitempty"`

	// Start: The beginning of the window (0-based, inclusive) for which
	// overlapping variants should be returned. If unspecified, defaults to
	// 0.
	Start int64 `json:"start,omitempty,string"`

	// VariantName: Only return variants which have exactly this name.
	VariantName string `json:"variantName,omitempty"`

	// VariantSetIds: At most one variant set ID must be provided. Only
	// variants from this variant set will be returned. If omitted, a call
	// set id must be included in the request.
	VariantSetIds []string `json:"variantSetIds,omitempty"`

	// ForceSendFields is a list of field names (e.g. "CallSetIds") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SearchVariantsRequest) MarshalJSON() ([]byte, error) {
	type noMethod SearchVariantsRequest
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// SearchVariantsResponse: The variant search response.
type SearchVariantsResponse struct {
	// NextPageToken: The continuation token, which is used to page through
	// large result sets. Provide this value in a subsequent request to
	// return the next page of results. This field will be empty if there
	// aren't any additional results.
	NextPageToken string `json:"nextPageToken,omitempty"`

	// Variants: The list of matching Variants.
	Variants []*Variant `json:"variants,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "NextPageToken") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *SearchVariantsResponse) MarshalJSON() ([]byte, error) {
	type noMethod SearchVariantsResponse
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Transcript: A transcript represents the assertion that a particular
// region of the reference genome may be transcribed as RNA.
type Transcript struct {
	// CodingSequence: The range of the coding sequence for this transcript,
	// if any. To determine the exact ranges of coding sequence, intersect
	// this range with those of the exons, if any. If there are any exons,
	// the codingSequence must start and end within them.
	//
	// Note that in some cases, the reference genome will not exactly match
	// the observed mRNA transcript e.g. due to variance in the source
	// genome from reference. In these cases, exon.frame will not
	// necessarily match the expected reference reading frame and coding
	// exon reference bases cannot necessarily be concatenated to produce
	// the original transcript mRNA.
	CodingSequence *TranscriptCodingSequence `json:"codingSequence,omitempty"`

	// Exons: The exons that compose this transcript. This field should be
	// unset for genomes where transcript splicing does not occur, for
	// example prokaryotes.
	//
	//
	// Introns are regions of the transcript that are not included in the
	// spliced RNA product. Though not explicitly modeled here, intron
	// ranges can be deduced; all regions of this transcript that are not
	// exons are introns.
	//
	//
	// Exonic sequences do not necessarily code for a translational product
	// (amino acids). Only the regions of exons bounded by the
	// codingSequence correspond to coding DNA sequence.
	//
	//
	// Exons are ordered by start position and may not overlap.
	Exons []*TranscriptExon `json:"exons,omitempty"`

	// GeneId: The annotation ID of the gene from which this transcript is
	// transcribed.
	GeneId string `json:"geneId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "CodingSequence") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Transcript) MarshalJSON() ([]byte, error) {
	type noMethod Transcript
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type TranscriptCodingSequence struct {
	// End: The end of the coding sequence on this annotation's reference
	// sequence, 0-based exclusive. Note that this position is relative to
	// the reference start, and not the containing annotation start.
	End int64 `json:"end,omitempty,string"`

	// Start: The start of the coding sequence on this annotation's
	// reference sequence, 0-based inclusive. Note that this position is
	// relative to the reference start, and not the containing annotation
	// start.
	Start int64 `json:"start,omitempty,string"`

	// ForceSendFields is a list of field names (e.g. "End") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *TranscriptCodingSequence) MarshalJSON() ([]byte, error) {
	type noMethod TranscriptCodingSequence
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type TranscriptExon struct {
	// End: The end position of the exon on this annotation's reference
	// sequence, 0-based exclusive. Note that this is relative to the
	// reference start, and not the containing annotation start.
	End int64 `json:"end,omitempty,string"`

	// Frame: The frame of this exon. Contains a value of 0, 1, or 2, which
	// indicates the offset of the first coding base of the exon within the
	// reading frame of the coding DNA sequence, if any. This field is
	// dependent on the strandedness of this annotation (see
	// Annotation.position.reverseStrand). For forward stranded annotations,
	// this offset is relative to the exon.start. For reverse strand
	// annotations, this offset is relative to the exon.end-1.
	//
	// Unset if this exon does not intersect the coding sequence. Upon
	// creation of a transcript, the frame must be populated for all or none
	// of the coding exons.
	Frame *Int32Value `json:"frame,omitempty"`

	// Start: The start position of the exon on this annotation's reference
	// sequence, 0-based inclusive. Note that this is relative to the
	// reference start, and not the containing annotation start.
	Start int64 `json:"start,omitempty,string"`

	// ForceSendFields is a list of field names (e.g. "End") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *TranscriptExon) MarshalJSON() ([]byte, error) {
	type noMethod TranscriptExon
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// Variant: A variant represents a change in DNA sequence relative to a
// reference sequence. For example, a variant could represent a SNP or
// an insertion. Variants belong to a variant set. Each of the calls on
// a variant represent a determination of genotype with respect to that
// variant. For example, a call might assign probability of 0.32 to the
// occurrence of a SNP named rs1234 in a sample named NA12345. A call
// belongs to a call set, which contains related calls typically from
// one sample.
type Variant struct {
	// AlternateBases: The bases that appear instead of the reference bases.
	AlternateBases []string `json:"alternateBases,omitempty"`

	// Calls: The variant calls for this particular variant. Each one
	// represents the determination of genotype with respect to this
	// variant.
	Calls []*Call `json:"calls,omitempty"`

	// Created: The date this variant was created, in milliseconds from the
	// epoch.
	Created int64 `json:"created,omitempty,string"`

	// End: The end position (0-based) of this variant. This corresponds to
	// the first base after the last base in the reference allele. So, the
	// length of the reference allele is (end - start). This is useful for
	// variants that don't explicitly give alternate bases, for example
	// large deletions.
	End int64 `json:"end,omitempty,string"`

	// Filter: A list of filters (normally quality filters) this variant has
	// failed. PASS indicates this variant has passed all filters.
	Filter []string `json:"filter,omitempty"`

	// Id: The Google generated ID of the variant, immutable.
	Id string `json:"id,omitempty"`

	// Info: A string which maps to an array of values.
	Info map[string][]string `json:"info,omitempty"`

	// Names: Names for the variant, for example a RefSNP ID.
	Names []string `json:"names,omitempty"`

	// Quality: A measure of how likely this variant is to be real. A higher
	// value is better.
	Quality float64 `json:"quality,omitempty"`

	// ReferenceBases: The reference bases for this variant. They start at
	// the given position.
	ReferenceBases string `json:"referenceBases,omitempty"`

	// ReferenceName: The reference on which this variant occurs. (such as
	// chr20 or X)
	ReferenceName string `json:"referenceName,omitempty"`

	// Start: The position at which this variant occurs (0-based). This
	// corresponds to the first base of the string of reference bases.
	Start int64 `json:"start,omitempty,string"`

	// VariantSetId: The ID of the variant set this variant belongs to.
	VariantSetId string `json:"variantSetId,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "AlternateBases") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *Variant) MarshalJSON() ([]byte, error) {
	type noMethod Variant
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// VariantAnnotation: A Variant annotation.
type VariantAnnotation struct {
	// AlternateBases: The alternate allele for this variant. If multiple
	// alternate alleles exist at this location, create a separate variant
	// for each one, as they may represent distinct conditions.
	AlternateBases string `json:"alternateBases,omitempty"`

	// ClinicalSignificance: Describes the clinical significance of a
	// variant. It is adapted from the ClinVar controlled vocabulary for
	// clinical significance described at:
	// http://www.ncbi.nlm.nih.gov/clinvar/docs/clinsig/
	//
	// Possible values:
	//   "ASSOCIATION"
	//   "BENIGN"
	//   "CLINICAL_SIGNIFICANCE_UNSPECIFIED"
	//   "CONFERS_SENSITIVITY"
	//   "DRUG_RESPONSE"
	//   "HISTOCOMPATIBILITY"
	//   "LIKELY_BENIGN"
	//   "LIKELY_PATHOGENIC"
	//   "MULTIPLE_REPORTED"
	//   "OTHER"
	//   "PATHOGENIC"
	//   "PROTECTIVE"
	//   "RISK_FACTOR"
	//   "UNCERTAIN"
	ClinicalSignificance string `json:"clinicalSignificance,omitempty"`

	// Conditions: The set of conditions associated with this variant. A
	// condition describes the way a variant influences human health.
	Conditions []*VariantAnnotationCondition `json:"conditions,omitempty"`

	// Effect: Effect of the variant on the coding sequence.
	//
	// Possible values:
	//   "EFFECT_UNSPECIFIED"
	//   "FRAMESHIFT"
	//   "FRAME_PRESERVING_INDEL"
	//   "NONSYNONYMOUS_SNP"
	//   "OTHER"
	//   "SPLICE_SITE_DISRUPTION"
	//   "STOP_GAIN"
	//   "STOP_LOSS"
	//   "SYNONYMOUS_SNP"
	Effect string `json:"effect,omitempty"`

	// GeneId: Google annotation ID of the gene affected by this variant.
	// This should be provided when the variant is created.
	GeneId string `json:"geneId,omitempty"`

	// TranscriptIds: Google annotation IDs of the transcripts affected by
	// this variant. These should be provided when the variant is created.
	TranscriptIds []string `json:"transcriptIds,omitempty"`

	// Type: Type has been adapted from ClinVar's list of variant types.
	//
	// Possible values:
	//   "CNV"
	//   "DELETION"
	//   "INSERTION"
	//   "OTHER"
	//   "SNP"
	//   "STRUCTURAL"
	//   "SUBSTITUTION"
	//   "TYPE_UNSPECIFIED"
	Type string `json:"type,omitempty"`

	// ForceSendFields is a list of field names (e.g. "AlternateBases") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VariantAnnotation) MarshalJSON() ([]byte, error) {
	type noMethod VariantAnnotation
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

type VariantAnnotationCondition struct {
	// ConceptId: The MedGen concept id associated with this gene. Search
	// for these IDs at http://www.ncbi.nlm.nih.gov/medgen/
	ConceptId string `json:"conceptId,omitempty"`

	// ExternalIds: The set of external IDs for this condition.
	ExternalIds []*ExternalId `json:"externalIds,omitempty"`

	// Names: A set of names for the condition.
	Names []string `json:"names,omitempty"`

	// OmimId: The OMIM id for this condition. Search for these IDs at
	// http://omim.org/
	OmimId string `json:"omimId,omitempty"`

	// ForceSendFields is a list of field names (e.g. "ConceptId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VariantAnnotationCondition) MarshalJSON() ([]byte, error) {
	type noMethod VariantAnnotationCondition
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// VariantSet: A variant set is a collection of call sets and variants.
// It contains summary statistics of those contents. A variant set
// belongs to a dataset.
type VariantSet struct {
	// DatasetId: The dataset to which this variant set belongs. Immutable.
	DatasetId string `json:"datasetId,omitempty"`

	// Id: The Google-generated ID of the variant set. Immutable.
	Id string `json:"id,omitempty"`

	// Metadata: The metadata associated with this variant set.
	Metadata []*Metadata `json:"metadata,omitempty"`

	// ReferenceBounds: A list of all references used by the variants in a
	// variant set with associated coordinate upper bounds for each one.
	ReferenceBounds []*ReferenceBound `json:"referenceBounds,omitempty"`

	// ServerResponse contains the HTTP response code and headers from the
	// server.
	googleapi.ServerResponse `json:"-"`

	// ForceSendFields is a list of field names (e.g. "DatasetId") to
	// unconditionally include in API requests. By default, fields with
	// empty values are omitted from API requests. However, any non-pointer,
	// non-interface field appearing in ForceSendFields will be sent to the
	// server regardless of whether the field is empty or not. This may be
	// used to include empty fields in Patch requests.
	ForceSendFields []string `json:"-"`
}

func (s *VariantSet) MarshalJSON() ([]byte, error) {
	type noMethod VariantSet
	raw := noMethod(*s)
	return internal.MarshalJSON(raw, s.ForceSendFields)
}

// method id "genomics.annotationSets.create":

type AnnotationSetsCreateCall struct {
	s             *Service
	annotationset *AnnotationSet
	opt_          map[string]interface{}
	ctx_          context.Context
}

// Create: Creates a new annotation set. Caller must have WRITE
// permission for the associated dataset.
func (r *AnnotationSetsService) Create(annotationset *AnnotationSet) *AnnotationSetsCreateCall {
	c := &AnnotationSetsCreateCall{s: r.s, opt_: make(map[string]interface{})}
	c.annotationset = annotationset
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AnnotationSetsCreateCall) Fields(s ...googleapi.Field) *AnnotationSetsCreateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AnnotationSetsCreateCall) Context(ctx context.Context) *AnnotationSetsCreateCall {
	c.ctx_ = ctx
	return c
}

func (c *AnnotationSetsCreateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.annotationset)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "annotationSets")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.annotationSets.create" call.
// Exactly one of *AnnotationSet or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *AnnotationSet.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *AnnotationSetsCreateCall) Do() (*AnnotationSet, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &AnnotationSet{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Creates a new annotation set. Caller must have WRITE permission for the associated dataset.",
	//   "httpMethod": "POST",
	//   "id": "genomics.annotationSets.create",
	//   "path": "annotationSets",
	//   "request": {
	//     "$ref": "AnnotationSet"
	//   },
	//   "response": {
	//     "$ref": "AnnotationSet"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.annotationSets.delete":

type AnnotationSetsDeleteCall struct {
	s               *Service
	annotationSetId string
	opt_            map[string]interface{}
	ctx_            context.Context
}

// Delete: Deletes an annotation set. Caller must have WRITE permission
// for the associated annotation set.
func (r *AnnotationSetsService) Delete(annotationSetId string) *AnnotationSetsDeleteCall {
	c := &AnnotationSetsDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.annotationSetId = annotationSetId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AnnotationSetsDeleteCall) Fields(s ...googleapi.Field) *AnnotationSetsDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AnnotationSetsDeleteCall) Context(ctx context.Context) *AnnotationSetsDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *AnnotationSetsDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "annotationSets/{annotationSetId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"annotationSetId": c.annotationSetId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.annotationSets.delete" call.
func (c *AnnotationSetsDeleteCall) Do() error {
	res, err := c.doRequest("json")
	if err != nil {
		return err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return err
	}
	return nil
	// {
	//   "description": "Deletes an annotation set. Caller must have WRITE permission for the associated annotation set.",
	//   "httpMethod": "DELETE",
	//   "id": "genomics.annotationSets.delete",
	//   "parameterOrder": [
	//     "annotationSetId"
	//   ],
	//   "parameters": {
	//     "annotationSetId": {
	//       "description": "The ID of the annotation set to be deleted.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "annotationSets/{annotationSetId}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.annotationSets.get":

type AnnotationSetsGetCall struct {
	s               *Service
	annotationSetId string
	opt_            map[string]interface{}
	ctx_            context.Context
}

// Get: Gets an annotation set. Caller must have READ permission for the
// associated dataset.
func (r *AnnotationSetsService) Get(annotationSetId string) *AnnotationSetsGetCall {
	c := &AnnotationSetsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.annotationSetId = annotationSetId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AnnotationSetsGetCall) Fields(s ...googleapi.Field) *AnnotationSetsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *AnnotationSetsGetCall) IfNoneMatch(entityTag string) *AnnotationSetsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AnnotationSetsGetCall) Context(ctx context.Context) *AnnotationSetsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *AnnotationSetsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "annotationSets/{annotationSetId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"annotationSetId": c.annotationSetId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if v, ok := c.opt_["ifNoneMatch"]; ok {
		req.Header.Set("If-None-Match", fmt.Sprintf("%v", v))
	}
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.annotationSets.get" call.
// Exactly one of *AnnotationSet or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *AnnotationSet.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *AnnotationSetsGetCall) Do() (*AnnotationSet, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &AnnotationSet{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Gets an annotation set. Caller must have READ permission for the associated dataset.",
	//   "httpMethod": "GET",
	//   "id": "genomics.annotationSets.get",
	//   "parameterOrder": [
	//     "annotationSetId"
	//   ],
	//   "parameters": {
	//     "annotationSetId": {
	//       "description": "The ID of the annotation set to be retrieved.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "annotationSets/{annotationSetId}",
	//   "response": {
	//     "$ref": "AnnotationSet"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics",
	//     "https://www.googleapis.com/auth/genomics.readonly"
	//   ]
	// }

}

// method id "genomics.annotationSets.patch":

type AnnotationSetsPatchCall struct {
	s               *Service
	annotationSetId string
	annotationset   *AnnotationSet
	opt_            map[string]interface{}
	ctx_            context.Context
}

// Patch: Updates an annotation set. The update must respect all
// mutability restrictions and other invariants described on the
// annotation set resource. Caller must have WRITE permission for the
// associated dataset. This method supports patch semantics.
func (r *AnnotationSetsService) Patch(annotationSetId string, annotationset *AnnotationSet) *AnnotationSetsPatchCall {
	c := &AnnotationSetsPatchCall{s: r.s, opt_: make(map[string]interface{})}
	c.annotationSetId = annotationSetId
	c.annotationset = annotationset
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AnnotationSetsPatchCall) Fields(s ...googleapi.Field) *AnnotationSetsPatchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AnnotationSetsPatchCall) Context(ctx context.Context) *AnnotationSetsPatchCall {
	c.ctx_ = ctx
	return c
}

func (c *AnnotationSetsPatchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.annotationset)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "annotationSets/{annotationSetId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PATCH", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"annotationSetId": c.annotationSetId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.annotationSets.patch" call.
// Exactly one of *AnnotationSet or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *AnnotationSet.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *AnnotationSetsPatchCall) Do() (*AnnotationSet, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &AnnotationSet{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Updates an annotation set. The update must respect all mutability restrictions and other invariants described on the annotation set resource. Caller must have WRITE permission for the associated dataset. This method supports patch semantics.",
	//   "httpMethod": "PATCH",
	//   "id": "genomics.annotationSets.patch",
	//   "parameterOrder": [
	//     "annotationSetId"
	//   ],
	//   "parameters": {
	//     "annotationSetId": {
	//       "description": "The ID of the annotation set to be updated.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "annotationSets/{annotationSetId}",
	//   "request": {
	//     "$ref": "AnnotationSet"
	//   },
	//   "response": {
	//     "$ref": "AnnotationSet"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.annotationSets.search":

type AnnotationSetsSearchCall struct {
	s                           *Service
	searchannotationsetsrequest *SearchAnnotationSetsRequest
	opt_                        map[string]interface{}
	ctx_                        context.Context
}

// Search: Searches for annotation sets that match the given criteria.
// Results are returned in a deterministic order. Caller must have READ
// permission for the queried datasets.
func (r *AnnotationSetsService) Search(searchannotationsetsrequest *SearchAnnotationSetsRequest) *AnnotationSetsSearchCall {
	c := &AnnotationSetsSearchCall{s: r.s, opt_: make(map[string]interface{})}
	c.searchannotationsetsrequest = searchannotationsetsrequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AnnotationSetsSearchCall) Fields(s ...googleapi.Field) *AnnotationSetsSearchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AnnotationSetsSearchCall) Context(ctx context.Context) *AnnotationSetsSearchCall {
	c.ctx_ = ctx
	return c
}

func (c *AnnotationSetsSearchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.searchannotationsetsrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "annotationSets/search")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.annotationSets.search" call.
// Exactly one of *SearchAnnotationSetsResponse or error will be
// non-nil. Any non-2xx status code is an error. Response headers are in
// either *SearchAnnotationSetsResponse.ServerResponse.Header or (if a
// response was returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *AnnotationSetsSearchCall) Do() (*SearchAnnotationSetsResponse, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &SearchAnnotationSetsResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Searches for annotation sets that match the given criteria. Results are returned in a deterministic order. Caller must have READ permission for the queried datasets.",
	//   "httpMethod": "POST",
	//   "id": "genomics.annotationSets.search",
	//   "path": "annotationSets/search",
	//   "request": {
	//     "$ref": "SearchAnnotationSetsRequest"
	//   },
	//   "response": {
	//     "$ref": "SearchAnnotationSetsResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics",
	//     "https://www.googleapis.com/auth/genomics.readonly"
	//   ]
	// }

}

// method id "genomics.annotationSets.update":

type AnnotationSetsUpdateCall struct {
	s               *Service
	annotationSetId string
	annotationset   *AnnotationSet
	opt_            map[string]interface{}
	ctx_            context.Context
}

// Update: Updates an annotation set. The update must respect all
// mutability restrictions and other invariants described on the
// annotation set resource. Caller must have WRITE permission for the
// associated dataset.
func (r *AnnotationSetsService) Update(annotationSetId string, annotationset *AnnotationSet) *AnnotationSetsUpdateCall {
	c := &AnnotationSetsUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.annotationSetId = annotationSetId
	c.annotationset = annotationset
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AnnotationSetsUpdateCall) Fields(s ...googleapi.Field) *AnnotationSetsUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AnnotationSetsUpdateCall) Context(ctx context.Context) *AnnotationSetsUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *AnnotationSetsUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.annotationset)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "annotationSets/{annotationSetId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"annotationSetId": c.annotationSetId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.annotationSets.update" call.
// Exactly one of *AnnotationSet or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *AnnotationSet.ServerResponse.Header or (if a response was returned
// at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *AnnotationSetsUpdateCall) Do() (*AnnotationSet, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &AnnotationSet{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Updates an annotation set. The update must respect all mutability restrictions and other invariants described on the annotation set resource. Caller must have WRITE permission for the associated dataset.",
	//   "httpMethod": "PUT",
	//   "id": "genomics.annotationSets.update",
	//   "parameterOrder": [
	//     "annotationSetId"
	//   ],
	//   "parameters": {
	//     "annotationSetId": {
	//       "description": "The ID of the annotation set to be updated.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "annotationSets/{annotationSetId}",
	//   "request": {
	//     "$ref": "AnnotationSet"
	//   },
	//   "response": {
	//     "$ref": "AnnotationSet"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.annotations.batchCreate":

type AnnotationsBatchCreateCall struct {
	s                             *Service
	batchcreateannotationsrequest *BatchCreateAnnotationsRequest
	opt_                          map[string]interface{}
	ctx_                          context.Context
}

// BatchCreate: Creates one or more new annotations atomically. All
// annotations must belong to the same annotation set. Caller must have
// WRITE permission for this annotation set. For optimal performance,
// batch positionally adjacent annotations together.
//
//
// If the request has a systemic issue, such as an attempt to write to
// an inaccessible annotation set, the entire RPC will fail accordingly.
// For lesser data issues, when possible an error will be isolated to
// the corresponding batch entry in the response; the remaining well
// formed annotations will be created normally.
func (r *AnnotationsService) BatchCreate(batchcreateannotationsrequest *BatchCreateAnnotationsRequest) *AnnotationsBatchCreateCall {
	c := &AnnotationsBatchCreateCall{s: r.s, opt_: make(map[string]interface{})}
	c.batchcreateannotationsrequest = batchcreateannotationsrequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AnnotationsBatchCreateCall) Fields(s ...googleapi.Field) *AnnotationsBatchCreateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AnnotationsBatchCreateCall) Context(ctx context.Context) *AnnotationsBatchCreateCall {
	c.ctx_ = ctx
	return c
}

func (c *AnnotationsBatchCreateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.batchcreateannotationsrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "annotations:batchCreate")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.annotations.batchCreate" call.
// Exactly one of *BatchAnnotationsResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *BatchAnnotationsResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *AnnotationsBatchCreateCall) Do() (*BatchAnnotationsResponse, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &BatchAnnotationsResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Creates one or more new annotations atomically. All annotations must belong to the same annotation set. Caller must have WRITE permission for this annotation set. For optimal performance, batch positionally adjacent annotations together.\n\n\nIf the request has a systemic issue, such as an attempt to write to an inaccessible annotation set, the entire RPC will fail accordingly. For lesser data issues, when possible an error will be isolated to the corresponding batch entry in the response; the remaining well formed annotations will be created normally.",
	//   "httpMethod": "POST",
	//   "id": "genomics.annotations.batchCreate",
	//   "path": "annotations:batchCreate",
	//   "request": {
	//     "$ref": "BatchCreateAnnotationsRequest"
	//   },
	//   "response": {
	//     "$ref": "BatchAnnotationsResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.annotations.create":

type AnnotationsCreateCall struct {
	s          *Service
	annotation *Annotation
	opt_       map[string]interface{}
	ctx_       context.Context
}

// Create: Creates a new annotation. Caller must have WRITE permission
// for the associated annotation set.
func (r *AnnotationsService) Create(annotation *Annotation) *AnnotationsCreateCall {
	c := &AnnotationsCreateCall{s: r.s, opt_: make(map[string]interface{})}
	c.annotation = annotation
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AnnotationsCreateCall) Fields(s ...googleapi.Field) *AnnotationsCreateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AnnotationsCreateCall) Context(ctx context.Context) *AnnotationsCreateCall {
	c.ctx_ = ctx
	return c
}

func (c *AnnotationsCreateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.annotation)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "annotations")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.annotations.create" call.
// Exactly one of *Annotation or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *Annotation.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *AnnotationsCreateCall) Do() (*Annotation, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &Annotation{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Creates a new annotation. Caller must have WRITE permission for the associated annotation set.",
	//   "httpMethod": "POST",
	//   "id": "genomics.annotations.create",
	//   "path": "annotations",
	//   "request": {
	//     "$ref": "Annotation"
	//   },
	//   "response": {
	//     "$ref": "Annotation"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.annotations.delete":

type AnnotationsDeleteCall struct {
	s            *Service
	annotationId string
	opt_         map[string]interface{}
	ctx_         context.Context
}

// Delete: Deletes an annotation. Caller must have WRITE permission for
// the associated annotation set.
func (r *AnnotationsService) Delete(annotationId string) *AnnotationsDeleteCall {
	c := &AnnotationsDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.annotationId = annotationId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AnnotationsDeleteCall) Fields(s ...googleapi.Field) *AnnotationsDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AnnotationsDeleteCall) Context(ctx context.Context) *AnnotationsDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *AnnotationsDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "annotations/{annotationId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"annotationId": c.annotationId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.annotations.delete" call.
func (c *AnnotationsDeleteCall) Do() error {
	res, err := c.doRequest("json")
	if err != nil {
		return err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return err
	}
	return nil
	// {
	//   "description": "Deletes an annotation. Caller must have WRITE permission for the associated annotation set.",
	//   "httpMethod": "DELETE",
	//   "id": "genomics.annotations.delete",
	//   "parameterOrder": [
	//     "annotationId"
	//   ],
	//   "parameters": {
	//     "annotationId": {
	//       "description": "The ID of the annotation set to be deleted.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "annotations/{annotationId}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.annotations.get":

type AnnotationsGetCall struct {
	s            *Service
	annotationId string
	opt_         map[string]interface{}
	ctx_         context.Context
}

// Get: Gets an annotation. Caller must have READ permission for the
// associated annotation set.
func (r *AnnotationsService) Get(annotationId string) *AnnotationsGetCall {
	c := &AnnotationsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.annotationId = annotationId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AnnotationsGetCall) Fields(s ...googleapi.Field) *AnnotationsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *AnnotationsGetCall) IfNoneMatch(entityTag string) *AnnotationsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AnnotationsGetCall) Context(ctx context.Context) *AnnotationsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *AnnotationsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "annotations/{annotationId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"annotationId": c.annotationId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if v, ok := c.opt_["ifNoneMatch"]; ok {
		req.Header.Set("If-None-Match", fmt.Sprintf("%v", v))
	}
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.annotations.get" call.
// Exactly one of *Annotation or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *Annotation.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *AnnotationsGetCall) Do() (*Annotation, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &Annotation{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Gets an annotation. Caller must have READ permission for the associated annotation set.",
	//   "httpMethod": "GET",
	//   "id": "genomics.annotations.get",
	//   "parameterOrder": [
	//     "annotationId"
	//   ],
	//   "parameters": {
	//     "annotationId": {
	//       "description": "The ID of the annotation set to be retrieved.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "annotations/{annotationId}",
	//   "response": {
	//     "$ref": "Annotation"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics",
	//     "https://www.googleapis.com/auth/genomics.readonly"
	//   ]
	// }

}

// method id "genomics.annotations.patch":

type AnnotationsPatchCall struct {
	s            *Service
	annotationId string
	annotation   *Annotation
	opt_         map[string]interface{}
	ctx_         context.Context
}

// Patch: Updates an annotation. The update must respect all mutability
// restrictions and other invariants described on the annotation
// resource. Caller must have WRITE permission for the associated
// dataset. This method supports patch semantics.
func (r *AnnotationsService) Patch(annotationId string, annotation *Annotation) *AnnotationsPatchCall {
	c := &AnnotationsPatchCall{s: r.s, opt_: make(map[string]interface{})}
	c.annotationId = annotationId
	c.annotation = annotation
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AnnotationsPatchCall) Fields(s ...googleapi.Field) *AnnotationsPatchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AnnotationsPatchCall) Context(ctx context.Context) *AnnotationsPatchCall {
	c.ctx_ = ctx
	return c
}

func (c *AnnotationsPatchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.annotation)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "annotations/{annotationId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PATCH", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"annotationId": c.annotationId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.annotations.patch" call.
// Exactly one of *Annotation or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *Annotation.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *AnnotationsPatchCall) Do() (*Annotation, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &Annotation{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Updates an annotation. The update must respect all mutability restrictions and other invariants described on the annotation resource. Caller must have WRITE permission for the associated dataset. This method supports patch semantics.",
	//   "httpMethod": "PATCH",
	//   "id": "genomics.annotations.patch",
	//   "parameterOrder": [
	//     "annotationId"
	//   ],
	//   "parameters": {
	//     "annotationId": {
	//       "description": "The ID of the annotation set to be updated.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "annotations/{annotationId}",
	//   "request": {
	//     "$ref": "Annotation"
	//   },
	//   "response": {
	//     "$ref": "Annotation"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.annotations.search":

type AnnotationsSearchCall struct {
	s                        *Service
	searchannotationsrequest *SearchAnnotationsRequest
	opt_                     map[string]interface{}
	ctx_                     context.Context
}

// Search: Searches for annotations that match the given criteria.
// Results are returned ordered by start position. Annotations that have
// matching start positions are ordered deterministically. Caller must
// have READ permission for the queried annotation sets.
func (r *AnnotationsService) Search(searchannotationsrequest *SearchAnnotationsRequest) *AnnotationsSearchCall {
	c := &AnnotationsSearchCall{s: r.s, opt_: make(map[string]interface{})}
	c.searchannotationsrequest = searchannotationsrequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AnnotationsSearchCall) Fields(s ...googleapi.Field) *AnnotationsSearchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AnnotationsSearchCall) Context(ctx context.Context) *AnnotationsSearchCall {
	c.ctx_ = ctx
	return c
}

func (c *AnnotationsSearchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.searchannotationsrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "annotations/search")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.annotations.search" call.
// Exactly one of *SearchAnnotationsResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *SearchAnnotationsResponse.ServerResponse.Header or (if a response
// was returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *AnnotationsSearchCall) Do() (*SearchAnnotationsResponse, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &SearchAnnotationsResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Searches for annotations that match the given criteria. Results are returned ordered by start position. Annotations that have matching start positions are ordered deterministically. Caller must have READ permission for the queried annotation sets.",
	//   "httpMethod": "POST",
	//   "id": "genomics.annotations.search",
	//   "path": "annotations/search",
	//   "request": {
	//     "$ref": "SearchAnnotationsRequest"
	//   },
	//   "response": {
	//     "$ref": "SearchAnnotationsResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics",
	//     "https://www.googleapis.com/auth/genomics.readonly"
	//   ]
	// }

}

// method id "genomics.annotations.update":

type AnnotationsUpdateCall struct {
	s            *Service
	annotationId string
	annotation   *Annotation
	opt_         map[string]interface{}
	ctx_         context.Context
}

// Update: Updates an annotation. The update must respect all mutability
// restrictions and other invariants described on the annotation
// resource. Caller must have WRITE permission for the associated
// dataset.
func (r *AnnotationsService) Update(annotationId string, annotation *Annotation) *AnnotationsUpdateCall {
	c := &AnnotationsUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.annotationId = annotationId
	c.annotation = annotation
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *AnnotationsUpdateCall) Fields(s ...googleapi.Field) *AnnotationsUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *AnnotationsUpdateCall) Context(ctx context.Context) *AnnotationsUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *AnnotationsUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.annotation)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "annotations/{annotationId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"annotationId": c.annotationId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.annotations.update" call.
// Exactly one of *Annotation or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *Annotation.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *AnnotationsUpdateCall) Do() (*Annotation, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &Annotation{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Updates an annotation. The update must respect all mutability restrictions and other invariants described on the annotation resource. Caller must have WRITE permission for the associated dataset.",
	//   "httpMethod": "PUT",
	//   "id": "genomics.annotations.update",
	//   "parameterOrder": [
	//     "annotationId"
	//   ],
	//   "parameters": {
	//     "annotationId": {
	//       "description": "The ID of the annotation set to be updated.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "annotations/{annotationId}",
	//   "request": {
	//     "$ref": "Annotation"
	//   },
	//   "response": {
	//     "$ref": "Annotation"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.callsets.create":

type CallsetsCreateCall struct {
	s       *Service
	callset *CallSet
	opt_    map[string]interface{}
	ctx_    context.Context
}

// Create: Creates a new call set.
func (r *CallsetsService) Create(callset *CallSet) *CallsetsCreateCall {
	c := &CallsetsCreateCall{s: r.s, opt_: make(map[string]interface{})}
	c.callset = callset
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CallsetsCreateCall) Fields(s ...googleapi.Field) *CallsetsCreateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *CallsetsCreateCall) Context(ctx context.Context) *CallsetsCreateCall {
	c.ctx_ = ctx
	return c
}

func (c *CallsetsCreateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.callset)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "callsets")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.callsets.create" call.
// Exactly one of *CallSet or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *CallSet.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *CallsetsCreateCall) Do() (*CallSet, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &CallSet{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Creates a new call set.",
	//   "httpMethod": "POST",
	//   "id": "genomics.callsets.create",
	//   "path": "callsets",
	//   "request": {
	//     "$ref": "CallSet"
	//   },
	//   "response": {
	//     "$ref": "CallSet"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.callsets.delete":

type CallsetsDeleteCall struct {
	s         *Service
	callSetId string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Delete: Deletes a call set.
func (r *CallsetsService) Delete(callSetId string) *CallsetsDeleteCall {
	c := &CallsetsDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.callSetId = callSetId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CallsetsDeleteCall) Fields(s ...googleapi.Field) *CallsetsDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *CallsetsDeleteCall) Context(ctx context.Context) *CallsetsDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *CallsetsDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "callsets/{callSetId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"callSetId": c.callSetId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.callsets.delete" call.
func (c *CallsetsDeleteCall) Do() error {
	res, err := c.doRequest("json")
	if err != nil {
		return err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return err
	}
	return nil
	// {
	//   "description": "Deletes a call set.",
	//   "httpMethod": "DELETE",
	//   "id": "genomics.callsets.delete",
	//   "parameterOrder": [
	//     "callSetId"
	//   ],
	//   "parameters": {
	//     "callSetId": {
	//       "description": "The ID of the call set to be deleted.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "callsets/{callSetId}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.callsets.get":

type CallsetsGetCall struct {
	s         *Service
	callSetId string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Get: Gets a call set by ID.
func (r *CallsetsService) Get(callSetId string) *CallsetsGetCall {
	c := &CallsetsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.callSetId = callSetId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CallsetsGetCall) Fields(s ...googleapi.Field) *CallsetsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *CallsetsGetCall) IfNoneMatch(entityTag string) *CallsetsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *CallsetsGetCall) Context(ctx context.Context) *CallsetsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *CallsetsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "callsets/{callSetId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"callSetId": c.callSetId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if v, ok := c.opt_["ifNoneMatch"]; ok {
		req.Header.Set("If-None-Match", fmt.Sprintf("%v", v))
	}
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.callsets.get" call.
// Exactly one of *CallSet or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *CallSet.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *CallsetsGetCall) Do() (*CallSet, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &CallSet{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Gets a call set by ID.",
	//   "httpMethod": "GET",
	//   "id": "genomics.callsets.get",
	//   "parameterOrder": [
	//     "callSetId"
	//   ],
	//   "parameters": {
	//     "callSetId": {
	//       "description": "The ID of the call set.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "callsets/{callSetId}",
	//   "response": {
	//     "$ref": "CallSet"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics",
	//     "https://www.googleapis.com/auth/genomics.readonly"
	//   ]
	// }

}

// method id "genomics.callsets.patch":

type CallsetsPatchCall struct {
	s         *Service
	callSetId string
	callset   *CallSet
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Patch: Updates a call set. This method supports patch semantics.
func (r *CallsetsService) Patch(callSetId string, callset *CallSet) *CallsetsPatchCall {
	c := &CallsetsPatchCall{s: r.s, opt_: make(map[string]interface{})}
	c.callSetId = callSetId
	c.callset = callset
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CallsetsPatchCall) Fields(s ...googleapi.Field) *CallsetsPatchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *CallsetsPatchCall) Context(ctx context.Context) *CallsetsPatchCall {
	c.ctx_ = ctx
	return c
}

func (c *CallsetsPatchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.callset)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "callsets/{callSetId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PATCH", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"callSetId": c.callSetId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.callsets.patch" call.
// Exactly one of *CallSet or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *CallSet.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *CallsetsPatchCall) Do() (*CallSet, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &CallSet{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Updates a call set. This method supports patch semantics.",
	//   "httpMethod": "PATCH",
	//   "id": "genomics.callsets.patch",
	//   "parameterOrder": [
	//     "callSetId"
	//   ],
	//   "parameters": {
	//     "callSetId": {
	//       "description": "The ID of the call set to be updated.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "callsets/{callSetId}",
	//   "request": {
	//     "$ref": "CallSet"
	//   },
	//   "response": {
	//     "$ref": "CallSet"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.callsets.search":

type CallsetsSearchCall struct {
	s                     *Service
	searchcallsetsrequest *SearchCallSetsRequest
	opt_                  map[string]interface{}
	ctx_                  context.Context
}

// Search: Gets a list of call sets matching the criteria.
//
// Implements GlobalAllianceApi.searchCallSets.
func (r *CallsetsService) Search(searchcallsetsrequest *SearchCallSetsRequest) *CallsetsSearchCall {
	c := &CallsetsSearchCall{s: r.s, opt_: make(map[string]interface{})}
	c.searchcallsetsrequest = searchcallsetsrequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CallsetsSearchCall) Fields(s ...googleapi.Field) *CallsetsSearchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *CallsetsSearchCall) Context(ctx context.Context) *CallsetsSearchCall {
	c.ctx_ = ctx
	return c
}

func (c *CallsetsSearchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.searchcallsetsrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "callsets/search")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.callsets.search" call.
// Exactly one of *SearchCallSetsResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *SearchCallSetsResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *CallsetsSearchCall) Do() (*SearchCallSetsResponse, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &SearchCallSetsResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Gets a list of call sets matching the criteria.\n\nImplements GlobalAllianceApi.searchCallSets.",
	//   "httpMethod": "POST",
	//   "id": "genomics.callsets.search",
	//   "path": "callsets/search",
	//   "request": {
	//     "$ref": "SearchCallSetsRequest"
	//   },
	//   "response": {
	//     "$ref": "SearchCallSetsResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics",
	//     "https://www.googleapis.com/auth/genomics.readonly"
	//   ]
	// }

}

// method id "genomics.callsets.update":

type CallsetsUpdateCall struct {
	s         *Service
	callSetId string
	callset   *CallSet
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Update: Updates a call set.
func (r *CallsetsService) Update(callSetId string, callset *CallSet) *CallsetsUpdateCall {
	c := &CallsetsUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.callSetId = callSetId
	c.callset = callset
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *CallsetsUpdateCall) Fields(s ...googleapi.Field) *CallsetsUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *CallsetsUpdateCall) Context(ctx context.Context) *CallsetsUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *CallsetsUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.callset)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "callsets/{callSetId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"callSetId": c.callSetId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.callsets.update" call.
// Exactly one of *CallSet or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *CallSet.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *CallsetsUpdateCall) Do() (*CallSet, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &CallSet{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Updates a call set.",
	//   "httpMethod": "PUT",
	//   "id": "genomics.callsets.update",
	//   "parameterOrder": [
	//     "callSetId"
	//   ],
	//   "parameters": {
	//     "callSetId": {
	//       "description": "The ID of the call set to be updated.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "callsets/{callSetId}",
	//   "request": {
	//     "$ref": "CallSet"
	//   },
	//   "response": {
	//     "$ref": "CallSet"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.datasets.create":

type DatasetsCreateCall struct {
	s       *Service
	dataset *Dataset
	opt_    map[string]interface{}
	ctx_    context.Context
}

// Create: Creates a new dataset.
func (r *DatasetsService) Create(dataset *Dataset) *DatasetsCreateCall {
	c := &DatasetsCreateCall{s: r.s, opt_: make(map[string]interface{})}
	c.dataset = dataset
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *DatasetsCreateCall) Fields(s ...googleapi.Field) *DatasetsCreateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *DatasetsCreateCall) Context(ctx context.Context) *DatasetsCreateCall {
	c.ctx_ = ctx
	return c
}

func (c *DatasetsCreateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.dataset)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "datasets")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.datasets.create" call.
// Exactly one of *Dataset or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Dataset.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *DatasetsCreateCall) Do() (*Dataset, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &Dataset{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Creates a new dataset.",
	//   "httpMethod": "POST",
	//   "id": "genomics.datasets.create",
	//   "path": "datasets",
	//   "request": {
	//     "$ref": "Dataset"
	//   },
	//   "response": {
	//     "$ref": "Dataset"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.datasets.delete":

type DatasetsDeleteCall struct {
	s         *Service
	datasetId string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Delete: Deletes a dataset.
func (r *DatasetsService) Delete(datasetId string) *DatasetsDeleteCall {
	c := &DatasetsDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.datasetId = datasetId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *DatasetsDeleteCall) Fields(s ...googleapi.Field) *DatasetsDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *DatasetsDeleteCall) Context(ctx context.Context) *DatasetsDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *DatasetsDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "datasets/{datasetId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"datasetId": c.datasetId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.datasets.delete" call.
func (c *DatasetsDeleteCall) Do() error {
	res, err := c.doRequest("json")
	if err != nil {
		return err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return err
	}
	return nil
	// {
	//   "description": "Deletes a dataset.",
	//   "httpMethod": "DELETE",
	//   "id": "genomics.datasets.delete",
	//   "parameterOrder": [
	//     "datasetId"
	//   ],
	//   "parameters": {
	//     "datasetId": {
	//       "description": "The ID of the dataset to be deleted.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "datasets/{datasetId}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.datasets.get":

type DatasetsGetCall struct {
	s         *Service
	datasetId string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Get: Gets a dataset by ID.
func (r *DatasetsService) Get(datasetId string) *DatasetsGetCall {
	c := &DatasetsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.datasetId = datasetId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *DatasetsGetCall) Fields(s ...googleapi.Field) *DatasetsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *DatasetsGetCall) IfNoneMatch(entityTag string) *DatasetsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *DatasetsGetCall) Context(ctx context.Context) *DatasetsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *DatasetsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "datasets/{datasetId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"datasetId": c.datasetId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if v, ok := c.opt_["ifNoneMatch"]; ok {
		req.Header.Set("If-None-Match", fmt.Sprintf("%v", v))
	}
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.datasets.get" call.
// Exactly one of *Dataset or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Dataset.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *DatasetsGetCall) Do() (*Dataset, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &Dataset{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Gets a dataset by ID.",
	//   "httpMethod": "GET",
	//   "id": "genomics.datasets.get",
	//   "parameterOrder": [
	//     "datasetId"
	//   ],
	//   "parameters": {
	//     "datasetId": {
	//       "description": "The ID of the dataset.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "datasets/{datasetId}",
	//   "response": {
	//     "$ref": "Dataset"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics",
	//     "https://www.googleapis.com/auth/genomics.readonly"
	//   ]
	// }

}

// method id "genomics.datasets.list":

type DatasetsListCall struct {
	s    *Service
	opt_ map[string]interface{}
	ctx_ context.Context
}

// List: Lists datasets within a project.
func (r *DatasetsService) List() *DatasetsListCall {
	c := &DatasetsListCall{s: r.s, opt_: make(map[string]interface{})}
	return c
}

// PageSize sets the optional parameter "pageSize": The maximum number
// of results returned by this request. If unspecified, defaults to 50.
func (c *DatasetsListCall) PageSize(pageSize int64) *DatasetsListCall {
	c.opt_["pageSize"] = pageSize
	return c
}

// PageToken sets the optional parameter "pageToken": The continuation
// token, which is used to page through large result sets. To get the
// next page of results, set this parameter to the value of
// nextPageToken from the previous response.
func (c *DatasetsListCall) PageToken(pageToken string) *DatasetsListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// ProjectNumber sets the optional parameter "projectNumber": Required.
// The project to list datasets for.
func (c *DatasetsListCall) ProjectNumber(projectNumber int64) *DatasetsListCall {
	c.opt_["projectNumber"] = projectNumber
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *DatasetsListCall) Fields(s ...googleapi.Field) *DatasetsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *DatasetsListCall) IfNoneMatch(entityTag string) *DatasetsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *DatasetsListCall) Context(ctx context.Context) *DatasetsListCall {
	c.ctx_ = ctx
	return c
}

func (c *DatasetsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["pageSize"]; ok {
		params.Set("pageSize", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["projectNumber"]; ok {
		params.Set("projectNumber", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "datasets")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("User-Agent", c.s.userAgent())
	if v, ok := c.opt_["ifNoneMatch"]; ok {
		req.Header.Set("If-None-Match", fmt.Sprintf("%v", v))
	}
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.datasets.list" call.
// Exactly one of *ListDatasetsResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *ListDatasetsResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *DatasetsListCall) Do() (*ListDatasetsResponse, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &ListDatasetsResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Lists datasets within a project.",
	//   "httpMethod": "GET",
	//   "id": "genomics.datasets.list",
	//   "parameters": {
	//     "pageSize": {
	//       "description": "The maximum number of results returned by this request. If unspecified, defaults to 50.",
	//       "format": "int32",
	//       "location": "query",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "The continuation token, which is used to page through large result sets. To get the next page of results, set this parameter to the value of nextPageToken from the previous response.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "projectNumber": {
	//       "description": "Required. The project to list datasets for.",
	//       "format": "int64",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "datasets",
	//   "response": {
	//     "$ref": "ListDatasetsResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics",
	//     "https://www.googleapis.com/auth/genomics.readonly"
	//   ]
	// }

}

// method id "genomics.datasets.patch":

type DatasetsPatchCall struct {
	s         *Service
	datasetId string
	dataset   *Dataset
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Patch: Updates a dataset. This method supports patch semantics.
func (r *DatasetsService) Patch(datasetId string, dataset *Dataset) *DatasetsPatchCall {
	c := &DatasetsPatchCall{s: r.s, opt_: make(map[string]interface{})}
	c.datasetId = datasetId
	c.dataset = dataset
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *DatasetsPatchCall) Fields(s ...googleapi.Field) *DatasetsPatchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *DatasetsPatchCall) Context(ctx context.Context) *DatasetsPatchCall {
	c.ctx_ = ctx
	return c
}

func (c *DatasetsPatchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.dataset)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "datasets/{datasetId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PATCH", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"datasetId": c.datasetId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.datasets.patch" call.
// Exactly one of *Dataset or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Dataset.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *DatasetsPatchCall) Do() (*Dataset, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &Dataset{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Updates a dataset. This method supports patch semantics.",
	//   "httpMethod": "PATCH",
	//   "id": "genomics.datasets.patch",
	//   "parameterOrder": [
	//     "datasetId"
	//   ],
	//   "parameters": {
	//     "datasetId": {
	//       "description": "The ID of the dataset to be updated.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "datasets/{datasetId}",
	//   "request": {
	//     "$ref": "Dataset"
	//   },
	//   "response": {
	//     "$ref": "Dataset"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.datasets.undelete":

type DatasetsUndeleteCall struct {
	s         *Service
	datasetId string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Undelete: Undeletes a dataset by restoring a dataset which was
// deleted via this API. This operation is only possible for a week
// after the deletion occurred.
func (r *DatasetsService) Undelete(datasetId string) *DatasetsUndeleteCall {
	c := &DatasetsUndeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.datasetId = datasetId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *DatasetsUndeleteCall) Fields(s ...googleapi.Field) *DatasetsUndeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *DatasetsUndeleteCall) Context(ctx context.Context) *DatasetsUndeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *DatasetsUndeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "datasets/{datasetId}/undelete")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"datasetId": c.datasetId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.datasets.undelete" call.
// Exactly one of *Dataset or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Dataset.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *DatasetsUndeleteCall) Do() (*Dataset, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &Dataset{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Undeletes a dataset by restoring a dataset which was deleted via this API. This operation is only possible for a week after the deletion occurred.",
	//   "httpMethod": "POST",
	//   "id": "genomics.datasets.undelete",
	//   "parameterOrder": [
	//     "datasetId"
	//   ],
	//   "parameters": {
	//     "datasetId": {
	//       "description": "The ID of the dataset to be undeleted.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "datasets/{datasetId}/undelete",
	//   "response": {
	//     "$ref": "Dataset"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.datasets.update":

type DatasetsUpdateCall struct {
	s         *Service
	datasetId string
	dataset   *Dataset
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Update: Updates a dataset.
func (r *DatasetsService) Update(datasetId string, dataset *Dataset) *DatasetsUpdateCall {
	c := &DatasetsUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.datasetId = datasetId
	c.dataset = dataset
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *DatasetsUpdateCall) Fields(s ...googleapi.Field) *DatasetsUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *DatasetsUpdateCall) Context(ctx context.Context) *DatasetsUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *DatasetsUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.dataset)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "datasets/{datasetId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"datasetId": c.datasetId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.datasets.update" call.
// Exactly one of *Dataset or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Dataset.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *DatasetsUpdateCall) Do() (*Dataset, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &Dataset{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Updates a dataset.",
	//   "httpMethod": "PUT",
	//   "id": "genomics.datasets.update",
	//   "parameterOrder": [
	//     "datasetId"
	//   ],
	//   "parameters": {
	//     "datasetId": {
	//       "description": "The ID of the dataset to be updated.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "datasets/{datasetId}",
	//   "request": {
	//     "$ref": "Dataset"
	//   },
	//   "response": {
	//     "$ref": "Dataset"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.experimental.jobs.create":

type ExperimentalJobsCreateCall struct {
	s                            *Service
	experimentalcreatejobrequest *ExperimentalCreateJobRequest
	opt_                         map[string]interface{}
	ctx_                         context.Context
}

// Create: Creates and asynchronously runs an ad-hoc job. This is an
// experimental call and may be removed or changed at any time.
func (r *ExperimentalJobsService) Create(experimentalcreatejobrequest *ExperimentalCreateJobRequest) *ExperimentalJobsCreateCall {
	c := &ExperimentalJobsCreateCall{s: r.s, opt_: make(map[string]interface{})}
	c.experimentalcreatejobrequest = experimentalcreatejobrequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ExperimentalJobsCreateCall) Fields(s ...googleapi.Field) *ExperimentalJobsCreateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ExperimentalJobsCreateCall) Context(ctx context.Context) *ExperimentalJobsCreateCall {
	c.ctx_ = ctx
	return c
}

func (c *ExperimentalJobsCreateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.experimentalcreatejobrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "experimental/jobs/create")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.experimental.jobs.create" call.
// Exactly one of *ExperimentalCreateJobResponse or error will be
// non-nil. Any non-2xx status code is an error. Response headers are in
// either *ExperimentalCreateJobResponse.ServerResponse.Header or (if a
// response was returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ExperimentalJobsCreateCall) Do() (*ExperimentalCreateJobResponse, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &ExperimentalCreateJobResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Creates and asynchronously runs an ad-hoc job. This is an experimental call and may be removed or changed at any time.",
	//   "httpMethod": "POST",
	//   "id": "genomics.experimental.jobs.create",
	//   "path": "experimental/jobs/create",
	//   "request": {
	//     "$ref": "ExperimentalCreateJobRequest"
	//   },
	//   "response": {
	//     "$ref": "ExperimentalCreateJobResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/devstorage.read_write",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.jobs.cancel":

type JobsCancelCall struct {
	s     *Service
	jobId string
	opt_  map[string]interface{}
	ctx_  context.Context
}

// Cancel: Cancels a job by ID. Note that it is possible for partial
// results to be generated and stored for cancelled jobs.
func (r *JobsService) Cancel(jobId string) *JobsCancelCall {
	c := &JobsCancelCall{s: r.s, opt_: make(map[string]interface{})}
	c.jobId = jobId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *JobsCancelCall) Fields(s ...googleapi.Field) *JobsCancelCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *JobsCancelCall) Context(ctx context.Context) *JobsCancelCall {
	c.ctx_ = ctx
	return c
}

func (c *JobsCancelCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "jobs/{jobId}/cancel")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"jobId": c.jobId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.jobs.cancel" call.
func (c *JobsCancelCall) Do() error {
	res, err := c.doRequest("json")
	if err != nil {
		return err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return err
	}
	return nil
	// {
	//   "description": "Cancels a job by ID. Note that it is possible for partial results to be generated and stored for cancelled jobs.",
	//   "httpMethod": "POST",
	//   "id": "genomics.jobs.cancel",
	//   "parameterOrder": [
	//     "jobId"
	//   ],
	//   "parameters": {
	//     "jobId": {
	//       "description": "Required. The ID of the job.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "jobs/{jobId}/cancel",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.jobs.get":

type JobsGetCall struct {
	s     *Service
	jobId string
	opt_  map[string]interface{}
	ctx_  context.Context
}

// Get: Gets a job by ID.
func (r *JobsService) Get(jobId string) *JobsGetCall {
	c := &JobsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.jobId = jobId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *JobsGetCall) Fields(s ...googleapi.Field) *JobsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *JobsGetCall) IfNoneMatch(entityTag string) *JobsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *JobsGetCall) Context(ctx context.Context) *JobsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *JobsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "jobs/{jobId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"jobId": c.jobId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if v, ok := c.opt_["ifNoneMatch"]; ok {
		req.Header.Set("If-None-Match", fmt.Sprintf("%v", v))
	}
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.jobs.get" call.
// Exactly one of *Job or error will be non-nil. Any non-2xx status code
// is an error. Response headers are in either
// *Job.ServerResponse.Header or (if a response was returned at all) in
// error.(*googleapi.Error).Header. Use googleapi.IsNotModified to check
// whether the returned error was because http.StatusNotModified was
// returned.
func (c *JobsGetCall) Do() (*Job, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &Job{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Gets a job by ID.",
	//   "httpMethod": "GET",
	//   "id": "genomics.jobs.get",
	//   "parameterOrder": [
	//     "jobId"
	//   ],
	//   "parameters": {
	//     "jobId": {
	//       "description": "Required. The ID of the job.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "jobs/{jobId}",
	//   "response": {
	//     "$ref": "Job"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics",
	//     "https://www.googleapis.com/auth/genomics.readonly"
	//   ]
	// }

}

// method id "genomics.jobs.search":

type JobsSearchCall struct {
	s                 *Service
	searchjobsrequest *SearchJobsRequest
	opt_              map[string]interface{}
	ctx_              context.Context
}

// Search: Gets a list of jobs matching the criteria.
func (r *JobsService) Search(searchjobsrequest *SearchJobsRequest) *JobsSearchCall {
	c := &JobsSearchCall{s: r.s, opt_: make(map[string]interface{})}
	c.searchjobsrequest = searchjobsrequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *JobsSearchCall) Fields(s ...googleapi.Field) *JobsSearchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *JobsSearchCall) Context(ctx context.Context) *JobsSearchCall {
	c.ctx_ = ctx
	return c
}

func (c *JobsSearchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.searchjobsrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "jobs/search")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.jobs.search" call.
// Exactly one of *SearchJobsResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *SearchJobsResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *JobsSearchCall) Do() (*SearchJobsResponse, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &SearchJobsResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Gets a list of jobs matching the criteria.",
	//   "httpMethod": "POST",
	//   "id": "genomics.jobs.search",
	//   "path": "jobs/search",
	//   "request": {
	//     "$ref": "SearchJobsRequest"
	//   },
	//   "response": {
	//     "$ref": "SearchJobsResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics",
	//     "https://www.googleapis.com/auth/genomics.readonly"
	//   ]
	// }

}

// method id "genomics.readgroupsets.align":

type ReadgroupsetsAlignCall struct {
	s                         *Service
	alignreadgroupsetsrequest *AlignReadGroupSetsRequest
	opt_                      map[string]interface{}
	ctx_                      context.Context
}

// Align: Aligns read data from existing read group sets or files from
// Google Cloud Storage. See the  alignment and variant calling
// documentation for more details.
func (r *ReadgroupsetsService) Align(alignreadgroupsetsrequest *AlignReadGroupSetsRequest) *ReadgroupsetsAlignCall {
	c := &ReadgroupsetsAlignCall{s: r.s, opt_: make(map[string]interface{})}
	c.alignreadgroupsetsrequest = alignreadgroupsetsrequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ReadgroupsetsAlignCall) Fields(s ...googleapi.Field) *ReadgroupsetsAlignCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ReadgroupsetsAlignCall) Context(ctx context.Context) *ReadgroupsetsAlignCall {
	c.ctx_ = ctx
	return c
}

func (c *ReadgroupsetsAlignCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.alignreadgroupsetsrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "readgroupsets/align")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.readgroupsets.align" call.
// Exactly one of *AlignReadGroupSetsResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *AlignReadGroupSetsResponse.ServerResponse.Header or (if a response
// was returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ReadgroupsetsAlignCall) Do() (*AlignReadGroupSetsResponse, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &AlignReadGroupSetsResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Aligns read data from existing read group sets or files from Google Cloud Storage. See the  alignment and variant calling documentation for more details.",
	//   "httpMethod": "POST",
	//   "id": "genomics.readgroupsets.align",
	//   "path": "readgroupsets/align",
	//   "request": {
	//     "$ref": "AlignReadGroupSetsRequest"
	//   },
	//   "response": {
	//     "$ref": "AlignReadGroupSetsResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/devstorage.read_write",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.readgroupsets.call":

type ReadgroupsetsCallCall struct {
	s                        *Service
	callreadgroupsetsrequest *CallReadGroupSetsRequest
	opt_                     map[string]interface{}
	ctx_                     context.Context
}

// Call: Calls variants on read data from existing read group sets or
// files from Google Cloud Storage. See the  alignment and variant
// calling documentation for more details.
func (r *ReadgroupsetsService) Call(callreadgroupsetsrequest *CallReadGroupSetsRequest) *ReadgroupsetsCallCall {
	c := &ReadgroupsetsCallCall{s: r.s, opt_: make(map[string]interface{})}
	c.callreadgroupsetsrequest = callreadgroupsetsrequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ReadgroupsetsCallCall) Fields(s ...googleapi.Field) *ReadgroupsetsCallCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ReadgroupsetsCallCall) Context(ctx context.Context) *ReadgroupsetsCallCall {
	c.ctx_ = ctx
	return c
}

func (c *ReadgroupsetsCallCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.callreadgroupsetsrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "readgroupsets/call")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.readgroupsets.call" call.
// Exactly one of *CallReadGroupSetsResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *CallReadGroupSetsResponse.ServerResponse.Header or (if a response
// was returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ReadgroupsetsCallCall) Do() (*CallReadGroupSetsResponse, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &CallReadGroupSetsResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Calls variants on read data from existing read group sets or files from Google Cloud Storage. See the  alignment and variant calling documentation for more details.",
	//   "httpMethod": "POST",
	//   "id": "genomics.readgroupsets.call",
	//   "path": "readgroupsets/call",
	//   "request": {
	//     "$ref": "CallReadGroupSetsRequest"
	//   },
	//   "response": {
	//     "$ref": "CallReadGroupSetsResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/devstorage.read_write",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.readgroupsets.delete":

type ReadgroupsetsDeleteCall struct {
	s              *Service
	readGroupSetId string
	opt_           map[string]interface{}
	ctx_           context.Context
}

// Delete: Deletes a read group set.
func (r *ReadgroupsetsService) Delete(readGroupSetId string) *ReadgroupsetsDeleteCall {
	c := &ReadgroupsetsDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.readGroupSetId = readGroupSetId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ReadgroupsetsDeleteCall) Fields(s ...googleapi.Field) *ReadgroupsetsDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ReadgroupsetsDeleteCall) Context(ctx context.Context) *ReadgroupsetsDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *ReadgroupsetsDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "readgroupsets/{readGroupSetId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"readGroupSetId": c.readGroupSetId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.readgroupsets.delete" call.
func (c *ReadgroupsetsDeleteCall) Do() error {
	res, err := c.doRequest("json")
	if err != nil {
		return err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return err
	}
	return nil
	// {
	//   "description": "Deletes a read group set.",
	//   "httpMethod": "DELETE",
	//   "id": "genomics.readgroupsets.delete",
	//   "parameterOrder": [
	//     "readGroupSetId"
	//   ],
	//   "parameters": {
	//     "readGroupSetId": {
	//       "description": "The ID of the read group set to be deleted. The caller must have WRITE permissions to the dataset associated with this read group set.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "readgroupsets/{readGroupSetId}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.readgroupsets.export":

type ReadgroupsetsExportCall struct {
	s                          *Service
	exportreadgroupsetsrequest *ExportReadGroupSetsRequest
	opt_                       map[string]interface{}
	ctx_                       context.Context
}

// Export: Exports read group sets to a BAM file in Google Cloud
// Storage.
//
// Note that currently there may be some differences between exported
// BAM files and the original BAM file at the time of import. See
// ImportReadGroupSets for details.
func (r *ReadgroupsetsService) Export(exportreadgroupsetsrequest *ExportReadGroupSetsRequest) *ReadgroupsetsExportCall {
	c := &ReadgroupsetsExportCall{s: r.s, opt_: make(map[string]interface{})}
	c.exportreadgroupsetsrequest = exportreadgroupsetsrequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ReadgroupsetsExportCall) Fields(s ...googleapi.Field) *ReadgroupsetsExportCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ReadgroupsetsExportCall) Context(ctx context.Context) *ReadgroupsetsExportCall {
	c.ctx_ = ctx
	return c
}

func (c *ReadgroupsetsExportCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.exportreadgroupsetsrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "readgroupsets/export")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.readgroupsets.export" call.
// Exactly one of *ExportReadGroupSetsResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *ExportReadGroupSetsResponse.ServerResponse.Header or (if a response
// was returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ReadgroupsetsExportCall) Do() (*ExportReadGroupSetsResponse, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &ExportReadGroupSetsResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Exports read group sets to a BAM file in Google Cloud Storage.\n\nNote that currently there may be some differences between exported BAM files and the original BAM file at the time of import. See ImportReadGroupSets for details.",
	//   "httpMethod": "POST",
	//   "id": "genomics.readgroupsets.export",
	//   "path": "readgroupsets/export",
	//   "request": {
	//     "$ref": "ExportReadGroupSetsRequest"
	//   },
	//   "response": {
	//     "$ref": "ExportReadGroupSetsResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/devstorage.read_write",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.readgroupsets.get":

type ReadgroupsetsGetCall struct {
	s              *Service
	readGroupSetId string
	opt_           map[string]interface{}
	ctx_           context.Context
}

// Get: Gets a read group set by ID.
func (r *ReadgroupsetsService) Get(readGroupSetId string) *ReadgroupsetsGetCall {
	c := &ReadgroupsetsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.readGroupSetId = readGroupSetId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ReadgroupsetsGetCall) Fields(s ...googleapi.Field) *ReadgroupsetsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ReadgroupsetsGetCall) IfNoneMatch(entityTag string) *ReadgroupsetsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ReadgroupsetsGetCall) Context(ctx context.Context) *ReadgroupsetsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *ReadgroupsetsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "readgroupsets/{readGroupSetId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"readGroupSetId": c.readGroupSetId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if v, ok := c.opt_["ifNoneMatch"]; ok {
		req.Header.Set("If-None-Match", fmt.Sprintf("%v", v))
	}
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.readgroupsets.get" call.
// Exactly one of *ReadGroupSet or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *ReadGroupSet.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ReadgroupsetsGetCall) Do() (*ReadGroupSet, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &ReadGroupSet{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Gets a read group set by ID.",
	//   "httpMethod": "GET",
	//   "id": "genomics.readgroupsets.get",
	//   "parameterOrder": [
	//     "readGroupSetId"
	//   ],
	//   "parameters": {
	//     "readGroupSetId": {
	//       "description": "The ID of the read group set.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "readgroupsets/{readGroupSetId}",
	//   "response": {
	//     "$ref": "ReadGroupSet"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics",
	//     "https://www.googleapis.com/auth/genomics.readonly"
	//   ]
	// }

}

// method id "genomics.readgroupsets.import":

type ReadgroupsetsImportCall struct {
	s                          *Service
	importreadgroupsetsrequest *ImportReadGroupSetsRequest
	opt_                       map[string]interface{}
	ctx_                       context.Context
}

// Import: Creates read group sets by asynchronously importing the
// provided information. The caller must have WRITE permissions to the
// dataset.
//
// Notes on BAM import:
// - Tags will be converted to strings - tag types are not preserved
// - Comments (@CO) in the input file header are not imported
// - Original order of reference headers is not preserved
// - Any reverse stranded unmapped reads will be reverse complemented,
// and their qualities (and "BQ" tag, if any) will be reversed
// - Unmapped reads will be stripped of positional information
// (referenceName and position)
func (r *ReadgroupsetsService) Import(importreadgroupsetsrequest *ImportReadGroupSetsRequest) *ReadgroupsetsImportCall {
	c := &ReadgroupsetsImportCall{s: r.s, opt_: make(map[string]interface{})}
	c.importreadgroupsetsrequest = importreadgroupsetsrequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ReadgroupsetsImportCall) Fields(s ...googleapi.Field) *ReadgroupsetsImportCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ReadgroupsetsImportCall) Context(ctx context.Context) *ReadgroupsetsImportCall {
	c.ctx_ = ctx
	return c
}

func (c *ReadgroupsetsImportCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.importreadgroupsetsrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "readgroupsets/import")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.readgroupsets.import" call.
// Exactly one of *ImportReadGroupSetsResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *ImportReadGroupSetsResponse.ServerResponse.Header or (if a response
// was returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ReadgroupsetsImportCall) Do() (*ImportReadGroupSetsResponse, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &ImportReadGroupSetsResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Creates read group sets by asynchronously importing the provided information. The caller must have WRITE permissions to the dataset.\n\nNotes on BAM import:  \n- Tags will be converted to strings - tag types are not preserved\n- Comments (@CO) in the input file header are not imported\n- Original order of reference headers is not preserved\n- Any reverse stranded unmapped reads will be reverse complemented, and their qualities (and \"BQ\" tag, if any) will be reversed\n- Unmapped reads will be stripped of positional information (referenceName and position)",
	//   "httpMethod": "POST",
	//   "id": "genomics.readgroupsets.import",
	//   "path": "readgroupsets/import",
	//   "request": {
	//     "$ref": "ImportReadGroupSetsRequest"
	//   },
	//   "response": {
	//     "$ref": "ImportReadGroupSetsResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/devstorage.read_write",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.readgroupsets.patch":

type ReadgroupsetsPatchCall struct {
	s              *Service
	readGroupSetId string
	readgroupset   *ReadGroupSet
	opt_           map[string]interface{}
	ctx_           context.Context
}

// Patch: Updates a read group set. This method supports patch
// semantics.
func (r *ReadgroupsetsService) Patch(readGroupSetId string, readgroupset *ReadGroupSet) *ReadgroupsetsPatchCall {
	c := &ReadgroupsetsPatchCall{s: r.s, opt_: make(map[string]interface{})}
	c.readGroupSetId = readGroupSetId
	c.readgroupset = readgroupset
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ReadgroupsetsPatchCall) Fields(s ...googleapi.Field) *ReadgroupsetsPatchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ReadgroupsetsPatchCall) Context(ctx context.Context) *ReadgroupsetsPatchCall {
	c.ctx_ = ctx
	return c
}

func (c *ReadgroupsetsPatchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.readgroupset)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "readgroupsets/{readGroupSetId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PATCH", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"readGroupSetId": c.readGroupSetId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.readgroupsets.patch" call.
// Exactly one of *ReadGroupSet or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *ReadGroupSet.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ReadgroupsetsPatchCall) Do() (*ReadGroupSet, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &ReadGroupSet{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Updates a read group set. This method supports patch semantics.",
	//   "httpMethod": "PATCH",
	//   "id": "genomics.readgroupsets.patch",
	//   "parameterOrder": [
	//     "readGroupSetId"
	//   ],
	//   "parameters": {
	//     "readGroupSetId": {
	//       "description": "The ID of the read group set to be updated. The caller must have WRITE permissions to the dataset associated with this read group set.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "readgroupsets/{readGroupSetId}",
	//   "request": {
	//     "$ref": "ReadGroupSet"
	//   },
	//   "response": {
	//     "$ref": "ReadGroupSet"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.readgroupsets.search":

type ReadgroupsetsSearchCall struct {
	s                          *Service
	searchreadgroupsetsrequest *SearchReadGroupSetsRequest
	opt_                       map[string]interface{}
	ctx_                       context.Context
}

// Search: Searches for read group sets matching the
// criteria.
//
// Implements GlobalAllianceApi.searchReadGroupSets.
func (r *ReadgroupsetsService) Search(searchreadgroupsetsrequest *SearchReadGroupSetsRequest) *ReadgroupsetsSearchCall {
	c := &ReadgroupsetsSearchCall{s: r.s, opt_: make(map[string]interface{})}
	c.searchreadgroupsetsrequest = searchreadgroupsetsrequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ReadgroupsetsSearchCall) Fields(s ...googleapi.Field) *ReadgroupsetsSearchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ReadgroupsetsSearchCall) Context(ctx context.Context) *ReadgroupsetsSearchCall {
	c.ctx_ = ctx
	return c
}

func (c *ReadgroupsetsSearchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.searchreadgroupsetsrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "readgroupsets/search")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.readgroupsets.search" call.
// Exactly one of *SearchReadGroupSetsResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *SearchReadGroupSetsResponse.ServerResponse.Header or (if a response
// was returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ReadgroupsetsSearchCall) Do() (*SearchReadGroupSetsResponse, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &SearchReadGroupSetsResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Searches for read group sets matching the criteria.\n\nImplements GlobalAllianceApi.searchReadGroupSets.",
	//   "httpMethod": "POST",
	//   "id": "genomics.readgroupsets.search",
	//   "path": "readgroupsets/search",
	//   "request": {
	//     "$ref": "SearchReadGroupSetsRequest"
	//   },
	//   "response": {
	//     "$ref": "SearchReadGroupSetsResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics",
	//     "https://www.googleapis.com/auth/genomics.readonly"
	//   ]
	// }

}

// method id "genomics.readgroupsets.update":

type ReadgroupsetsUpdateCall struct {
	s              *Service
	readGroupSetId string
	readgroupset   *ReadGroupSet
	opt_           map[string]interface{}
	ctx_           context.Context
}

// Update: Updates a read group set.
func (r *ReadgroupsetsService) Update(readGroupSetId string, readgroupset *ReadGroupSet) *ReadgroupsetsUpdateCall {
	c := &ReadgroupsetsUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.readGroupSetId = readGroupSetId
	c.readgroupset = readgroupset
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ReadgroupsetsUpdateCall) Fields(s ...googleapi.Field) *ReadgroupsetsUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ReadgroupsetsUpdateCall) Context(ctx context.Context) *ReadgroupsetsUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *ReadgroupsetsUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.readgroupset)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "readgroupsets/{readGroupSetId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"readGroupSetId": c.readGroupSetId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.readgroupsets.update" call.
// Exactly one of *ReadGroupSet or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *ReadGroupSet.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ReadgroupsetsUpdateCall) Do() (*ReadGroupSet, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &ReadGroupSet{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Updates a read group set.",
	//   "httpMethod": "PUT",
	//   "id": "genomics.readgroupsets.update",
	//   "parameterOrder": [
	//     "readGroupSetId"
	//   ],
	//   "parameters": {
	//     "readGroupSetId": {
	//       "description": "The ID of the read group set to be updated. The caller must have WRITE permissions to the dataset associated with this read group set.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "readgroupsets/{readGroupSetId}",
	//   "request": {
	//     "$ref": "ReadGroupSet"
	//   },
	//   "response": {
	//     "$ref": "ReadGroupSet"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.readgroupsets.coveragebuckets.list":

type ReadgroupsetsCoveragebucketsListCall struct {
	s              *Service
	readGroupSetId string
	opt_           map[string]interface{}
	ctx_           context.Context
}

// List: Lists fixed width coverage buckets for a read group set, each
// of which correspond to a range of a reference sequence. Each bucket
// summarizes coverage information across its corresponding genomic
// range.
//
// Coverage is defined as the number of reads which are aligned to a
// given base in the reference sequence. Coverage buckets are available
// at several precomputed bucket widths, enabling retrieval of various
// coverage 'zoom levels'. The caller must have READ permissions for the
// target read group set.
func (r *ReadgroupsetsCoveragebucketsService) List(readGroupSetId string) *ReadgroupsetsCoveragebucketsListCall {
	c := &ReadgroupsetsCoveragebucketsListCall{s: r.s, opt_: make(map[string]interface{})}
	c.readGroupSetId = readGroupSetId
	return c
}

// PageSize sets the optional parameter "pageSize": The maximum number
// of results to return in a single page. If unspecified, defaults to
// 1024. The maximum value is 2048.
func (c *ReadgroupsetsCoveragebucketsListCall) PageSize(pageSize int64) *ReadgroupsetsCoveragebucketsListCall {
	c.opt_["pageSize"] = pageSize
	return c
}

// PageToken sets the optional parameter "pageToken": The continuation
// token, which is used to page through large result sets. To get the
// next page of results, set this parameter to the value of
// nextPageToken from the previous response.
func (c *ReadgroupsetsCoveragebucketsListCall) PageToken(pageToken string) *ReadgroupsetsCoveragebucketsListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// RangeEnd sets the optional parameter "range.end": The end position of
// the range on the reference, 0-based exclusive. If specified,
// referenceName must also be specified.
func (c *ReadgroupsetsCoveragebucketsListCall) RangeEnd(rangeEnd int64) *ReadgroupsetsCoveragebucketsListCall {
	c.opt_["range.end"] = rangeEnd
	return c
}

// RangeReferenceName sets the optional parameter "range.referenceName":
// The reference sequence name, for example chr1, 1, or chrX.
func (c *ReadgroupsetsCoveragebucketsListCall) RangeReferenceName(rangeReferenceName string) *ReadgroupsetsCoveragebucketsListCall {
	c.opt_["range.referenceName"] = rangeReferenceName
	return c
}

// RangeStart sets the optional parameter "range.start": The start
// position of the range on the reference, 0-based inclusive. If
// specified, referenceName must also be specified.
func (c *ReadgroupsetsCoveragebucketsListCall) RangeStart(rangeStart int64) *ReadgroupsetsCoveragebucketsListCall {
	c.opt_["range.start"] = rangeStart
	return c
}

// TargetBucketWidth sets the optional parameter "targetBucketWidth":
// The desired width of each reported coverage bucket in base pairs.
// This will be rounded down to the nearest precomputed bucket width;
// the value of which is returned as bucketWidth in the response.
// Defaults to infinity (each bucket spans an entire reference sequence)
// or the length of the target range, if specified. The smallest
// precomputed bucketWidth is currently 2048 base pairs; this is subject
// to change.
func (c *ReadgroupsetsCoveragebucketsListCall) TargetBucketWidth(targetBucketWidth int64) *ReadgroupsetsCoveragebucketsListCall {
	c.opt_["targetBucketWidth"] = targetBucketWidth
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ReadgroupsetsCoveragebucketsListCall) Fields(s ...googleapi.Field) *ReadgroupsetsCoveragebucketsListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ReadgroupsetsCoveragebucketsListCall) IfNoneMatch(entityTag string) *ReadgroupsetsCoveragebucketsListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ReadgroupsetsCoveragebucketsListCall) Context(ctx context.Context) *ReadgroupsetsCoveragebucketsListCall {
	c.ctx_ = ctx
	return c
}

func (c *ReadgroupsetsCoveragebucketsListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["pageSize"]; ok {
		params.Set("pageSize", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["range.end"]; ok {
		params.Set("range.end", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["range.referenceName"]; ok {
		params.Set("range.referenceName", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["range.start"]; ok {
		params.Set("range.start", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["targetBucketWidth"]; ok {
		params.Set("targetBucketWidth", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "readgroupsets/{readGroupSetId}/coveragebuckets")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"readGroupSetId": c.readGroupSetId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if v, ok := c.opt_["ifNoneMatch"]; ok {
		req.Header.Set("If-None-Match", fmt.Sprintf("%v", v))
	}
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.readgroupsets.coveragebuckets.list" call.
// Exactly one of *ListCoverageBucketsResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *ListCoverageBucketsResponse.ServerResponse.Header or (if a response
// was returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ReadgroupsetsCoveragebucketsListCall) Do() (*ListCoverageBucketsResponse, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &ListCoverageBucketsResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Lists fixed width coverage buckets for a read group set, each of which correspond to a range of a reference sequence. Each bucket summarizes coverage information across its corresponding genomic range.\n\nCoverage is defined as the number of reads which are aligned to a given base in the reference sequence. Coverage buckets are available at several precomputed bucket widths, enabling retrieval of various coverage 'zoom levels'. The caller must have READ permissions for the target read group set.",
	//   "httpMethod": "GET",
	//   "id": "genomics.readgroupsets.coveragebuckets.list",
	//   "parameterOrder": [
	//     "readGroupSetId"
	//   ],
	//   "parameters": {
	//     "pageSize": {
	//       "description": "The maximum number of results to return in a single page. If unspecified, defaults to 1024. The maximum value is 2048.",
	//       "format": "int32",
	//       "location": "query",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "The continuation token, which is used to page through large result sets. To get the next page of results, set this parameter to the value of nextPageToken from the previous response.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "range.end": {
	//       "description": "The end position of the range on the reference, 0-based exclusive. If specified, referenceName must also be specified.",
	//       "format": "int64",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "range.referenceName": {
	//       "description": "The reference sequence name, for example chr1, 1, or chrX.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "range.start": {
	//       "description": "The start position of the range on the reference, 0-based inclusive. If specified, referenceName must also be specified.",
	//       "format": "int64",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "readGroupSetId": {
	//       "description": "Required. The ID of the read group set over which coverage is requested.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "targetBucketWidth": {
	//       "description": "The desired width of each reported coverage bucket in base pairs. This will be rounded down to the nearest precomputed bucket width; the value of which is returned as bucketWidth in the response. Defaults to infinity (each bucket spans an entire reference sequence) or the length of the target range, if specified. The smallest precomputed bucketWidth is currently 2048 base pairs; this is subject to change.",
	//       "format": "int64",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "readgroupsets/{readGroupSetId}/coveragebuckets",
	//   "response": {
	//     "$ref": "ListCoverageBucketsResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics",
	//     "https://www.googleapis.com/auth/genomics.readonly"
	//   ]
	// }

}

// method id "genomics.reads.search":

type ReadsSearchCall struct {
	s                  *Service
	searchreadsrequest *SearchReadsRequest
	opt_               map[string]interface{}
	ctx_               context.Context
}

// Search: Gets a list of reads for one or more read group sets. Reads
// search operates over a genomic coordinate space of reference sequence
// & position defined over the reference sequences to which the
// requested read group sets are aligned.
//
// If a target positional range is specified, search returns all reads
// whose alignment to the reference genome overlap the range. A query
// which specifies only read group set IDs yields all reads in those
// read group sets, including unmapped reads.
//
// All reads returned (including reads on subsequent pages) are ordered
// by genomic coordinate (reference sequence & position). Reads with
// equivalent genomic coordinates are returned in a deterministic
// order.
//
// Implements GlobalAllianceApi.searchReads.
func (r *ReadsService) Search(searchreadsrequest *SearchReadsRequest) *ReadsSearchCall {
	c := &ReadsSearchCall{s: r.s, opt_: make(map[string]interface{})}
	c.searchreadsrequest = searchreadsrequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ReadsSearchCall) Fields(s ...googleapi.Field) *ReadsSearchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ReadsSearchCall) Context(ctx context.Context) *ReadsSearchCall {
	c.ctx_ = ctx
	return c
}

func (c *ReadsSearchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.searchreadsrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "reads/search")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.reads.search" call.
// Exactly one of *SearchReadsResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *SearchReadsResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ReadsSearchCall) Do() (*SearchReadsResponse, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &SearchReadsResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Gets a list of reads for one or more read group sets. Reads search operates over a genomic coordinate space of reference sequence \u0026 position defined over the reference sequences to which the requested read group sets are aligned.\n\nIf a target positional range is specified, search returns all reads whose alignment to the reference genome overlap the range. A query which specifies only read group set IDs yields all reads in those read group sets, including unmapped reads.\n\nAll reads returned (including reads on subsequent pages) are ordered by genomic coordinate (reference sequence \u0026 position). Reads with equivalent genomic coordinates are returned in a deterministic order.\n\nImplements GlobalAllianceApi.searchReads.",
	//   "httpMethod": "POST",
	//   "id": "genomics.reads.search",
	//   "path": "reads/search",
	//   "request": {
	//     "$ref": "SearchReadsRequest"
	//   },
	//   "response": {
	//     "$ref": "SearchReadsResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics",
	//     "https://www.googleapis.com/auth/genomics.readonly"
	//   ]
	// }

}

// method id "genomics.references.get":

type ReferencesGetCall struct {
	s           *Service
	referenceId string
	opt_        map[string]interface{}
	ctx_        context.Context
}

// Get: Gets a reference.
//
// Implements GlobalAllianceApi.getReference.
func (r *ReferencesService) Get(referenceId string) *ReferencesGetCall {
	c := &ReferencesGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.referenceId = referenceId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ReferencesGetCall) Fields(s ...googleapi.Field) *ReferencesGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ReferencesGetCall) IfNoneMatch(entityTag string) *ReferencesGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ReferencesGetCall) Context(ctx context.Context) *ReferencesGetCall {
	c.ctx_ = ctx
	return c
}

func (c *ReferencesGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "references/{referenceId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"referenceId": c.referenceId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if v, ok := c.opt_["ifNoneMatch"]; ok {
		req.Header.Set("If-None-Match", fmt.Sprintf("%v", v))
	}
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.references.get" call.
// Exactly one of *Reference or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *Reference.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ReferencesGetCall) Do() (*Reference, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &Reference{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Gets a reference.\n\nImplements GlobalAllianceApi.getReference.",
	//   "httpMethod": "GET",
	//   "id": "genomics.references.get",
	//   "parameterOrder": [
	//     "referenceId"
	//   ],
	//   "parameters": {
	//     "referenceId": {
	//       "description": "The ID of the reference.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "references/{referenceId}",
	//   "response": {
	//     "$ref": "Reference"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics",
	//     "https://www.googleapis.com/auth/genomics.readonly"
	//   ]
	// }

}

// method id "genomics.references.search":

type ReferencesSearchCall struct {
	s                       *Service
	searchreferencesrequest *SearchReferencesRequest
	opt_                    map[string]interface{}
	ctx_                    context.Context
}

// Search: Searches for references which match the given
// criteria.
//
// Implements GlobalAllianceApi.searchReferences.
func (r *ReferencesService) Search(searchreferencesrequest *SearchReferencesRequest) *ReferencesSearchCall {
	c := &ReferencesSearchCall{s: r.s, opt_: make(map[string]interface{})}
	c.searchreferencesrequest = searchreferencesrequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ReferencesSearchCall) Fields(s ...googleapi.Field) *ReferencesSearchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ReferencesSearchCall) Context(ctx context.Context) *ReferencesSearchCall {
	c.ctx_ = ctx
	return c
}

func (c *ReferencesSearchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.searchreferencesrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "references/search")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.references.search" call.
// Exactly one of *SearchReferencesResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *SearchReferencesResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ReferencesSearchCall) Do() (*SearchReferencesResponse, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &SearchReferencesResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Searches for references which match the given criteria.\n\nImplements GlobalAllianceApi.searchReferences.",
	//   "httpMethod": "POST",
	//   "id": "genomics.references.search",
	//   "path": "references/search",
	//   "request": {
	//     "$ref": "SearchReferencesRequest"
	//   },
	//   "response": {
	//     "$ref": "SearchReferencesResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics",
	//     "https://www.googleapis.com/auth/genomics.readonly"
	//   ]
	// }

}

// method id "genomics.references.bases.list":

type ReferencesBasesListCall struct {
	s           *Service
	referenceId string
	opt_        map[string]interface{}
	ctx_        context.Context
}

// List: Lists the bases in a reference, optionally restricted to a
// range.
//
// Implements GlobalAllianceApi.getReferenceBases.
func (r *ReferencesBasesService) List(referenceId string) *ReferencesBasesListCall {
	c := &ReferencesBasesListCall{s: r.s, opt_: make(map[string]interface{})}
	c.referenceId = referenceId
	return c
}

// End sets the optional parameter "end": The end position (0-based,
// exclusive) of this query. Defaults to the length of this reference.
func (c *ReferencesBasesListCall) End(end int64) *ReferencesBasesListCall {
	c.opt_["end"] = end
	return c
}

// PageSize sets the optional parameter "pageSize": Specifies the
// maximum number of bases to return in a single page.
func (c *ReferencesBasesListCall) PageSize(pageSize int64) *ReferencesBasesListCall {
	c.opt_["pageSize"] = pageSize
	return c
}

// PageToken sets the optional parameter "pageToken": The continuation
// token, which is used to page through large result sets. To get the
// next page of results, set this parameter to the value of
// nextPageToken from the previous response.
func (c *ReferencesBasesListCall) PageToken(pageToken string) *ReferencesBasesListCall {
	c.opt_["pageToken"] = pageToken
	return c
}

// Start sets the optional parameter "start": The start position
// (0-based) of this query. Defaults to 0.
func (c *ReferencesBasesListCall) Start(start int64) *ReferencesBasesListCall {
	c.opt_["start"] = start
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ReferencesBasesListCall) Fields(s ...googleapi.Field) *ReferencesBasesListCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ReferencesBasesListCall) IfNoneMatch(entityTag string) *ReferencesBasesListCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ReferencesBasesListCall) Context(ctx context.Context) *ReferencesBasesListCall {
	c.ctx_ = ctx
	return c
}

func (c *ReferencesBasesListCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["end"]; ok {
		params.Set("end", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageSize"]; ok {
		params.Set("pageSize", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["pageToken"]; ok {
		params.Set("pageToken", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["start"]; ok {
		params.Set("start", fmt.Sprintf("%v", v))
	}
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "references/{referenceId}/bases")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"referenceId": c.referenceId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if v, ok := c.opt_["ifNoneMatch"]; ok {
		req.Header.Set("If-None-Match", fmt.Sprintf("%v", v))
	}
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.references.bases.list" call.
// Exactly one of *ListBasesResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *ListBasesResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ReferencesBasesListCall) Do() (*ListBasesResponse, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &ListBasesResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Lists the bases in a reference, optionally restricted to a range.\n\nImplements GlobalAllianceApi.getReferenceBases.",
	//   "httpMethod": "GET",
	//   "id": "genomics.references.bases.list",
	//   "parameterOrder": [
	//     "referenceId"
	//   ],
	//   "parameters": {
	//     "end": {
	//       "description": "The end position (0-based, exclusive) of this query. Defaults to the length of this reference.",
	//       "format": "int64",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "pageSize": {
	//       "description": "Specifies the maximum number of bases to return in a single page.",
	//       "format": "int32",
	//       "location": "query",
	//       "type": "integer"
	//     },
	//     "pageToken": {
	//       "description": "The continuation token, which is used to page through large result sets. To get the next page of results, set this parameter to the value of nextPageToken from the previous response.",
	//       "location": "query",
	//       "type": "string"
	//     },
	//     "referenceId": {
	//       "description": "The ID of the reference.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     },
	//     "start": {
	//       "description": "The start position (0-based) of this query. Defaults to 0.",
	//       "format": "int64",
	//       "location": "query",
	//       "type": "string"
	//     }
	//   },
	//   "path": "references/{referenceId}/bases",
	//   "response": {
	//     "$ref": "ListBasesResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics",
	//     "https://www.googleapis.com/auth/genomics.readonly"
	//   ]
	// }

}

// method id "genomics.referencesets.get":

type ReferencesetsGetCall struct {
	s              *Service
	referenceSetId string
	opt_           map[string]interface{}
	ctx_           context.Context
}

// Get: Gets a reference set.
//
// Implements GlobalAllianceApi.getReferenceSet.
func (r *ReferencesetsService) Get(referenceSetId string) *ReferencesetsGetCall {
	c := &ReferencesetsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.referenceSetId = referenceSetId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ReferencesetsGetCall) Fields(s ...googleapi.Field) *ReferencesetsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *ReferencesetsGetCall) IfNoneMatch(entityTag string) *ReferencesetsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ReferencesetsGetCall) Context(ctx context.Context) *ReferencesetsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *ReferencesetsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "referencesets/{referenceSetId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"referenceSetId": c.referenceSetId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if v, ok := c.opt_["ifNoneMatch"]; ok {
		req.Header.Set("If-None-Match", fmt.Sprintf("%v", v))
	}
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.referencesets.get" call.
// Exactly one of *ReferenceSet or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *ReferenceSet.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *ReferencesetsGetCall) Do() (*ReferenceSet, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &ReferenceSet{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Gets a reference set.\n\nImplements GlobalAllianceApi.getReferenceSet.",
	//   "httpMethod": "GET",
	//   "id": "genomics.referencesets.get",
	//   "parameterOrder": [
	//     "referenceSetId"
	//   ],
	//   "parameters": {
	//     "referenceSetId": {
	//       "description": "The ID of the reference set.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "referencesets/{referenceSetId}",
	//   "response": {
	//     "$ref": "ReferenceSet"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics",
	//     "https://www.googleapis.com/auth/genomics.readonly"
	//   ]
	// }

}

// method id "genomics.referencesets.search":

type ReferencesetsSearchCall struct {
	s                          *Service
	searchreferencesetsrequest *SearchReferenceSetsRequest
	opt_                       map[string]interface{}
	ctx_                       context.Context
}

// Search: Searches for reference sets which match the given
// criteria.
//
// Implements GlobalAllianceApi.searchReferenceSets.
func (r *ReferencesetsService) Search(searchreferencesetsrequest *SearchReferenceSetsRequest) *ReferencesetsSearchCall {
	c := &ReferencesetsSearchCall{s: r.s, opt_: make(map[string]interface{})}
	c.searchreferencesetsrequest = searchreferencesetsrequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *ReferencesetsSearchCall) Fields(s ...googleapi.Field) *ReferencesetsSearchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *ReferencesetsSearchCall) Context(ctx context.Context) *ReferencesetsSearchCall {
	c.ctx_ = ctx
	return c
}

func (c *ReferencesetsSearchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.searchreferencesetsrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "referencesets/search")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.referencesets.search" call.
// Exactly one of *SearchReferenceSetsResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *SearchReferenceSetsResponse.ServerResponse.Header or (if a response
// was returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *ReferencesetsSearchCall) Do() (*SearchReferenceSetsResponse, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &SearchReferenceSetsResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Searches for reference sets which match the given criteria.\n\nImplements GlobalAllianceApi.searchReferenceSets.",
	//   "httpMethod": "POST",
	//   "id": "genomics.referencesets.search",
	//   "path": "referencesets/search",
	//   "request": {
	//     "$ref": "SearchReferenceSetsRequest"
	//   },
	//   "response": {
	//     "$ref": "SearchReferenceSetsResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics",
	//     "https://www.googleapis.com/auth/genomics.readonly"
	//   ]
	// }

}

// method id "genomics.variants.create":

type VariantsCreateCall struct {
	s       *Service
	variant *Variant
	opt_    map[string]interface{}
	ctx_    context.Context
}

// Create: Creates a new variant.
func (r *VariantsService) Create(variant *Variant) *VariantsCreateCall {
	c := &VariantsCreateCall{s: r.s, opt_: make(map[string]interface{})}
	c.variant = variant
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *VariantsCreateCall) Fields(s ...googleapi.Field) *VariantsCreateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *VariantsCreateCall) Context(ctx context.Context) *VariantsCreateCall {
	c.ctx_ = ctx
	return c
}

func (c *VariantsCreateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.variant)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "variants")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.variants.create" call.
// Exactly one of *Variant or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Variant.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *VariantsCreateCall) Do() (*Variant, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &Variant{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Creates a new variant.",
	//   "httpMethod": "POST",
	//   "id": "genomics.variants.create",
	//   "path": "variants",
	//   "request": {
	//     "$ref": "Variant"
	//   },
	//   "response": {
	//     "$ref": "Variant"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.variants.delete":

type VariantsDeleteCall struct {
	s         *Service
	variantId string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Delete: Deletes a variant.
func (r *VariantsService) Delete(variantId string) *VariantsDeleteCall {
	c := &VariantsDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.variantId = variantId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *VariantsDeleteCall) Fields(s ...googleapi.Field) *VariantsDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *VariantsDeleteCall) Context(ctx context.Context) *VariantsDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *VariantsDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "variants/{variantId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"variantId": c.variantId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.variants.delete" call.
func (c *VariantsDeleteCall) Do() error {
	res, err := c.doRequest("json")
	if err != nil {
		return err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return err
	}
	return nil
	// {
	//   "description": "Deletes a variant.",
	//   "httpMethod": "DELETE",
	//   "id": "genomics.variants.delete",
	//   "parameterOrder": [
	//     "variantId"
	//   ],
	//   "parameters": {
	//     "variantId": {
	//       "description": "The ID of the variant to be deleted.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "variants/{variantId}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.variants.get":

type VariantsGetCall struct {
	s         *Service
	variantId string
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Get: Gets a variant by ID.
func (r *VariantsService) Get(variantId string) *VariantsGetCall {
	c := &VariantsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.variantId = variantId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *VariantsGetCall) Fields(s ...googleapi.Field) *VariantsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *VariantsGetCall) IfNoneMatch(entityTag string) *VariantsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *VariantsGetCall) Context(ctx context.Context) *VariantsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *VariantsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "variants/{variantId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"variantId": c.variantId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if v, ok := c.opt_["ifNoneMatch"]; ok {
		req.Header.Set("If-None-Match", fmt.Sprintf("%v", v))
	}
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.variants.get" call.
// Exactly one of *Variant or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Variant.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *VariantsGetCall) Do() (*Variant, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &Variant{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Gets a variant by ID.",
	//   "httpMethod": "GET",
	//   "id": "genomics.variants.get",
	//   "parameterOrder": [
	//     "variantId"
	//   ],
	//   "parameters": {
	//     "variantId": {
	//       "description": "The ID of the variant.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "variants/{variantId}",
	//   "response": {
	//     "$ref": "Variant"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics",
	//     "https://www.googleapis.com/auth/genomics.readonly"
	//   ]
	// }

}

// method id "genomics.variants.search":

type VariantsSearchCall struct {
	s                     *Service
	searchvariantsrequest *SearchVariantsRequest
	opt_                  map[string]interface{}
	ctx_                  context.Context
}

// Search: Gets a list of variants matching the criteria.
//
// Implements GlobalAllianceApi.searchVariants.
func (r *VariantsService) Search(searchvariantsrequest *SearchVariantsRequest) *VariantsSearchCall {
	c := &VariantsSearchCall{s: r.s, opt_: make(map[string]interface{})}
	c.searchvariantsrequest = searchvariantsrequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *VariantsSearchCall) Fields(s ...googleapi.Field) *VariantsSearchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *VariantsSearchCall) Context(ctx context.Context) *VariantsSearchCall {
	c.ctx_ = ctx
	return c
}

func (c *VariantsSearchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.searchvariantsrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "variants/search")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.variants.search" call.
// Exactly one of *SearchVariantsResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *SearchVariantsResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *VariantsSearchCall) Do() (*SearchVariantsResponse, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &SearchVariantsResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Gets a list of variants matching the criteria.\n\nImplements GlobalAllianceApi.searchVariants.",
	//   "httpMethod": "POST",
	//   "id": "genomics.variants.search",
	//   "path": "variants/search",
	//   "request": {
	//     "$ref": "SearchVariantsRequest"
	//   },
	//   "response": {
	//     "$ref": "SearchVariantsResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics",
	//     "https://www.googleapis.com/auth/genomics.readonly"
	//   ]
	// }

}

// method id "genomics.variants.update":

type VariantsUpdateCall struct {
	s         *Service
	variantId string
	variant   *Variant
	opt_      map[string]interface{}
	ctx_      context.Context
}

// Update: Updates a variant's names and info fields. All other
// modifications are silently ignored. Returns the modified variant
// without its calls.
func (r *VariantsService) Update(variantId string, variant *Variant) *VariantsUpdateCall {
	c := &VariantsUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.variantId = variantId
	c.variant = variant
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *VariantsUpdateCall) Fields(s ...googleapi.Field) *VariantsUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *VariantsUpdateCall) Context(ctx context.Context) *VariantsUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *VariantsUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.variant)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "variants/{variantId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"variantId": c.variantId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.variants.update" call.
// Exactly one of *Variant or error will be non-nil. Any non-2xx status
// code is an error. Response headers are in either
// *Variant.ServerResponse.Header or (if a response was returned at all)
// in error.(*googleapi.Error).Header. Use googleapi.IsNotModified to
// check whether the returned error was because http.StatusNotModified
// was returned.
func (c *VariantsUpdateCall) Do() (*Variant, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &Variant{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Updates a variant's names and info fields. All other modifications are silently ignored. Returns the modified variant without its calls.",
	//   "httpMethod": "PUT",
	//   "id": "genomics.variants.update",
	//   "parameterOrder": [
	//     "variantId"
	//   ],
	//   "parameters": {
	//     "variantId": {
	//       "description": "The ID of the variant to be updated.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "variants/{variantId}",
	//   "request": {
	//     "$ref": "Variant"
	//   },
	//   "response": {
	//     "$ref": "Variant"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.variantsets.create":

type VariantsetsCreateCall struct {
	s          *Service
	variantset *VariantSet
	opt_       map[string]interface{}
	ctx_       context.Context
}

// Create: Creates a new variant set (only necessary in v1).
//
// The provided variant set must have a valid datasetId set - all other
// fields are optional. Note that the id field will be ignored, as this
// is assigned by the server.
func (r *VariantsetsService) Create(variantset *VariantSet) *VariantsetsCreateCall {
	c := &VariantsetsCreateCall{s: r.s, opt_: make(map[string]interface{})}
	c.variantset = variantset
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *VariantsetsCreateCall) Fields(s ...googleapi.Field) *VariantsetsCreateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *VariantsetsCreateCall) Context(ctx context.Context) *VariantsetsCreateCall {
	c.ctx_ = ctx
	return c
}

func (c *VariantsetsCreateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.variantset)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "variantsets")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.variantsets.create" call.
// Exactly one of *VariantSet or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *VariantSet.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *VariantsetsCreateCall) Do() (*VariantSet, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &VariantSet{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Creates a new variant set (only necessary in v1).\n\nThe provided variant set must have a valid datasetId set - all other fields are optional. Note that the id field will be ignored, as this is assigned by the server.",
	//   "httpMethod": "POST",
	//   "id": "genomics.variantsets.create",
	//   "path": "variantsets",
	//   "request": {
	//     "$ref": "VariantSet"
	//   },
	//   "response": {
	//     "$ref": "VariantSet"
	//   }
	// }

}

// method id "genomics.variantsets.delete":

type VariantsetsDeleteCall struct {
	s            *Service
	variantSetId string
	opt_         map[string]interface{}
	ctx_         context.Context
}

// Delete: Deletes the contents of a variant set. The variant set object
// is not deleted.
func (r *VariantsetsService) Delete(variantSetId string) *VariantsetsDeleteCall {
	c := &VariantsetsDeleteCall{s: r.s, opt_: make(map[string]interface{})}
	c.variantSetId = variantSetId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *VariantsetsDeleteCall) Fields(s ...googleapi.Field) *VariantsetsDeleteCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *VariantsetsDeleteCall) Context(ctx context.Context) *VariantsetsDeleteCall {
	c.ctx_ = ctx
	return c
}

func (c *VariantsetsDeleteCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "variantsets/{variantSetId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("DELETE", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"variantSetId": c.variantSetId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.variantsets.delete" call.
func (c *VariantsetsDeleteCall) Do() error {
	res, err := c.doRequest("json")
	if err != nil {
		return err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return err
	}
	return nil
	// {
	//   "description": "Deletes the contents of a variant set. The variant set object is not deleted.",
	//   "httpMethod": "DELETE",
	//   "id": "genomics.variantsets.delete",
	//   "parameterOrder": [
	//     "variantSetId"
	//   ],
	//   "parameters": {
	//     "variantSetId": {
	//       "description": "The ID of the variant set to be deleted.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "variantsets/{variantSetId}",
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.variantsets.export":

type VariantsetsExportCall struct {
	s                       *Service
	variantSetId            string
	exportvariantsetrequest *ExportVariantSetRequest
	opt_                    map[string]interface{}
	ctx_                    context.Context
}

// Export: Exports variant set data to an external destination.
func (r *VariantsetsService) Export(variantSetId string, exportvariantsetrequest *ExportVariantSetRequest) *VariantsetsExportCall {
	c := &VariantsetsExportCall{s: r.s, opt_: make(map[string]interface{})}
	c.variantSetId = variantSetId
	c.exportvariantsetrequest = exportvariantsetrequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *VariantsetsExportCall) Fields(s ...googleapi.Field) *VariantsetsExportCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *VariantsetsExportCall) Context(ctx context.Context) *VariantsetsExportCall {
	c.ctx_ = ctx
	return c
}

func (c *VariantsetsExportCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.exportvariantsetrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "variantsets/{variantSetId}/export")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"variantSetId": c.variantSetId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.variantsets.export" call.
// Exactly one of *ExportVariantSetResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *ExportVariantSetResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *VariantsetsExportCall) Do() (*ExportVariantSetResponse, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &ExportVariantSetResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Exports variant set data to an external destination.",
	//   "httpMethod": "POST",
	//   "id": "genomics.variantsets.export",
	//   "parameterOrder": [
	//     "variantSetId"
	//   ],
	//   "parameters": {
	//     "variantSetId": {
	//       "description": "Required. The ID of the variant set that contains variant data which should be exported. The caller must have READ access to this variant set.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "variantsets/{variantSetId}/export",
	//   "request": {
	//     "$ref": "ExportVariantSetRequest"
	//   },
	//   "response": {
	//     "$ref": "ExportVariantSetResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/bigquery",
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.variantsets.get":

type VariantsetsGetCall struct {
	s            *Service
	variantSetId string
	opt_         map[string]interface{}
	ctx_         context.Context
}

// Get: Gets a variant set by ID.
func (r *VariantsetsService) Get(variantSetId string) *VariantsetsGetCall {
	c := &VariantsetsGetCall{s: r.s, opt_: make(map[string]interface{})}
	c.variantSetId = variantSetId
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *VariantsetsGetCall) Fields(s ...googleapi.Field) *VariantsetsGetCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// IfNoneMatch sets the optional parameter which makes the operation
// fail if the object's ETag matches the given value. This is useful for
// getting updates only after the object has changed since the last
// request. Use googleapi.IsNotModified to check whether the response
// error from Do is the result of In-None-Match.
func (c *VariantsetsGetCall) IfNoneMatch(entityTag string) *VariantsetsGetCall {
	c.opt_["ifNoneMatch"] = entityTag
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *VariantsetsGetCall) Context(ctx context.Context) *VariantsetsGetCall {
	c.ctx_ = ctx
	return c
}

func (c *VariantsetsGetCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "variantsets/{variantSetId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("GET", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"variantSetId": c.variantSetId,
	})
	req.Header.Set("User-Agent", c.s.userAgent())
	if v, ok := c.opt_["ifNoneMatch"]; ok {
		req.Header.Set("If-None-Match", fmt.Sprintf("%v", v))
	}
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.variantsets.get" call.
// Exactly one of *VariantSet or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *VariantSet.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *VariantsetsGetCall) Do() (*VariantSet, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &VariantSet{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Gets a variant set by ID.",
	//   "httpMethod": "GET",
	//   "id": "genomics.variantsets.get",
	//   "parameterOrder": [
	//     "variantSetId"
	//   ],
	//   "parameters": {
	//     "variantSetId": {
	//       "description": "Required. The ID of the variant set.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "variantsets/{variantSetId}",
	//   "response": {
	//     "$ref": "VariantSet"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics",
	//     "https://www.googleapis.com/auth/genomics.readonly"
	//   ]
	// }

}

// method id "genomics.variantsets.importVariants":

type VariantsetsImportVariantsCall struct {
	s                     *Service
	variantSetId          string
	importvariantsrequest *ImportVariantsRequest
	opt_                  map[string]interface{}
	ctx_                  context.Context
}

// ImportVariants: Creates variant data by asynchronously importing the
// provided information.
//
// The variants for import will be merged with any existing data and
// each other according to the behavior of mergeVariants. In particular,
// this means for merged VCF variants that have conflicting INFO fields,
// some data will be arbitrarily discarded. As a special case, for
// single-sample VCF files, QUAL and FILTER fields will be moved to the
// call level; these are sometimes interpreted in a call-specific
// context. Imported VCF headers are appended to the metadata already in
// a variant set.
func (r *VariantsetsService) ImportVariants(variantSetId string, importvariantsrequest *ImportVariantsRequest) *VariantsetsImportVariantsCall {
	c := &VariantsetsImportVariantsCall{s: r.s, opt_: make(map[string]interface{})}
	c.variantSetId = variantSetId
	c.importvariantsrequest = importvariantsrequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *VariantsetsImportVariantsCall) Fields(s ...googleapi.Field) *VariantsetsImportVariantsCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *VariantsetsImportVariantsCall) Context(ctx context.Context) *VariantsetsImportVariantsCall {
	c.ctx_ = ctx
	return c
}

func (c *VariantsetsImportVariantsCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.importvariantsrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "variantsets/{variantSetId}/importVariants")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"variantSetId": c.variantSetId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.variantsets.importVariants" call.
// Exactly one of *ImportVariantsResponse or error will be non-nil. Any
// non-2xx status code is an error. Response headers are in either
// *ImportVariantsResponse.ServerResponse.Header or (if a response was
// returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *VariantsetsImportVariantsCall) Do() (*ImportVariantsResponse, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &ImportVariantsResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Creates variant data by asynchronously importing the provided information.\n\nThe variants for import will be merged with any existing data and each other according to the behavior of mergeVariants. In particular, this means for merged VCF variants that have conflicting INFO fields, some data will be arbitrarily discarded. As a special case, for single-sample VCF files, QUAL and FILTER fields will be moved to the call level; these are sometimes interpreted in a call-specific context. Imported VCF headers are appended to the metadata already in a variant set.",
	//   "httpMethod": "POST",
	//   "id": "genomics.variantsets.importVariants",
	//   "parameterOrder": [
	//     "variantSetId"
	//   ],
	//   "parameters": {
	//     "variantSetId": {
	//       "description": "Required. The variant set to which variant data should be imported.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "variantsets/{variantSetId}/importVariants",
	//   "request": {
	//     "$ref": "ImportVariantsRequest"
	//   },
	//   "response": {
	//     "$ref": "ImportVariantsResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/devstorage.read_write",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.variantsets.mergeVariants":

type VariantsetsMergeVariantsCall struct {
	s                    *Service
	variantSetId         string
	mergevariantsrequest *MergeVariantsRequest
	opt_                 map[string]interface{}
	ctx_                 context.Context
}

// MergeVariants: Merges the given variants with existing variants. Each
// variant will be merged with an existing variant that matches its
// reference sequence, start, end, reference bases, and alternative
// bases. If no such variant exists, a new one will be created.
//
// When variants are merged, the call information from the new variant
// is added to the existing variant, and other fields (such as key/value
// pairs) are discarded.
func (r *VariantsetsService) MergeVariants(variantSetId string, mergevariantsrequest *MergeVariantsRequest) *VariantsetsMergeVariantsCall {
	c := &VariantsetsMergeVariantsCall{s: r.s, opt_: make(map[string]interface{})}
	c.variantSetId = variantSetId
	c.mergevariantsrequest = mergevariantsrequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *VariantsetsMergeVariantsCall) Fields(s ...googleapi.Field) *VariantsetsMergeVariantsCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *VariantsetsMergeVariantsCall) Context(ctx context.Context) *VariantsetsMergeVariantsCall {
	c.ctx_ = ctx
	return c
}

func (c *VariantsetsMergeVariantsCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.mergevariantsrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "variantsets/{variantSetId}/mergeVariants")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"variantSetId": c.variantSetId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.variantsets.mergeVariants" call.
func (c *VariantsetsMergeVariantsCall) Do() error {
	res, err := c.doRequest("json")
	if err != nil {
		return err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return err
	}
	return nil
	// {
	//   "description": "Merges the given variants with existing variants. Each variant will be merged with an existing variant that matches its reference sequence, start, end, reference bases, and alternative bases. If no such variant exists, a new one will be created.\n\nWhen variants are merged, the call information from the new variant is added to the existing variant, and other fields (such as key/value pairs) are discarded.",
	//   "httpMethod": "POST",
	//   "id": "genomics.variantsets.mergeVariants",
	//   "parameterOrder": [
	//     "variantSetId"
	//   ],
	//   "parameters": {
	//     "variantSetId": {
	//       "description": "The destination variant set.",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "variantsets/{variantSetId}/mergeVariants",
	//   "request": {
	//     "$ref": "MergeVariantsRequest"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.variantsets.patch":

type VariantsetsPatchCall struct {
	s            *Service
	variantSetId string
	variantset   *VariantSet
	opt_         map[string]interface{}
	ctx_         context.Context
}

// Patch: Updates a variant set's metadata. All other modifications are
// silently ignored. This method supports patch semantics.
func (r *VariantsetsService) Patch(variantSetId string, variantset *VariantSet) *VariantsetsPatchCall {
	c := &VariantsetsPatchCall{s: r.s, opt_: make(map[string]interface{})}
	c.variantSetId = variantSetId
	c.variantset = variantset
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *VariantsetsPatchCall) Fields(s ...googleapi.Field) *VariantsetsPatchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *VariantsetsPatchCall) Context(ctx context.Context) *VariantsetsPatchCall {
	c.ctx_ = ctx
	return c
}

func (c *VariantsetsPatchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.variantset)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "variantsets/{variantSetId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PATCH", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"variantSetId": c.variantSetId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.variantsets.patch" call.
// Exactly one of *VariantSet or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *VariantSet.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *VariantsetsPatchCall) Do() (*VariantSet, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &VariantSet{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Updates a variant set's metadata. All other modifications are silently ignored. This method supports patch semantics.",
	//   "httpMethod": "PATCH",
	//   "id": "genomics.variantsets.patch",
	//   "parameterOrder": [
	//     "variantSetId"
	//   ],
	//   "parameters": {
	//     "variantSetId": {
	//       "description": "The ID of the variant to be updated (must already exist).",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "variantsets/{variantSetId}",
	//   "request": {
	//     "$ref": "VariantSet"
	//   },
	//   "response": {
	//     "$ref": "VariantSet"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}

// method id "genomics.variantsets.search":

type VariantsetsSearchCall struct {
	s                        *Service
	searchvariantsetsrequest *SearchVariantSetsRequest
	opt_                     map[string]interface{}
	ctx_                     context.Context
}

// Search: Returns a list of all variant sets matching search
// criteria.
//
// Implements GlobalAllianceApi.searchVariantSets.
func (r *VariantsetsService) Search(searchvariantsetsrequest *SearchVariantSetsRequest) *VariantsetsSearchCall {
	c := &VariantsetsSearchCall{s: r.s, opt_: make(map[string]interface{})}
	c.searchvariantsetsrequest = searchvariantsetsrequest
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *VariantsetsSearchCall) Fields(s ...googleapi.Field) *VariantsetsSearchCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *VariantsetsSearchCall) Context(ctx context.Context) *VariantsetsSearchCall {
	c.ctx_ = ctx
	return c
}

func (c *VariantsetsSearchCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.searchvariantsetsrequest)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "variantsets/search")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("POST", urls, body)
	googleapi.SetOpaque(req.URL)
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.variantsets.search" call.
// Exactly one of *SearchVariantSetsResponse or error will be non-nil.
// Any non-2xx status code is an error. Response headers are in either
// *SearchVariantSetsResponse.ServerResponse.Header or (if a response
// was returned at all) in error.(*googleapi.Error).Header. Use
// googleapi.IsNotModified to check whether the returned error was
// because http.StatusNotModified was returned.
func (c *VariantsetsSearchCall) Do() (*SearchVariantSetsResponse, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &SearchVariantSetsResponse{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Returns a list of all variant sets matching search criteria.\n\nImplements GlobalAllianceApi.searchVariantSets.",
	//   "httpMethod": "POST",
	//   "id": "genomics.variantsets.search",
	//   "path": "variantsets/search",
	//   "request": {
	//     "$ref": "SearchVariantSetsRequest"
	//   },
	//   "response": {
	//     "$ref": "SearchVariantSetsResponse"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics",
	//     "https://www.googleapis.com/auth/genomics.readonly"
	//   ]
	// }

}

// method id "genomics.variantsets.update":

type VariantsetsUpdateCall struct {
	s            *Service
	variantSetId string
	variantset   *VariantSet
	opt_         map[string]interface{}
	ctx_         context.Context
}

// Update: Updates a variant set's metadata. All other modifications are
// silently ignored.
func (r *VariantsetsService) Update(variantSetId string, variantset *VariantSet) *VariantsetsUpdateCall {
	c := &VariantsetsUpdateCall{s: r.s, opt_: make(map[string]interface{})}
	c.variantSetId = variantSetId
	c.variantset = variantset
	return c
}

// Fields allows partial responses to be retrieved.
// See https://developers.google.com/gdata/docs/2.0/basics#PartialResponse
// for more information.
func (c *VariantsetsUpdateCall) Fields(s ...googleapi.Field) *VariantsetsUpdateCall {
	c.opt_["fields"] = googleapi.CombineFields(s)
	return c
}

// Context sets the context to be used in this call's Do method.
// Any pending HTTP request will be aborted if the provided context
// is canceled.
func (c *VariantsetsUpdateCall) Context(ctx context.Context) *VariantsetsUpdateCall {
	c.ctx_ = ctx
	return c
}

func (c *VariantsetsUpdateCall) doRequest(alt string) (*http.Response, error) {
	var body io.Reader = nil
	body, err := googleapi.WithoutDataWrapper.JSONReader(c.variantset)
	if err != nil {
		return nil, err
	}
	ctype := "application/json"
	params := make(url.Values)
	params.Set("alt", alt)
	if v, ok := c.opt_["fields"]; ok {
		params.Set("fields", fmt.Sprintf("%v", v))
	}
	urls := googleapi.ResolveRelative(c.s.BasePath, "variantsets/{variantSetId}")
	urls += "?" + params.Encode()
	req, _ := http.NewRequest("PUT", urls, body)
	googleapi.Expand(req.URL, map[string]string{
		"variantSetId": c.variantSetId,
	})
	req.Header.Set("Content-Type", ctype)
	req.Header.Set("User-Agent", c.s.userAgent())
	if c.ctx_ != nil {
		return ctxhttp.Do(c.ctx_, c.s.client, req)
	}
	return c.s.client.Do(req)
}

// Do executes the "genomics.variantsets.update" call.
// Exactly one of *VariantSet or error will be non-nil. Any non-2xx
// status code is an error. Response headers are in either
// *VariantSet.ServerResponse.Header or (if a response was returned at
// all) in error.(*googleapi.Error).Header. Use googleapi.IsNotModified
// to check whether the returned error was because
// http.StatusNotModified was returned.
func (c *VariantsetsUpdateCall) Do() (*VariantSet, error) {
	res, err := c.doRequest("json")
	if res != nil && res.StatusCode == http.StatusNotModified {
		if res.Body != nil {
			res.Body.Close()
		}
		return nil, &googleapi.Error{
			Code:   res.StatusCode,
			Header: res.Header,
		}
	}
	if err != nil {
		return nil, err
	}
	defer googleapi.CloseBody(res)
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, err
	}
	ret := &VariantSet{
		ServerResponse: googleapi.ServerResponse{
			Header:         res.Header,
			HTTPStatusCode: res.StatusCode,
		},
	}
	if err := json.NewDecoder(res.Body).Decode(&ret); err != nil {
		return nil, err
	}
	return ret, nil
	// {
	//   "description": "Updates a variant set's metadata. All other modifications are silently ignored.",
	//   "httpMethod": "PUT",
	//   "id": "genomics.variantsets.update",
	//   "parameterOrder": [
	//     "variantSetId"
	//   ],
	//   "parameters": {
	//     "variantSetId": {
	//       "description": "The ID of the variant to be updated (must already exist).",
	//       "location": "path",
	//       "required": true,
	//       "type": "string"
	//     }
	//   },
	//   "path": "variantsets/{variantSetId}",
	//   "request": {
	//     "$ref": "VariantSet"
	//   },
	//   "response": {
	//     "$ref": "VariantSet"
	//   },
	//   "scopes": [
	//     "https://www.googleapis.com/auth/cloud-platform",
	//     "https://www.googleapis.com/auth/genomics"
	//   ]
	// }

}
