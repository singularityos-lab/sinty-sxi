package wire

type Failure int

const (
	OK Failure = iota
	ResourceLimit
	CBORType
	CBORTag
	CBORIndefinite
	CBORShortest
	CBORDuplicateKey
	CBOROrder
	CBORTrailing
	InvalidUTF8
	TextNFC
	RequiredField
	UnknownField
	StringSize
	ApplicationID
	IntegerRange
	InvalidDigestSize
	InvalidPath
	InvalidName
	EntryArchitecture
	EntryOrder
	EntryABI
	EntryKind
	InventoryOrder
	DuplicatePath
	InventoryKind
	InventoryMode
	InventorySize
	InventoryDigest
	InventoryParent
	ControlSubtree
	CaseCollision
	PayloadDigest
	InvalidStatePolicy
	InvalidHealthPolicy
	ExtensionID
	ExtensionRecord
	CriticalExtension
	Internal
)

var failureNames = [...]string{
	OK:                  "OK",
	ResourceLimit:       "SXI_V1_RESOURCE_LIMIT",
	CBORType:            "SXI_V1_CBOR_TYPE",
	CBORTag:             "SXI_V1_CBOR_TAG",
	CBORIndefinite:      "SXI_V1_CBOR_INDEFINITE",
	CBORShortest:        "SXI_V1_CBOR_SHORTEST",
	CBORDuplicateKey:    "SXI_V1_CBOR_DUPLICATE_KEY",
	CBOROrder:           "SXI_V1_CBOR_ORDER",
	CBORTrailing:        "SXI_V1_CBOR_TRAILING",
	InvalidUTF8:         "SXI_V1_UTF8",
	TextNFC:             "SXI_V1_TEXT_NFC",
	RequiredField:       "SXI_V1_REQUIRED_FIELD",
	UnknownField:        "SXI_V1_UNKNOWN_FIELD",
	StringSize:          "SXI_V1_STRING_SIZE",
	ApplicationID:       "SXI_V1_APPLICATION_ID",
	IntegerRange:        "SXI_V1_INTEGER_RANGE",
	InvalidDigestSize:   "SXI_V1_DIGEST_SIZE",
	InvalidPath:         "SXI_V1_PATH",
	InvalidName:         "SXI_V1_NAME",
	EntryArchitecture:   "SXI_V1_ENTRY_ARCHITECTURE",
	EntryOrder:          "SXI_V1_ENTRY_ORDER",
	EntryABI:            "SXI_V1_ENTRY_ABI",
	EntryKind:           "SXI_V1_ENTRY_KIND",
	InventoryOrder:      "SXI_V1_INVENTORY_ORDER",
	DuplicatePath:       "SXI_V1_DUPLICATE_PATH",
	InventoryKind:       "SXI_V1_INVENTORY_KIND",
	InventoryMode:       "SXI_V1_INVENTORY_MODE",
	InventorySize:       "SXI_V1_INVENTORY_SIZE",
	InventoryDigest:     "SXI_V1_INVENTORY_DIGEST",
	InventoryParent:     "SXI_V1_INVENTORY_PARENT",
	ControlSubtree:      "SXI_V1_CONTROL_SUBTREE",
	CaseCollision:       "SXI_V1_CASE_COLLISION",
	PayloadDigest:       "SXI_V1_PAYLOAD_DIGEST",
	InvalidStatePolicy:  "SXI_V1_STATE_POLICY",
	InvalidHealthPolicy: "SXI_V1_HEALTH_POLICY",
	ExtensionID:         "SXI_V1_EXTENSION_ID",
	ExtensionRecord:     "SXI_V1_EXTENSION_RECORD",
	CriticalExtension:   "SXI_V1_CRITICAL_EXTENSION",
	Internal:            "SXI_V1_INTERNAL",
}

func (f Failure) String() string {
	if f < 0 || int(f) >= len(failureNames) {
		return failureNames[Internal]
	}
	return failureNames[f]
}

type Error struct {
	Failure Failure
}

func (e *Error) Error() string {
	return "sxi: manifest rejected: " + e.Failure.String()
}
