package types

//
// import "fmt"
//
// // CVSSv2 represents the Common Vulnerability Scoring System (CVSS), that assesses the severity of
// // vulnerabilities.
// // It describes the CVSS score, but also a vector describing the components from which the score
// // was calculated. This provides users of the score confidence in its correctness and provides
// // insight into the nature of the vulnerability.
// //
// // Reference: https://nvd.nist.gov/CVSS/Vector-v2.aspx
// type CVSSv2 struct {
// 	// Base Vectors
// 	AccessVector     CVSSValue
// 	AccessComplexity CVSSValue
// 	Authentication   CVSSValue
// 	ConfImpact       CVSSValue
// 	IntegImpact      CVSSValue
// 	AvailImpact      CVSSValue
// 	// Temporal Vectors
// 	Exploitability   CVSSValue
// 	RemediationLevel CVSSValue
// 	ReportConfidence CVSSValue
// 	// Environmental Vectors
// 	CollateralDamagePotential        CVSSValue
// 	TargetDistribution               CVSSValue
// 	SystemConfidentialityRequirement CVSSValue
// 	SystemIntegrityRequirement       CVSSValue
// 	SystemAvailabilityRequirement    CVSSValue
// }
//
// func NewCVSSv2(value string) (*CVSSv2, error) {
//
// }
//
// // CVSSValue is the comprehensible value for a CVSS metric.
// type CVSSValue string
//
// // Metric acronym + Value abbreviation -> Comprehensible metric value.
// var toValue map[string]func(string) (CVSSValue, error)
//
// func init() {
// 	parsers = make(map[string]func(string) (CVSSValue, error), 14)
// 	toValue["AV"] = av
// 	toValue["AC"] = ac
// 	toValue["Au"] = au
// 	toValue["C"] = cAndIAndA
// 	toValue["I"] = cAndIAndA
// 	toValue["A"] = cAndIAndA
// 	toValue["E"] = e
// 	toValue["RL"] = rl
// 	toValue["RC"] = rc
// 	toValue["CDP"] = cdp
// 	toValue["TD"] = td
// 	toValue["CR"] = crAndIrAndAr
// 	toValue["IR"] = crAndIrAndAr
// 	toValue["AR"] = crAndIrAndAr
// }
//
// func av(v string) (CVSSValue, error) {
// 	switch v {
// 	case "L":
// 		return CVSSValue("Local access"), nil
// 	case "A":
// 		return CVSSValue("Adjacent Network"), nil
// 	case "N":
// 		return CVSSValue("Network"), nil
// 	default:
// 		return "", fmt.Errorf("%v is not a valid value for AV", v)
// 	}
// }
//
// func ac(v string) (CVSSValue, error) {
// 	switch v {
// 	case "H":
// 		return CVSSValue("High"), nil
// 	case "M":
// 		return CVSSValue("Medium"), nil
// 	case "L":
// 		return CVSSValue("Low"), nil
// 	default:
// 		return "", fmt.Errorf("%v is not a valid value for AC", v)
// 	}
// }
//
// func au(v string) (CVSSValue, error) {
// 	switch v {
// 	case "N":
// 		return CVSSValue("None required"), nil
// 	case "S":
// 		return CVSSValue("Requires single instance"), nil
// 	case "M":
// 		return CVSSValue("Requires multiple instances"), nil
// 	default:
// 		return "", fmt.Errorf("%v is not a valid value for Au", v)
// 	}
// }
//
// func cAndIAndA(v string) (CVSSValue, error) {
// 	switch v {
// 	case "N":
// 		return CVSSValue("None"), nil
// 	case "P":
// 		return CVSSValue("Partial"), nil
// 	case "C":
// 		return CVSSValue("Complete"), nil
// 	default:
// 		return "", fmt.Errorf("%v is not a valid value for C/I/A", v)
// 	}
// }
//
// func e(v string) (CVSSValue, error) {
// 	switch v {
// 	case "U":
// 		return CVSSValue("Unproven"), nil
// 	case "POC":
// 		return CVSSValue("Proof-of-concept"), nil
// 	case "F":
// 		return CVSSValue("Functional"), nil
// 	case "H":
// 		return CVSSValue("High"), nil
// 	case "ND":
// 		return CVSSValue("Not Defined"), nil
// 	default:
// 		return "", fmt.Errorf("%v is not a valid value for E", v)
// 	}
// }
//
// func rl(v string) (CVSSValue, error) {
// 	switch v {
// 	case "OF":
// 		return CVSSValue("Official-fix"), nil
// 	case "T":
// 		return CVSSValue("Temporary-fix"), nil
// 	case "W":
// 		return CVSSValue("Workaround"), nil
// 	case "U":
// 		return CVSSValue("Unavailable"), nil
// 	case "ND":
// 		return CVSSValue("Not Defined"), nil
// 	default:
// 		return "", fmt.Errorf("%v is not a valid value for RL", v)
// 	}
// }
//
// func rc(v string) (CVSSValue, error) {
// 	switch v {
// 	case "UC":
// 		return CVSSValue("Unconfirmed"), nil
// 	case "UR":
// 		return CVSSValue("Uncorroborated"), nil
// 	case "C":
// 		return CVSSValue("Confirmed"), nil
// 	case "ND":
// 		return CVSSValue("Not Defined"), nil
// 	default:
// 		return "", fmt.Errorf("%v is not a valid value for RC", v)
// 	}
// }
//
// func cdp(v string) (CVSSValue, error) {
// 	switch v {
// 	case "N":
// 		return CVSSValue("None"), nil
// 	case "L":
// 		return CVSSValue("Low"), nil
// 	case "LM":
// 		return CVSSValue("Low-Medium"), nil
// 	case "MH":
// 		return CVSSValue("Medium-High"), nil
// 	case "H":
// 		return CVSSValue("High"), nil
// 	case "ND":
// 		return CVSSValue("Not Defined"), nil
// 	default:
// 		return "", fmt.Errorf("%v is not a valid value for CDP", v)
// 	}
// }
//
// func td(v string) (CVSSValue, error) {
// 	switch v {
// 	case "N":
// 		return CVSSValue("None (0%)"), nil
// 	case "L":
// 		return CVSSValue("Low (1-25%)"), nil
// 	case "M":
// 		return CVSSValue("Medium (26-75%)"), nil
// 	case "H":
// 		return CVSSValue("High (76-100%)"), nil
// 	case "ND":
// 		return CVSSValue("Not Defined"), nil
// 	default:
// 		return "", fmt.Errorf("%v is not a valid value for TD", v)
// 	}
// }
//
// func crAndIrAndAr(v string) (CVSSValue, error) {
// 	switch v {
// 	case "L":
// 		return CVSSValue("Low"), nil
// 	case "M":
// 		return CVSSValue("Medium"), nil
// 	case "H":
// 		return CVSSValue("High"), nil
// 	case "ND":
// 		return CVSSValue("Not Defined"), nil
// 	default:
// 		return "", fmt.Errorf("%v is not a valid value for CR/IR/AR", v)
// 	}
// }
