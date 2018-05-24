// Code generated from FilterExpression.g4 by ANTLR 4.7.1. DO NOT EDIT.

package gen // FilterExpression
import (
	"fmt"
	"reflect"
	"strconv"

	"github.com/antlr/antlr4/runtime/Go/antlr"
)

// Suppress unused import errors
var _ = fmt.Printf
var _ = reflect.Copy
var _ = strconv.Itoa

var parserATN = []uint16{
	3, 24715, 42794, 33075, 47597, 16764, 15335, 30598, 22884, 3, 30, 303,
	4, 2, 9, 2, 4, 3, 9, 3, 4, 4, 9, 4, 4, 5, 9, 5, 4, 6, 9, 6, 4, 7, 9, 7,
	4, 8, 9, 8, 4, 9, 9, 9, 4, 10, 9, 10, 4, 11, 9, 11, 4, 12, 9, 12, 4, 13,
	9, 13, 4, 14, 9, 14, 4, 15, 9, 15, 4, 16, 9, 16, 4, 17, 9, 17, 4, 18, 9,
	18, 4, 19, 9, 19, 4, 20, 9, 20, 4, 21, 9, 21, 4, 22, 9, 22, 4, 23, 9, 23,
	3, 2, 5, 2, 48, 10, 2, 3, 2, 7, 2, 51, 10, 2, 12, 2, 14, 2, 54, 11, 2,
	3, 2, 3, 2, 3, 3, 3, 3, 3, 3, 3, 3, 7, 3, 62, 10, 3, 12, 3, 14, 3, 65,
	11, 3, 3, 4, 3, 4, 6, 4, 69, 10, 4, 13, 4, 14, 4, 70, 3, 4, 7, 4, 74, 10,
	4, 12, 4, 14, 4, 77, 11, 4, 3, 5, 3, 5, 3, 5, 3, 5, 7, 5, 83, 10, 5, 12,
	5, 14, 5, 86, 11, 5, 3, 6, 5, 6, 89, 10, 6, 3, 6, 3, 6, 3, 7, 3, 7, 7,
	7, 95, 10, 7, 12, 7, 14, 7, 98, 11, 7, 3, 7, 3, 7, 7, 7, 102, 10, 7, 12,
	7, 14, 7, 105, 11, 7, 3, 7, 3, 7, 5, 7, 109, 10, 7, 3, 8, 3, 8, 5, 8, 113,
	10, 8, 3, 9, 3, 9, 3, 10, 3, 10, 3, 10, 3, 10, 3, 10, 3, 10, 3, 10, 3,
	10, 5, 10, 125, 10, 10, 3, 10, 5, 10, 128, 10, 10, 3, 10, 3, 10, 3, 10,
	7, 10, 133, 10, 10, 12, 10, 14, 10, 136, 11, 10, 3, 10, 3, 10, 7, 10, 140,
	10, 10, 12, 10, 14, 10, 143, 11, 10, 3, 10, 3, 10, 7, 10, 147, 10, 10,
	12, 10, 14, 10, 150, 11, 10, 3, 11, 3, 11, 3, 11, 3, 11, 5, 11, 156, 10,
	11, 3, 11, 5, 11, 159, 10, 11, 3, 11, 5, 11, 162, 10, 11, 3, 12, 7, 12,
	165, 10, 12, 12, 12, 14, 12, 168, 11, 12, 3, 12, 3, 12, 3, 12, 3, 12, 7,
	12, 174, 10, 12, 12, 12, 14, 12, 177, 11, 12, 3, 12, 7, 12, 180, 10, 12,
	12, 12, 14, 12, 183, 11, 12, 3, 13, 3, 13, 7, 13, 187, 10, 13, 12, 13,
	14, 13, 190, 11, 13, 3, 13, 3, 13, 7, 13, 194, 10, 13, 12, 13, 14, 13,
	197, 11, 13, 3, 13, 3, 13, 3, 14, 3, 14, 7, 14, 203, 10, 14, 12, 14, 14,
	14, 206, 11, 14, 3, 15, 3, 15, 3, 15, 5, 15, 211, 10, 15, 3, 16, 3, 16,
	5, 16, 215, 10, 16, 3, 17, 5, 17, 218, 10, 17, 3, 17, 6, 17, 221, 10, 17,
	13, 17, 14, 17, 222, 3, 17, 5, 17, 226, 10, 17, 3, 17, 5, 17, 229, 10,
	17, 3, 18, 5, 18, 232, 10, 18, 3, 18, 6, 18, 235, 10, 18, 13, 18, 14, 18,
	236, 3, 18, 3, 18, 7, 18, 241, 10, 18, 12, 18, 14, 18, 244, 11, 18, 3,
	18, 3, 18, 6, 18, 248, 10, 18, 13, 18, 14, 18, 249, 5, 18, 252, 10, 18,
	3, 18, 5, 18, 255, 10, 18, 3, 19, 3, 19, 3, 20, 3, 20, 3, 20, 6, 20, 262,
	10, 20, 13, 20, 14, 20, 263, 5, 20, 266, 10, 20, 3, 21, 6, 21, 269, 10,
	21, 13, 21, 14, 21, 270, 3, 21, 3, 21, 6, 21, 275, 10, 21, 13, 21, 14,
	21, 276, 3, 22, 6, 22, 280, 10, 22, 13, 22, 14, 22, 281, 3, 22, 3, 22,
	6, 22, 286, 10, 22, 13, 22, 14, 22, 287, 3, 23, 7, 23, 291, 10, 23, 12,
	23, 14, 23, 294, 11, 23, 3, 23, 3, 23, 7, 23, 298, 10, 23, 12, 23, 14,
	23, 301, 11, 23, 3, 23, 2, 3, 18, 24, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20,
	22, 24, 26, 28, 30, 32, 34, 36, 38, 40, 42, 44, 2, 6, 4, 2, 4, 4, 15, 20,
	5, 2, 21, 21, 26, 26, 29, 29, 5, 2, 21, 22, 26, 26, 29, 29, 3, 2, 5, 7,
	2, 328, 2, 47, 3, 2, 2, 2, 4, 57, 3, 2, 2, 2, 6, 66, 3, 2, 2, 2, 8, 78,
	3, 2, 2, 2, 10, 88, 3, 2, 2, 2, 12, 92, 3, 2, 2, 2, 14, 112, 3, 2, 2, 2,
	16, 114, 3, 2, 2, 2, 18, 116, 3, 2, 2, 2, 20, 161, 3, 2, 2, 2, 22, 166,
	3, 2, 2, 2, 24, 184, 3, 2, 2, 2, 26, 200, 3, 2, 2, 2, 28, 210, 3, 2, 2,
	2, 30, 214, 3, 2, 2, 2, 32, 228, 3, 2, 2, 2, 34, 231, 3, 2, 2, 2, 36, 256,
	3, 2, 2, 2, 38, 265, 3, 2, 2, 2, 40, 268, 3, 2, 2, 2, 42, 279, 3, 2, 2,
	2, 44, 292, 3, 2, 2, 2, 46, 48, 5, 4, 3, 2, 47, 46, 3, 2, 2, 2, 47, 48,
	3, 2, 2, 2, 48, 52, 3, 2, 2, 2, 49, 51, 7, 25, 2, 2, 50, 49, 3, 2, 2, 2,
	51, 54, 3, 2, 2, 2, 52, 50, 3, 2, 2, 2, 52, 53, 3, 2, 2, 2, 53, 55, 3,
	2, 2, 2, 54, 52, 3, 2, 2, 2, 55, 56, 7, 2, 2, 3, 56, 3, 3, 2, 2, 2, 57,
	63, 5, 6, 4, 2, 58, 59, 5, 40, 21, 2, 59, 60, 5, 6, 4, 2, 60, 62, 3, 2,
	2, 2, 61, 58, 3, 2, 2, 2, 62, 65, 3, 2, 2, 2, 63, 61, 3, 2, 2, 2, 63, 64,
	3, 2, 2, 2, 64, 5, 3, 2, 2, 2, 65, 63, 3, 2, 2, 2, 66, 75, 5, 8, 5, 2,
	67, 69, 7, 25, 2, 2, 68, 67, 3, 2, 2, 2, 69, 70, 3, 2, 2, 2, 70, 68, 3,
	2, 2, 2, 70, 71, 3, 2, 2, 2, 71, 72, 3, 2, 2, 2, 72, 74, 5, 8, 5, 2, 73,
	68, 3, 2, 2, 2, 74, 77, 3, 2, 2, 2, 75, 73, 3, 2, 2, 2, 75, 76, 3, 2, 2,
	2, 76, 7, 3, 2, 2, 2, 77, 75, 3, 2, 2, 2, 78, 84, 5, 10, 6, 2, 79, 80,
	5, 42, 22, 2, 80, 81, 5, 10, 6, 2, 81, 83, 3, 2, 2, 2, 82, 79, 3, 2, 2,
	2, 83, 86, 3, 2, 2, 2, 84, 82, 3, 2, 2, 2, 84, 85, 3, 2, 2, 2, 85, 9, 3,
	2, 2, 2, 86, 84, 3, 2, 2, 2, 87, 89, 5, 38, 20, 2, 88, 87, 3, 2, 2, 2,
	88, 89, 3, 2, 2, 2, 89, 90, 3, 2, 2, 2, 90, 91, 5, 12, 7, 2, 91, 11, 3,
	2, 2, 2, 92, 108, 5, 14, 8, 2, 93, 95, 7, 25, 2, 2, 94, 93, 3, 2, 2, 2,
	95, 98, 3, 2, 2, 2, 96, 94, 3, 2, 2, 2, 96, 97, 3, 2, 2, 2, 97, 99, 3,
	2, 2, 2, 98, 96, 3, 2, 2, 2, 99, 103, 5, 16, 9, 2, 100, 102, 7, 25, 2,
	2, 101, 100, 3, 2, 2, 2, 102, 105, 3, 2, 2, 2, 103, 101, 3, 2, 2, 2, 103,
	104, 3, 2, 2, 2, 104, 106, 3, 2, 2, 2, 105, 103, 3, 2, 2, 2, 106, 107,
	5, 14, 8, 2, 107, 109, 3, 2, 2, 2, 108, 96, 3, 2, 2, 2, 108, 109, 3, 2,
	2, 2, 109, 13, 3, 2, 2, 2, 110, 113, 5, 30, 16, 2, 111, 113, 5, 18, 10,
	2, 112, 110, 3, 2, 2, 2, 112, 111, 3, 2, 2, 2, 113, 15, 3, 2, 2, 2, 114,
	115, 9, 2, 2, 2, 115, 17, 3, 2, 2, 2, 116, 117, 8, 10, 1, 2, 117, 118,
	5, 20, 11, 2, 118, 148, 3, 2, 2, 2, 119, 120, 12, 4, 2, 2, 120, 121, 7,
	3, 2, 2, 121, 127, 5, 28, 15, 2, 122, 124, 7, 8, 2, 2, 123, 125, 5, 22,
	12, 2, 124, 123, 3, 2, 2, 2, 124, 125, 3, 2, 2, 2, 125, 126, 3, 2, 2, 2,
	126, 128, 7, 9, 2, 2, 127, 122, 3, 2, 2, 2, 127, 128, 3, 2, 2, 2, 128,
	147, 3, 2, 2, 2, 129, 130, 12, 3, 2, 2, 130, 134, 7, 10, 2, 2, 131, 133,
	7, 25, 2, 2, 132, 131, 3, 2, 2, 2, 133, 136, 3, 2, 2, 2, 134, 132, 3, 2,
	2, 2, 134, 135, 3, 2, 2, 2, 135, 137, 3, 2, 2, 2, 136, 134, 3, 2, 2, 2,
	137, 141, 5, 14, 8, 2, 138, 140, 7, 25, 2, 2, 139, 138, 3, 2, 2, 2, 140,
	143, 3, 2, 2, 2, 141, 139, 3, 2, 2, 2, 141, 142, 3, 2, 2, 2, 142, 144,
	3, 2, 2, 2, 143, 141, 3, 2, 2, 2, 144, 145, 7, 11, 2, 2, 145, 147, 3, 2,
	2, 2, 146, 119, 3, 2, 2, 2, 146, 129, 3, 2, 2, 2, 147, 150, 3, 2, 2, 2,
	148, 146, 3, 2, 2, 2, 148, 149, 3, 2, 2, 2, 149, 19, 3, 2, 2, 2, 150, 148,
	3, 2, 2, 2, 151, 162, 5, 24, 13, 2, 152, 158, 5, 26, 14, 2, 153, 155, 7,
	8, 2, 2, 154, 156, 5, 22, 12, 2, 155, 154, 3, 2, 2, 2, 155, 156, 3, 2,
	2, 2, 156, 157, 3, 2, 2, 2, 157, 159, 7, 9, 2, 2, 158, 153, 3, 2, 2, 2,
	158, 159, 3, 2, 2, 2, 159, 162, 3, 2, 2, 2, 160, 162, 7, 24, 2, 2, 161,
	151, 3, 2, 2, 2, 161, 152, 3, 2, 2, 2, 161, 160, 3, 2, 2, 2, 162, 21, 3,
	2, 2, 2, 163, 165, 7, 25, 2, 2, 164, 163, 3, 2, 2, 2, 165, 168, 3, 2, 2,
	2, 166, 164, 3, 2, 2, 2, 166, 167, 3, 2, 2, 2, 167, 169, 3, 2, 2, 2, 168,
	166, 3, 2, 2, 2, 169, 175, 5, 14, 8, 2, 170, 171, 5, 44, 23, 2, 171, 172,
	5, 14, 8, 2, 172, 174, 3, 2, 2, 2, 173, 170, 3, 2, 2, 2, 174, 177, 3, 2,
	2, 2, 175, 173, 3, 2, 2, 2, 175, 176, 3, 2, 2, 2, 176, 181, 3, 2, 2, 2,
	177, 175, 3, 2, 2, 2, 178, 180, 7, 25, 2, 2, 179, 178, 3, 2, 2, 2, 180,
	183, 3, 2, 2, 2, 181, 179, 3, 2, 2, 2, 181, 182, 3, 2, 2, 2, 182, 23, 3,
	2, 2, 2, 183, 181, 3, 2, 2, 2, 184, 188, 7, 8, 2, 2, 185, 187, 7, 25, 2,
	2, 186, 185, 3, 2, 2, 2, 187, 190, 3, 2, 2, 2, 188, 186, 3, 2, 2, 2, 188,
	189, 3, 2, 2, 2, 189, 191, 3, 2, 2, 2, 190, 188, 3, 2, 2, 2, 191, 195,
	5, 4, 3, 2, 192, 194, 7, 25, 2, 2, 193, 192, 3, 2, 2, 2, 194, 197, 3, 2,
	2, 2, 195, 193, 3, 2, 2, 2, 195, 196, 3, 2, 2, 2, 196, 198, 3, 2, 2, 2,
	197, 195, 3, 2, 2, 2, 198, 199, 7, 9, 2, 2, 199, 25, 3, 2, 2, 2, 200, 204,
	9, 3, 2, 2, 201, 203, 9, 4, 2, 2, 202, 201, 3, 2, 2, 2, 203, 206, 3, 2,
	2, 2, 204, 202, 3, 2, 2, 2, 204, 205, 3, 2, 2, 2, 205, 27, 3, 2, 2, 2,
	206, 204, 3, 2, 2, 2, 207, 211, 5, 26, 14, 2, 208, 211, 7, 24, 2, 2, 209,
	211, 5, 36, 19, 2, 210, 207, 3, 2, 2, 2, 210, 208, 3, 2, 2, 2, 210, 209,
	3, 2, 2, 2, 211, 29, 3, 2, 2, 2, 212, 215, 5, 34, 18, 2, 213, 215, 5, 32,
	17, 2, 214, 212, 3, 2, 2, 2, 214, 213, 3, 2, 2, 2, 215, 31, 3, 2, 2, 2,
	216, 218, 7, 22, 2, 2, 217, 216, 3, 2, 2, 2, 217, 218, 3, 2, 2, 2, 218,
	220, 3, 2, 2, 2, 219, 221, 7, 26, 2, 2, 220, 219, 3, 2, 2, 2, 221, 222,
	3, 2, 2, 2, 222, 220, 3, 2, 2, 2, 222, 223, 3, 2, 2, 2, 223, 229, 3, 2,
	2, 2, 224, 226, 7, 22, 2, 2, 225, 224, 3, 2, 2, 2, 225, 226, 3, 2, 2, 2,
	226, 227, 3, 2, 2, 2, 227, 229, 7, 27, 2, 2, 228, 217, 3, 2, 2, 2, 228,
	225, 3, 2, 2, 2, 229, 33, 3, 2, 2, 2, 230, 232, 7, 22, 2, 2, 231, 230,
	3, 2, 2, 2, 231, 232, 3, 2, 2, 2, 232, 251, 3, 2, 2, 2, 233, 235, 7, 26,
	2, 2, 234, 233, 3, 2, 2, 2, 235, 236, 3, 2, 2, 2, 236, 234, 3, 2, 2, 2,
	236, 237, 3, 2, 2, 2, 237, 238, 3, 2, 2, 2, 238, 242, 7, 3, 2, 2, 239,
	241, 7, 26, 2, 2, 240, 239, 3, 2, 2, 2, 241, 244, 3, 2, 2, 2, 242, 240,
	3, 2, 2, 2, 242, 243, 3, 2, 2, 2, 243, 252, 3, 2, 2, 2, 244, 242, 3, 2,
	2, 2, 245, 247, 7, 3, 2, 2, 246, 248, 7, 26, 2, 2, 247, 246, 3, 2, 2, 2,
	248, 249, 3, 2, 2, 2, 249, 247, 3, 2, 2, 2, 249, 250, 3, 2, 2, 2, 250,
	252, 3, 2, 2, 2, 251, 234, 3, 2, 2, 2, 251, 245, 3, 2, 2, 2, 252, 254,
	3, 2, 2, 2, 253, 255, 7, 28, 2, 2, 254, 253, 3, 2, 2, 2, 254, 255, 3, 2,
	2, 2, 255, 35, 3, 2, 2, 2, 256, 257, 9, 5, 2, 2, 257, 37, 3, 2, 2, 2, 258,
	266, 7, 22, 2, 2, 259, 261, 7, 7, 2, 2, 260, 262, 7, 25, 2, 2, 261, 260,
	3, 2, 2, 2, 262, 263, 3, 2, 2, 2, 263, 261, 3, 2, 2, 2, 263, 264, 3, 2,
	2, 2, 264, 266, 3, 2, 2, 2, 265, 258, 3, 2, 2, 2, 265, 259, 3, 2, 2, 2,
	266, 39, 3, 2, 2, 2, 267, 269, 7, 25, 2, 2, 268, 267, 3, 2, 2, 2, 269,
	270, 3, 2, 2, 2, 270, 268, 3, 2, 2, 2, 270, 271, 3, 2, 2, 2, 271, 272,
	3, 2, 2, 2, 272, 274, 7, 6, 2, 2, 273, 275, 7, 25, 2, 2, 274, 273, 3, 2,
	2, 2, 275, 276, 3, 2, 2, 2, 276, 274, 3, 2, 2, 2, 276, 277, 3, 2, 2, 2,
	277, 41, 3, 2, 2, 2, 278, 280, 7, 25, 2, 2, 279, 278, 3, 2, 2, 2, 280,
	281, 3, 2, 2, 2, 281, 279, 3, 2, 2, 2, 281, 282, 3, 2, 2, 2, 282, 283,
	3, 2, 2, 2, 283, 285, 7, 5, 2, 2, 284, 286, 7, 25, 2, 2, 285, 284, 3, 2,
	2, 2, 286, 287, 3, 2, 2, 2, 287, 285, 3, 2, 2, 2, 287, 288, 3, 2, 2, 2,
	288, 43, 3, 2, 2, 2, 289, 291, 7, 25, 2, 2, 290, 289, 3, 2, 2, 2, 291,
	294, 3, 2, 2, 2, 292, 290, 3, 2, 2, 2, 292, 293, 3, 2, 2, 2, 293, 295,
	3, 2, 2, 2, 294, 292, 3, 2, 2, 2, 295, 299, 7, 14, 2, 2, 296, 298, 7, 25,
	2, 2, 297, 296, 3, 2, 2, 2, 298, 301, 3, 2, 2, 2, 299, 297, 3, 2, 2, 2,
	299, 300, 3, 2, 2, 2, 300, 45, 3, 2, 2, 2, 301, 299, 3, 2, 2, 2, 48, 47,
	52, 63, 70, 75, 84, 88, 96, 103, 108, 112, 124, 127, 134, 141, 146, 148,
	155, 158, 161, 166, 175, 181, 188, 195, 204, 210, 214, 217, 222, 225, 228,
	231, 236, 242, 249, 251, 254, 263, 265, 270, 276, 281, 287, 292, 299,
}
var deserializer = antlr.NewATNDeserializer(nil)
var deserializedATN = deserializer.DeserializeFromUInt16(parserATN)

var literalNames = []string{
	"", "'.'", "':'", "'OR'", "'AND'", "'NOT'", "'('", "')'", "'['", "']'",
	"'{'", "'}'", "','", "'<'", "'<='", "'>'", "'>='", "'!='", "'='", "'!'",
	"'-'", "'+'", "", "", "", "", "", "", "'\\'",
}
var symbolicNames = []string{
	"", "DOT", "HAS", "OR", "AND", "NOT", "LPAREN", "RPAREN", "LBRACE", "RBRACE",
	"LBRACKET", "RBRACKET", "COMMA", "LESS_THAN", "LESS_EQUALS", "GREATER_THAN",
	"GREATER_EQUALS", "NOT_EQUALS", "EQUALS", "EXCLAIM", "MINUS", "PLUS", "STRING",
	"WS", "DIGIT", "HEX_DIGIT", "EXPONENT", "TEXT", "BACKSLASH",
}

var ruleNames = []string{
	"filter", "expression", "sequence", "factor", "term", "restriction", "comparable",
	"comparator", "value", "primary", "argList", "composite", "text", "field",
	"number", "intVal", "floatVal", "keyword", "notOp", "andOp", "orOp", "sep",
}
var decisionToDFA = make([]*antlr.DFA, len(deserializedATN.DecisionToState))

func init() {
	for index, ds := range deserializedATN.DecisionToState {
		decisionToDFA[index] = antlr.NewDFA(ds, index)
	}
}

type FilterExpression struct {
	*antlr.BaseParser
}

func NewFilterExpression(input antlr.TokenStream) *FilterExpression {
	this := new(FilterExpression)

	this.BaseParser = antlr.NewBaseParser(input)

	this.Interpreter = antlr.NewParserATNSimulator(this, deserializedATN, decisionToDFA, antlr.NewPredictionContextCache())
	this.RuleNames = ruleNames
	this.LiteralNames = literalNames
	this.SymbolicNames = symbolicNames
	this.GrammarFileName = "FilterExpression.g4"

	return this
}

// FilterExpression tokens.
const (
	FilterExpressionEOF            = antlr.TokenEOF
	FilterExpressionDOT            = 1
	FilterExpressionHAS            = 2
	FilterExpressionOR             = 3
	FilterExpressionAND            = 4
	FilterExpressionNOT            = 5
	FilterExpressionLPAREN         = 6
	FilterExpressionRPAREN         = 7
	FilterExpressionLBRACE         = 8
	FilterExpressionRBRACE         = 9
	FilterExpressionLBRACKET       = 10
	FilterExpressionRBRACKET       = 11
	FilterExpressionCOMMA          = 12
	FilterExpressionLESS_THAN      = 13
	FilterExpressionLESS_EQUALS    = 14
	FilterExpressionGREATER_THAN   = 15
	FilterExpressionGREATER_EQUALS = 16
	FilterExpressionNOT_EQUALS     = 17
	FilterExpressionEQUALS         = 18
	FilterExpressionEXCLAIM        = 19
	FilterExpressionMINUS          = 20
	FilterExpressionPLUS           = 21
	FilterExpressionSTRING         = 22
	FilterExpressionWS             = 23
	FilterExpressionDIGIT          = 24
	FilterExpressionHEX_DIGIT      = 25
	FilterExpressionEXPONENT       = 26
	FilterExpressionTEXT           = 27
	FilterExpressionBACKSLASH      = 28
)

// FilterExpression rules.
const (
	FilterExpressionRULE_filter      = 0
	FilterExpressionRULE_expression  = 1
	FilterExpressionRULE_sequence    = 2
	FilterExpressionRULE_factor      = 3
	FilterExpressionRULE_term        = 4
	FilterExpressionRULE_restriction = 5
	FilterExpressionRULE_comparable  = 6
	FilterExpressionRULE_comparator  = 7
	FilterExpressionRULE_value       = 8
	FilterExpressionRULE_primary     = 9
	FilterExpressionRULE_argList     = 10
	FilterExpressionRULE_composite   = 11
	FilterExpressionRULE_text        = 12
	FilterExpressionRULE_field       = 13
	FilterExpressionRULE_number      = 14
	FilterExpressionRULE_intVal      = 15
	FilterExpressionRULE_floatVal    = 16
	FilterExpressionRULE_keyword     = 17
	FilterExpressionRULE_notOp       = 18
	FilterExpressionRULE_andOp       = 19
	FilterExpressionRULE_orOp        = 20
	FilterExpressionRULE_sep         = 21
)

// IFilterContext is an interface to support dynamic dispatch.
type IFilterContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsFilterContext differentiates from other interfaces.
	IsFilterContext()
}

type FilterContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyFilterContext() *FilterContext {
	var p = new(FilterContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = FilterExpressionRULE_filter
	return p
}

func (*FilterContext) IsFilterContext() {}

func NewFilterContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *FilterContext {
	var p = new(FilterContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = FilterExpressionRULE_filter

	return p
}

func (s *FilterContext) GetParser() antlr.Parser { return s.parser }

func (s *FilterContext) EOF() antlr.TerminalNode {
	return s.GetToken(FilterExpressionEOF, 0)
}

func (s *FilterContext) Expression() IExpressionContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IExpressionContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(IExpressionContext)
}

func (s *FilterContext) AllWS() []antlr.TerminalNode {
	return s.GetTokens(FilterExpressionWS)
}

func (s *FilterContext) WS(i int) antlr.TerminalNode {
	return s.GetToken(FilterExpressionWS, i)
}

func (s *FilterContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *FilterContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *FilterContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case FilterExpressionVisitor:
		return t.VisitFilter(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *FilterExpression) Filter() (localctx IFilterContext) {
	localctx = NewFilterContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 0, FilterExpressionRULE_filter)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	p.SetState(45)
	p.GetErrorHandler().Sync(p)
	_la = p.GetTokenStream().LA(1)

	if ((_la)&-(0x1f+1)) == 0 && ((1<<uint(_la))&((1<<FilterExpressionDOT)|(1<<FilterExpressionNOT)|(1<<FilterExpressionLPAREN)|(1<<FilterExpressionEXCLAIM)|(1<<FilterExpressionMINUS)|(1<<FilterExpressionSTRING)|(1<<FilterExpressionDIGIT)|(1<<FilterExpressionHEX_DIGIT)|(1<<FilterExpressionTEXT))) != 0 {
		{
			p.SetState(44)
			p.Expression()
		}

	}
	p.SetState(50)
	p.GetErrorHandler().Sync(p)
	_la = p.GetTokenStream().LA(1)

	for _la == FilterExpressionWS {
		{
			p.SetState(47)
			p.Match(FilterExpressionWS)
		}

		p.SetState(52)
		p.GetErrorHandler().Sync(p)
		_la = p.GetTokenStream().LA(1)
	}
	{
		p.SetState(53)
		p.Match(FilterExpressionEOF)
	}

	return localctx
}

// IExpressionContext is an interface to support dynamic dispatch.
type IExpressionContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// GetExpr returns the expr rule contexts.
	GetExpr() ISequenceContext

	// Get_andOp returns the _andOp rule contexts.
	Get_andOp() IAndOpContext

	// Get_sequence returns the _sequence rule contexts.
	Get_sequence() ISequenceContext

	// SetExpr sets the expr rule contexts.
	SetExpr(ISequenceContext)

	// Set_andOp sets the _andOp rule contexts.
	Set_andOp(IAndOpContext)

	// Set_sequence sets the _sequence rule contexts.
	Set_sequence(ISequenceContext)

	// GetOp returns the op rule context list.
	GetOp() []IAndOpContext

	// GetRest returns the rest rule context list.
	GetRest() []ISequenceContext

	// SetOp sets the op rule context list.
	SetOp([]IAndOpContext)

	// SetRest sets the rest rule context list.
	SetRest([]ISequenceContext)

	// IsExpressionContext differentiates from other interfaces.
	IsExpressionContext()
}

type ExpressionContext struct {
	*antlr.BaseParserRuleContext
	parser    antlr.Parser
	expr      ISequenceContext
	_andOp    IAndOpContext
	op        []IAndOpContext
	_sequence ISequenceContext
	rest      []ISequenceContext
}

func NewEmptyExpressionContext() *ExpressionContext {
	var p = new(ExpressionContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = FilterExpressionRULE_expression
	return p
}

func (*ExpressionContext) IsExpressionContext() {}

func NewExpressionContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *ExpressionContext {
	var p = new(ExpressionContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = FilterExpressionRULE_expression

	return p
}

func (s *ExpressionContext) GetParser() antlr.Parser { return s.parser }

func (s *ExpressionContext) GetExpr() ISequenceContext { return s.expr }

func (s *ExpressionContext) Get_andOp() IAndOpContext { return s._andOp }

func (s *ExpressionContext) Get_sequence() ISequenceContext { return s._sequence }

func (s *ExpressionContext) SetExpr(v ISequenceContext) { s.expr = v }

func (s *ExpressionContext) Set_andOp(v IAndOpContext) { s._andOp = v }

func (s *ExpressionContext) Set_sequence(v ISequenceContext) { s._sequence = v }

func (s *ExpressionContext) GetOp() []IAndOpContext { return s.op }

func (s *ExpressionContext) GetRest() []ISequenceContext { return s.rest }

func (s *ExpressionContext) SetOp(v []IAndOpContext) { s.op = v }

func (s *ExpressionContext) SetRest(v []ISequenceContext) { s.rest = v }

func (s *ExpressionContext) AllSequence() []ISequenceContext {
	var ts = s.GetTypedRuleContexts(reflect.TypeOf((*ISequenceContext)(nil)).Elem())
	var tst = make([]ISequenceContext, len(ts))

	for i, t := range ts {
		if t != nil {
			tst[i] = t.(ISequenceContext)
		}
	}

	return tst
}

func (s *ExpressionContext) Sequence(i int) ISequenceContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*ISequenceContext)(nil)).Elem(), i)

	if t == nil {
		return nil
	}

	return t.(ISequenceContext)
}

func (s *ExpressionContext) AllAndOp() []IAndOpContext {
	var ts = s.GetTypedRuleContexts(reflect.TypeOf((*IAndOpContext)(nil)).Elem())
	var tst = make([]IAndOpContext, len(ts))

	for i, t := range ts {
		if t != nil {
			tst[i] = t.(IAndOpContext)
		}
	}

	return tst
}

func (s *ExpressionContext) AndOp(i int) IAndOpContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IAndOpContext)(nil)).Elem(), i)

	if t == nil {
		return nil
	}

	return t.(IAndOpContext)
}

func (s *ExpressionContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ExpressionContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *ExpressionContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case FilterExpressionVisitor:
		return t.VisitExpression(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *FilterExpression) Expression() (localctx IExpressionContext) {
	localctx = NewExpressionContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 2, FilterExpressionRULE_expression)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	var _alt int

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(55)

		var _x = p.Sequence()

		localctx.(*ExpressionContext).expr = _x
	}
	p.SetState(61)
	p.GetErrorHandler().Sync(p)
	_alt = p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 2, p.GetParserRuleContext())

	for _alt != 2 && _alt != antlr.ATNInvalidAltNumber {
		if _alt == 1 {
			{
				p.SetState(56)

				var _x = p.AndOp()

				localctx.(*ExpressionContext)._andOp = _x
			}
			localctx.(*ExpressionContext).op = append(localctx.(*ExpressionContext).op, localctx.(*ExpressionContext)._andOp)
			{
				p.SetState(57)

				var _x = p.Sequence()

				localctx.(*ExpressionContext)._sequence = _x
			}
			localctx.(*ExpressionContext).rest = append(localctx.(*ExpressionContext).rest, localctx.(*ExpressionContext)._sequence)

		}
		p.SetState(63)
		p.GetErrorHandler().Sync(p)
		_alt = p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 2, p.GetParserRuleContext())
	}

	return localctx
}

// ISequenceContext is an interface to support dynamic dispatch.
type ISequenceContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// GetExpr returns the expr rule contexts.
	GetExpr() IFactorContext

	// Get_factor returns the _factor rule contexts.
	Get_factor() IFactorContext

	// SetExpr sets the expr rule contexts.
	SetExpr(IFactorContext)

	// Set_factor sets the _factor rule contexts.
	Set_factor(IFactorContext)

	// GetRest returns the rest rule context list.
	GetRest() []IFactorContext

	// SetRest sets the rest rule context list.
	SetRest([]IFactorContext)

	// IsSequenceContext differentiates from other interfaces.
	IsSequenceContext()
}

type SequenceContext struct {
	*antlr.BaseParserRuleContext
	parser  antlr.Parser
	expr    IFactorContext
	_factor IFactorContext
	rest    []IFactorContext
}

func NewEmptySequenceContext() *SequenceContext {
	var p = new(SequenceContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = FilterExpressionRULE_sequence
	return p
}

func (*SequenceContext) IsSequenceContext() {}

func NewSequenceContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *SequenceContext {
	var p = new(SequenceContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = FilterExpressionRULE_sequence

	return p
}

func (s *SequenceContext) GetParser() antlr.Parser { return s.parser }

func (s *SequenceContext) GetExpr() IFactorContext { return s.expr }

func (s *SequenceContext) Get_factor() IFactorContext { return s._factor }

func (s *SequenceContext) SetExpr(v IFactorContext) { s.expr = v }

func (s *SequenceContext) Set_factor(v IFactorContext) { s._factor = v }

func (s *SequenceContext) GetRest() []IFactorContext { return s.rest }

func (s *SequenceContext) SetRest(v []IFactorContext) { s.rest = v }

func (s *SequenceContext) AllFactor() []IFactorContext {
	var ts = s.GetTypedRuleContexts(reflect.TypeOf((*IFactorContext)(nil)).Elem())
	var tst = make([]IFactorContext, len(ts))

	for i, t := range ts {
		if t != nil {
			tst[i] = t.(IFactorContext)
		}
	}

	return tst
}

func (s *SequenceContext) Factor(i int) IFactorContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IFactorContext)(nil)).Elem(), i)

	if t == nil {
		return nil
	}

	return t.(IFactorContext)
}

func (s *SequenceContext) AllWS() []antlr.TerminalNode {
	return s.GetTokens(FilterExpressionWS)
}

func (s *SequenceContext) WS(i int) antlr.TerminalNode {
	return s.GetToken(FilterExpressionWS, i)
}

func (s *SequenceContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *SequenceContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *SequenceContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case FilterExpressionVisitor:
		return t.VisitSequence(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *FilterExpression) Sequence() (localctx ISequenceContext) {
	localctx = NewSequenceContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 4, FilterExpressionRULE_sequence)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	var _alt int

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(64)

		var _x = p.Factor()

		localctx.(*SequenceContext).expr = _x
	}
	p.SetState(73)
	p.GetErrorHandler().Sync(p)
	_alt = p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 4, p.GetParserRuleContext())

	for _alt != 2 && _alt != antlr.ATNInvalidAltNumber {
		if _alt == 1 {
			p.SetState(66)
			p.GetErrorHandler().Sync(p)
			_la = p.GetTokenStream().LA(1)

			for ok := true; ok; ok = _la == FilterExpressionWS {
				{
					p.SetState(65)
					p.Match(FilterExpressionWS)
				}

				p.SetState(68)
				p.GetErrorHandler().Sync(p)
				_la = p.GetTokenStream().LA(1)
			}
			{
				p.SetState(70)

				var _x = p.Factor()

				localctx.(*SequenceContext)._factor = _x
			}
			localctx.(*SequenceContext).rest = append(localctx.(*SequenceContext).rest, localctx.(*SequenceContext)._factor)

		}
		p.SetState(75)
		p.GetErrorHandler().Sync(p)
		_alt = p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 4, p.GetParserRuleContext())
	}

	return localctx
}

// IFactorContext is an interface to support dynamic dispatch.
type IFactorContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// GetExpr returns the expr rule contexts.
	GetExpr() ITermContext

	// Get_orOp returns the _orOp rule contexts.
	Get_orOp() IOrOpContext

	// Get_term returns the _term rule contexts.
	Get_term() ITermContext

	// SetExpr sets the expr rule contexts.
	SetExpr(ITermContext)

	// Set_orOp sets the _orOp rule contexts.
	Set_orOp(IOrOpContext)

	// Set_term sets the _term rule contexts.
	Set_term(ITermContext)

	// GetOp returns the op rule context list.
	GetOp() []IOrOpContext

	// GetRest returns the rest rule context list.
	GetRest() []ITermContext

	// SetOp sets the op rule context list.
	SetOp([]IOrOpContext)

	// SetRest sets the rest rule context list.
	SetRest([]ITermContext)

	// IsFactorContext differentiates from other interfaces.
	IsFactorContext()
}

type FactorContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
	expr   ITermContext
	_orOp  IOrOpContext
	op     []IOrOpContext
	_term  ITermContext
	rest   []ITermContext
}

func NewEmptyFactorContext() *FactorContext {
	var p = new(FactorContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = FilterExpressionRULE_factor
	return p
}

func (*FactorContext) IsFactorContext() {}

func NewFactorContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *FactorContext {
	var p = new(FactorContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = FilterExpressionRULE_factor

	return p
}

func (s *FactorContext) GetParser() antlr.Parser { return s.parser }

func (s *FactorContext) GetExpr() ITermContext { return s.expr }

func (s *FactorContext) Get_orOp() IOrOpContext { return s._orOp }

func (s *FactorContext) Get_term() ITermContext { return s._term }

func (s *FactorContext) SetExpr(v ITermContext) { s.expr = v }

func (s *FactorContext) Set_orOp(v IOrOpContext) { s._orOp = v }

func (s *FactorContext) Set_term(v ITermContext) { s._term = v }

func (s *FactorContext) GetOp() []IOrOpContext { return s.op }

func (s *FactorContext) GetRest() []ITermContext { return s.rest }

func (s *FactorContext) SetOp(v []IOrOpContext) { s.op = v }

func (s *FactorContext) SetRest(v []ITermContext) { s.rest = v }

func (s *FactorContext) AllTerm() []ITermContext {
	var ts = s.GetTypedRuleContexts(reflect.TypeOf((*ITermContext)(nil)).Elem())
	var tst = make([]ITermContext, len(ts))

	for i, t := range ts {
		if t != nil {
			tst[i] = t.(ITermContext)
		}
	}

	return tst
}

func (s *FactorContext) Term(i int) ITermContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*ITermContext)(nil)).Elem(), i)

	if t == nil {
		return nil
	}

	return t.(ITermContext)
}

func (s *FactorContext) AllOrOp() []IOrOpContext {
	var ts = s.GetTypedRuleContexts(reflect.TypeOf((*IOrOpContext)(nil)).Elem())
	var tst = make([]IOrOpContext, len(ts))

	for i, t := range ts {
		if t != nil {
			tst[i] = t.(IOrOpContext)
		}
	}

	return tst
}

func (s *FactorContext) OrOp(i int) IOrOpContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IOrOpContext)(nil)).Elem(), i)

	if t == nil {
		return nil
	}

	return t.(IOrOpContext)
}

func (s *FactorContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *FactorContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *FactorContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case FilterExpressionVisitor:
		return t.VisitFactor(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *FilterExpression) Factor() (localctx IFactorContext) {
	localctx = NewFactorContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 6, FilterExpressionRULE_factor)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	var _alt int

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(76)

		var _x = p.Term()

		localctx.(*FactorContext).expr = _x
	}
	p.SetState(82)
	p.GetErrorHandler().Sync(p)
	_alt = p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 5, p.GetParserRuleContext())

	for _alt != 2 && _alt != antlr.ATNInvalidAltNumber {
		if _alt == 1 {
			{
				p.SetState(77)

				var _x = p.OrOp()

				localctx.(*FactorContext)._orOp = _x
			}
			localctx.(*FactorContext).op = append(localctx.(*FactorContext).op, localctx.(*FactorContext)._orOp)
			{
				p.SetState(78)

				var _x = p.Term()

				localctx.(*FactorContext)._term = _x
			}
			localctx.(*FactorContext).rest = append(localctx.(*FactorContext).rest, localctx.(*FactorContext)._term)

		}
		p.SetState(84)
		p.GetErrorHandler().Sync(p)
		_alt = p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 5, p.GetParserRuleContext())
	}

	return localctx
}

// ITermContext is an interface to support dynamic dispatch.
type ITermContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// GetOp returns the op rule contexts.
	GetOp() INotOpContext

	// GetExpr returns the expr rule contexts.
	GetExpr() IRestrictionContext

	// SetOp sets the op rule contexts.
	SetOp(INotOpContext)

	// SetExpr sets the expr rule contexts.
	SetExpr(IRestrictionContext)

	// IsTermContext differentiates from other interfaces.
	IsTermContext()
}

type TermContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
	op     INotOpContext
	expr   IRestrictionContext
}

func NewEmptyTermContext() *TermContext {
	var p = new(TermContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = FilterExpressionRULE_term
	return p
}

func (*TermContext) IsTermContext() {}

func NewTermContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *TermContext {
	var p = new(TermContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = FilterExpressionRULE_term

	return p
}

func (s *TermContext) GetParser() antlr.Parser { return s.parser }

func (s *TermContext) GetOp() INotOpContext { return s.op }

func (s *TermContext) GetExpr() IRestrictionContext { return s.expr }

func (s *TermContext) SetOp(v INotOpContext) { s.op = v }

func (s *TermContext) SetExpr(v IRestrictionContext) { s.expr = v }

func (s *TermContext) Restriction() IRestrictionContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IRestrictionContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(IRestrictionContext)
}

func (s *TermContext) NotOp() INotOpContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*INotOpContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(INotOpContext)
}

func (s *TermContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *TermContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *TermContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case FilterExpressionVisitor:
		return t.VisitTerm(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *FilterExpression) Term() (localctx ITermContext) {
	localctx = NewTermContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 8, FilterExpressionRULE_term)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	p.SetState(86)
	p.GetErrorHandler().Sync(p)

	if p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 6, p.GetParserRuleContext()) == 1 {
		{
			p.SetState(85)

			var _x = p.NotOp()

			localctx.(*TermContext).op = _x
		}

	}
	{
		p.SetState(88)

		var _x = p.Restriction()

		localctx.(*TermContext).expr = _x
	}

	return localctx
}

// IRestrictionContext is an interface to support dynamic dispatch.
type IRestrictionContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// GetExpr returns the expr rule contexts.
	GetExpr() IComparableContext

	// GetOp returns the op rule contexts.
	GetOp() IComparatorContext

	// GetRest returns the rest rule contexts.
	GetRest() IComparableContext

	// SetExpr sets the expr rule contexts.
	SetExpr(IComparableContext)

	// SetOp sets the op rule contexts.
	SetOp(IComparatorContext)

	// SetRest sets the rest rule contexts.
	SetRest(IComparableContext)

	// IsRestrictionContext differentiates from other interfaces.
	IsRestrictionContext()
}

type RestrictionContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
	expr   IComparableContext
	op     IComparatorContext
	rest   IComparableContext
}

func NewEmptyRestrictionContext() *RestrictionContext {
	var p = new(RestrictionContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = FilterExpressionRULE_restriction
	return p
}

func (*RestrictionContext) IsRestrictionContext() {}

func NewRestrictionContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *RestrictionContext {
	var p = new(RestrictionContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = FilterExpressionRULE_restriction

	return p
}

func (s *RestrictionContext) GetParser() antlr.Parser { return s.parser }

func (s *RestrictionContext) GetExpr() IComparableContext { return s.expr }

func (s *RestrictionContext) GetOp() IComparatorContext { return s.op }

func (s *RestrictionContext) GetRest() IComparableContext { return s.rest }

func (s *RestrictionContext) SetExpr(v IComparableContext) { s.expr = v }

func (s *RestrictionContext) SetOp(v IComparatorContext) { s.op = v }

func (s *RestrictionContext) SetRest(v IComparableContext) { s.rest = v }

func (s *RestrictionContext) AllComparable() []IComparableContext {
	var ts = s.GetTypedRuleContexts(reflect.TypeOf((*IComparableContext)(nil)).Elem())
	var tst = make([]IComparableContext, len(ts))

	for i, t := range ts {
		if t != nil {
			tst[i] = t.(IComparableContext)
		}
	}

	return tst
}

func (s *RestrictionContext) Comparable(i int) IComparableContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IComparableContext)(nil)).Elem(), i)

	if t == nil {
		return nil
	}

	return t.(IComparableContext)
}

func (s *RestrictionContext) Comparator() IComparatorContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IComparatorContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(IComparatorContext)
}

func (s *RestrictionContext) AllWS() []antlr.TerminalNode {
	return s.GetTokens(FilterExpressionWS)
}

func (s *RestrictionContext) WS(i int) antlr.TerminalNode {
	return s.GetToken(FilterExpressionWS, i)
}

func (s *RestrictionContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *RestrictionContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *RestrictionContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case FilterExpressionVisitor:
		return t.VisitRestriction(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *FilterExpression) Restriction() (localctx IRestrictionContext) {
	localctx = NewRestrictionContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 10, FilterExpressionRULE_restriction)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(90)

		var _x = p.Comparable()

		localctx.(*RestrictionContext).expr = _x
	}
	p.SetState(106)
	p.GetErrorHandler().Sync(p)

	if p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 9, p.GetParserRuleContext()) == 1 {
		p.SetState(94)
		p.GetErrorHandler().Sync(p)
		_la = p.GetTokenStream().LA(1)

		for _la == FilterExpressionWS {
			{
				p.SetState(91)
				p.Match(FilterExpressionWS)
			}

			p.SetState(96)
			p.GetErrorHandler().Sync(p)
			_la = p.GetTokenStream().LA(1)
		}
		{
			p.SetState(97)

			var _x = p.Comparator()

			localctx.(*RestrictionContext).op = _x
		}
		p.SetState(101)
		p.GetErrorHandler().Sync(p)
		_la = p.GetTokenStream().LA(1)

		for _la == FilterExpressionWS {
			{
				p.SetState(98)
				p.Match(FilterExpressionWS)
			}

			p.SetState(103)
			p.GetErrorHandler().Sync(p)
			_la = p.GetTokenStream().LA(1)
		}
		{
			p.SetState(104)

			var _x = p.Comparable()

			localctx.(*RestrictionContext).rest = _x
		}

	}

	return localctx
}

// IComparableContext is an interface to support dynamic dispatch.
type IComparableContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsComparableContext differentiates from other interfaces.
	IsComparableContext()
}

type ComparableContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyComparableContext() *ComparableContext {
	var p = new(ComparableContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = FilterExpressionRULE_comparable
	return p
}

func (*ComparableContext) IsComparableContext() {}

func NewComparableContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *ComparableContext {
	var p = new(ComparableContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = FilterExpressionRULE_comparable

	return p
}

func (s *ComparableContext) GetParser() antlr.Parser { return s.parser }

func (s *ComparableContext) Number() INumberContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*INumberContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(INumberContext)
}

func (s *ComparableContext) Value() IValueContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IValueContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(IValueContext)
}

func (s *ComparableContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ComparableContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *ComparableContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case FilterExpressionVisitor:
		return t.VisitComparable(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *FilterExpression) Comparable() (localctx IComparableContext) {
	localctx = NewComparableContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 12, FilterExpressionRULE_comparable)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.SetState(110)
	p.GetErrorHandler().Sync(p)
	switch p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 10, p.GetParserRuleContext()) {
	case 1:
		p.EnterOuterAlt(localctx, 1)
		{
			p.SetState(108)
			p.Number()
		}

	case 2:
		p.EnterOuterAlt(localctx, 2)
		{
			p.SetState(109)
			p.value(0)
		}

	}

	return localctx
}

// IComparatorContext is an interface to support dynamic dispatch.
type IComparatorContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsComparatorContext differentiates from other interfaces.
	IsComparatorContext()
}

type ComparatorContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyComparatorContext() *ComparatorContext {
	var p = new(ComparatorContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = FilterExpressionRULE_comparator
	return p
}

func (*ComparatorContext) IsComparatorContext() {}

func NewComparatorContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *ComparatorContext {
	var p = new(ComparatorContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = FilterExpressionRULE_comparator

	return p
}

func (s *ComparatorContext) GetParser() antlr.Parser { return s.parser }

func (s *ComparatorContext) LESS_EQUALS() antlr.TerminalNode {
	return s.GetToken(FilterExpressionLESS_EQUALS, 0)
}

func (s *ComparatorContext) LESS_THAN() antlr.TerminalNode {
	return s.GetToken(FilterExpressionLESS_THAN, 0)
}

func (s *ComparatorContext) GREATER_EQUALS() antlr.TerminalNode {
	return s.GetToken(FilterExpressionGREATER_EQUALS, 0)
}

func (s *ComparatorContext) GREATER_THAN() antlr.TerminalNode {
	return s.GetToken(FilterExpressionGREATER_THAN, 0)
}

func (s *ComparatorContext) NOT_EQUALS() antlr.TerminalNode {
	return s.GetToken(FilterExpressionNOT_EQUALS, 0)
}

func (s *ComparatorContext) EQUALS() antlr.TerminalNode {
	return s.GetToken(FilterExpressionEQUALS, 0)
}

func (s *ComparatorContext) HAS() antlr.TerminalNode {
	return s.GetToken(FilterExpressionHAS, 0)
}

func (s *ComparatorContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ComparatorContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *ComparatorContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case FilterExpressionVisitor:
		return t.VisitComparator(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *FilterExpression) Comparator() (localctx IComparatorContext) {
	localctx = NewComparatorContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 14, FilterExpressionRULE_comparator)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(112)
		_la = p.GetTokenStream().LA(1)

		if !(((_la)&-(0x1f+1)) == 0 && ((1<<uint(_la))&((1<<FilterExpressionHAS)|(1<<FilterExpressionLESS_THAN)|(1<<FilterExpressionLESS_EQUALS)|(1<<FilterExpressionGREATER_THAN)|(1<<FilterExpressionGREATER_EQUALS)|(1<<FilterExpressionNOT_EQUALS)|(1<<FilterExpressionEQUALS))) != 0) {
			p.GetErrorHandler().RecoverInline(p)
		} else {
			p.GetErrorHandler().ReportMatch(p)
			p.Consume()
		}
	}

	return localctx
}

// IValueContext is an interface to support dynamic dispatch.
type IValueContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsValueContext differentiates from other interfaces.
	IsValueContext()
}

type ValueContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyValueContext() *ValueContext {
	var p = new(ValueContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = FilterExpressionRULE_value
	return p
}

func (*ValueContext) IsValueContext() {}

func NewValueContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *ValueContext {
	var p = new(ValueContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = FilterExpressionRULE_value

	return p
}

func (s *ValueContext) GetParser() antlr.Parser { return s.parser }

func (s *ValueContext) CopyFrom(ctx *ValueContext) {
	s.BaseParserRuleContext.CopyFrom(ctx.BaseParserRuleContext)
}

func (s *ValueContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ValueContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

type SelectOrCallContext struct {
	*ValueContext
	op   antlr.Token
	open antlr.Token
}

func NewSelectOrCallContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *SelectOrCallContext {
	var p = new(SelectOrCallContext)

	p.ValueContext = NewEmptyValueContext()
	p.parser = parser
	p.CopyFrom(ctx.(*ValueContext))

	return p
}

func (s *SelectOrCallContext) GetOp() antlr.Token { return s.op }

func (s *SelectOrCallContext) GetOpen() antlr.Token { return s.open }

func (s *SelectOrCallContext) SetOp(v antlr.Token) { s.op = v }

func (s *SelectOrCallContext) SetOpen(v antlr.Token) { s.open = v }

func (s *SelectOrCallContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *SelectOrCallContext) Value() IValueContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IValueContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(IValueContext)
}

func (s *SelectOrCallContext) Field() IFieldContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IFieldContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(IFieldContext)
}

func (s *SelectOrCallContext) DOT() antlr.TerminalNode {
	return s.GetToken(FilterExpressionDOT, 0)
}

func (s *SelectOrCallContext) RPAREN() antlr.TerminalNode {
	return s.GetToken(FilterExpressionRPAREN, 0)
}

func (s *SelectOrCallContext) LPAREN() antlr.TerminalNode {
	return s.GetToken(FilterExpressionLPAREN, 0)
}

func (s *SelectOrCallContext) ArgList() IArgListContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IArgListContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(IArgListContext)
}

func (s *SelectOrCallContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case FilterExpressionVisitor:
		return t.VisitSelectOrCall(s)

	default:
		return t.VisitChildren(s)
	}
}

type DynamicIndexContext struct {
	*ValueContext
	op    antlr.Token
	index IComparableContext
}

func NewDynamicIndexContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *DynamicIndexContext {
	var p = new(DynamicIndexContext)

	p.ValueContext = NewEmptyValueContext()
	p.parser = parser
	p.CopyFrom(ctx.(*ValueContext))

	return p
}

func (s *DynamicIndexContext) GetOp() antlr.Token { return s.op }

func (s *DynamicIndexContext) SetOp(v antlr.Token) { s.op = v }

func (s *DynamicIndexContext) GetIndex() IComparableContext { return s.index }

func (s *DynamicIndexContext) SetIndex(v IComparableContext) { s.index = v }

func (s *DynamicIndexContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *DynamicIndexContext) Value() IValueContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IValueContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(IValueContext)
}

func (s *DynamicIndexContext) RBRACE() antlr.TerminalNode {
	return s.GetToken(FilterExpressionRBRACE, 0)
}

func (s *DynamicIndexContext) LBRACE() antlr.TerminalNode {
	return s.GetToken(FilterExpressionLBRACE, 0)
}

func (s *DynamicIndexContext) Comparable() IComparableContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IComparableContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(IComparableContext)
}

func (s *DynamicIndexContext) AllWS() []antlr.TerminalNode {
	return s.GetTokens(FilterExpressionWS)
}

func (s *DynamicIndexContext) WS(i int) antlr.TerminalNode {
	return s.GetToken(FilterExpressionWS, i)
}

func (s *DynamicIndexContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case FilterExpressionVisitor:
		return t.VisitDynamicIndex(s)

	default:
		return t.VisitChildren(s)
	}
}

type PrimaryExprContext struct {
	*ValueContext
}

func NewPrimaryExprContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *PrimaryExprContext {
	var p = new(PrimaryExprContext)

	p.ValueContext = NewEmptyValueContext()
	p.parser = parser
	p.CopyFrom(ctx.(*ValueContext))

	return p
}

func (s *PrimaryExprContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *PrimaryExprContext) Primary() IPrimaryContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IPrimaryContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(IPrimaryContext)
}

func (s *PrimaryExprContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case FilterExpressionVisitor:
		return t.VisitPrimaryExpr(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *FilterExpression) Value() (localctx IValueContext) {
	return p.value(0)
}

func (p *FilterExpression) value(_p int) (localctx IValueContext) {
	var _parentctx antlr.ParserRuleContext = p.GetParserRuleContext()
	_parentState := p.GetState()
	localctx = NewValueContext(p, p.GetParserRuleContext(), _parentState)
	var _prevctx IValueContext = localctx
	var _ antlr.ParserRuleContext = _prevctx // TODO: To prevent unused variable warning.
	_startState := 16
	p.EnterRecursionRule(localctx, 16, FilterExpressionRULE_value, _p)
	var _la int

	defer func() {
		p.UnrollRecursionContexts(_parentctx)
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	var _alt int

	p.EnterOuterAlt(localctx, 1)
	localctx = NewPrimaryExprContext(p, localctx)
	p.SetParserRuleContext(localctx)
	_prevctx = localctx

	{
		p.SetState(115)
		p.Primary()
	}

	p.GetParserRuleContext().SetStop(p.GetTokenStream().LT(-1))
	p.SetState(146)
	p.GetErrorHandler().Sync(p)
	_alt = p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 16, p.GetParserRuleContext())

	for _alt != 2 && _alt != antlr.ATNInvalidAltNumber {
		if _alt == 1 {
			if p.GetParseListeners() != nil {
				p.TriggerExitRuleEvent()
			}
			_prevctx = localctx
			p.SetState(144)
			p.GetErrorHandler().Sync(p)
			switch p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 15, p.GetParserRuleContext()) {
			case 1:
				localctx = NewSelectOrCallContext(p, NewValueContext(p, _parentctx, _parentState))
				p.PushNewRecursionContext(localctx, _startState, FilterExpressionRULE_value)
				p.SetState(117)

				if !(p.Precpred(p.GetParserRuleContext(), 2)) {
					panic(antlr.NewFailedPredicateException(p, "p.Precpred(p.GetParserRuleContext(), 2)", ""))
				}
				{
					p.SetState(118)

					var _m = p.Match(FilterExpressionDOT)

					localctx.(*SelectOrCallContext).op = _m
				}
				{
					p.SetState(119)
					p.Field()
				}
				p.SetState(125)
				p.GetErrorHandler().Sync(p)

				if p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 12, p.GetParserRuleContext()) == 1 {
					{
						p.SetState(120)

						var _m = p.Match(FilterExpressionLPAREN)

						localctx.(*SelectOrCallContext).open = _m
					}
					p.SetState(122)
					p.GetErrorHandler().Sync(p)
					_la = p.GetTokenStream().LA(1)

					if ((_la)&-(0x1f+1)) == 0 && ((1<<uint(_la))&((1<<FilterExpressionDOT)|(1<<FilterExpressionLPAREN)|(1<<FilterExpressionEXCLAIM)|(1<<FilterExpressionMINUS)|(1<<FilterExpressionSTRING)|(1<<FilterExpressionWS)|(1<<FilterExpressionDIGIT)|(1<<FilterExpressionHEX_DIGIT)|(1<<FilterExpressionTEXT))) != 0 {
						{
							p.SetState(121)
							p.ArgList()
						}

					}
					{
						p.SetState(124)
						p.Match(FilterExpressionRPAREN)
					}

				}

			case 2:
				localctx = NewDynamicIndexContext(p, NewValueContext(p, _parentctx, _parentState))
				p.PushNewRecursionContext(localctx, _startState, FilterExpressionRULE_value)
				p.SetState(127)

				if !(p.Precpred(p.GetParserRuleContext(), 1)) {
					panic(antlr.NewFailedPredicateException(p, "p.Precpred(p.GetParserRuleContext(), 1)", ""))
				}
				{
					p.SetState(128)

					var _m = p.Match(FilterExpressionLBRACE)

					localctx.(*DynamicIndexContext).op = _m
				}
				p.SetState(132)
				p.GetErrorHandler().Sync(p)
				_la = p.GetTokenStream().LA(1)

				for _la == FilterExpressionWS {
					{
						p.SetState(129)
						p.Match(FilterExpressionWS)
					}

					p.SetState(134)
					p.GetErrorHandler().Sync(p)
					_la = p.GetTokenStream().LA(1)
				}
				{
					p.SetState(135)

					var _x = p.Comparable()

					localctx.(*DynamicIndexContext).index = _x
				}
				p.SetState(139)
				p.GetErrorHandler().Sync(p)
				_la = p.GetTokenStream().LA(1)

				for _la == FilterExpressionWS {
					{
						p.SetState(136)
						p.Match(FilterExpressionWS)
					}

					p.SetState(141)
					p.GetErrorHandler().Sync(p)
					_la = p.GetTokenStream().LA(1)
				}
				{
					p.SetState(142)
					p.Match(FilterExpressionRBRACE)
				}

			}

		}
		p.SetState(148)
		p.GetErrorHandler().Sync(p)
		_alt = p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 16, p.GetParserRuleContext())
	}

	return localctx
}

// IPrimaryContext is an interface to support dynamic dispatch.
type IPrimaryContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsPrimaryContext differentiates from other interfaces.
	IsPrimaryContext()
}

type PrimaryContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyPrimaryContext() *PrimaryContext {
	var p = new(PrimaryContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = FilterExpressionRULE_primary
	return p
}

func (*PrimaryContext) IsPrimaryContext() {}

func NewPrimaryContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *PrimaryContext {
	var p = new(PrimaryContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = FilterExpressionRULE_primary

	return p
}

func (s *PrimaryContext) GetParser() antlr.Parser { return s.parser }

func (s *PrimaryContext) CopyFrom(ctx *PrimaryContext) {
	s.BaseParserRuleContext.CopyFrom(ctx.BaseParserRuleContext)
}

func (s *PrimaryContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *PrimaryContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

type StringValContext struct {
	*PrimaryContext
	quotedText antlr.Token
}

func NewStringValContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *StringValContext {
	var p = new(StringValContext)

	p.PrimaryContext = NewEmptyPrimaryContext()
	p.parser = parser
	p.CopyFrom(ctx.(*PrimaryContext))

	return p
}

func (s *StringValContext) GetQuotedText() antlr.Token { return s.quotedText }

func (s *StringValContext) SetQuotedText(v antlr.Token) { s.quotedText = v }

func (s *StringValContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *StringValContext) STRING() antlr.TerminalNode {
	return s.GetToken(FilterExpressionSTRING, 0)
}

func (s *StringValContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case FilterExpressionVisitor:
		return t.VisitStringVal(s)

	default:
		return t.VisitChildren(s)
	}
}

type NestedExprContext struct {
	*PrimaryContext
}

func NewNestedExprContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *NestedExprContext {
	var p = new(NestedExprContext)

	p.PrimaryContext = NewEmptyPrimaryContext()
	p.parser = parser
	p.CopyFrom(ctx.(*PrimaryContext))

	return p
}

func (s *NestedExprContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *NestedExprContext) Composite() ICompositeContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*ICompositeContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(ICompositeContext)
}

func (s *NestedExprContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case FilterExpressionVisitor:
		return t.VisitNestedExpr(s)

	default:
		return t.VisitChildren(s)
	}
}

type IdentOrGlobalCallContext struct {
	*PrimaryContext
	id   ITextContext
	open antlr.Token
}

func NewIdentOrGlobalCallContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *IdentOrGlobalCallContext {
	var p = new(IdentOrGlobalCallContext)

	p.PrimaryContext = NewEmptyPrimaryContext()
	p.parser = parser
	p.CopyFrom(ctx.(*PrimaryContext))

	return p
}

func (s *IdentOrGlobalCallContext) GetOpen() antlr.Token { return s.open }

func (s *IdentOrGlobalCallContext) SetOpen(v antlr.Token) { s.open = v }

func (s *IdentOrGlobalCallContext) GetId() ITextContext { return s.id }

func (s *IdentOrGlobalCallContext) SetId(v ITextContext) { s.id = v }

func (s *IdentOrGlobalCallContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *IdentOrGlobalCallContext) Text() ITextContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*ITextContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(ITextContext)
}

func (s *IdentOrGlobalCallContext) RPAREN() antlr.TerminalNode {
	return s.GetToken(FilterExpressionRPAREN, 0)
}

func (s *IdentOrGlobalCallContext) LPAREN() antlr.TerminalNode {
	return s.GetToken(FilterExpressionLPAREN, 0)
}

func (s *IdentOrGlobalCallContext) ArgList() IArgListContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IArgListContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(IArgListContext)
}

func (s *IdentOrGlobalCallContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case FilterExpressionVisitor:
		return t.VisitIdentOrGlobalCall(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *FilterExpression) Primary() (localctx IPrimaryContext) {
	localctx = NewPrimaryContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 18, FilterExpressionRULE_primary)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.SetState(159)
	p.GetErrorHandler().Sync(p)

	switch p.GetTokenStream().LA(1) {
	case FilterExpressionLPAREN:
		localctx = NewNestedExprContext(p, localctx)
		p.EnterOuterAlt(localctx, 1)
		{
			p.SetState(149)
			p.Composite()
		}

	case FilterExpressionEXCLAIM, FilterExpressionDIGIT, FilterExpressionTEXT:
		localctx = NewIdentOrGlobalCallContext(p, localctx)
		p.EnterOuterAlt(localctx, 2)
		{
			p.SetState(150)

			var _x = p.Text()

			localctx.(*IdentOrGlobalCallContext).id = _x
		}
		p.SetState(156)
		p.GetErrorHandler().Sync(p)

		if p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 18, p.GetParserRuleContext()) == 1 {
			{
				p.SetState(151)

				var _m = p.Match(FilterExpressionLPAREN)

				localctx.(*IdentOrGlobalCallContext).open = _m
			}
			p.SetState(153)
			p.GetErrorHandler().Sync(p)
			_la = p.GetTokenStream().LA(1)

			if ((_la)&-(0x1f+1)) == 0 && ((1<<uint(_la))&((1<<FilterExpressionDOT)|(1<<FilterExpressionLPAREN)|(1<<FilterExpressionEXCLAIM)|(1<<FilterExpressionMINUS)|(1<<FilterExpressionSTRING)|(1<<FilterExpressionWS)|(1<<FilterExpressionDIGIT)|(1<<FilterExpressionHEX_DIGIT)|(1<<FilterExpressionTEXT))) != 0 {
				{
					p.SetState(152)
					p.ArgList()
				}

			}
			{
				p.SetState(155)
				p.Match(FilterExpressionRPAREN)
			}

		}

	case FilterExpressionSTRING:
		localctx = NewStringValContext(p, localctx)
		p.EnterOuterAlt(localctx, 3)
		{
			p.SetState(158)

			var _m = p.Match(FilterExpressionSTRING)

			localctx.(*StringValContext).quotedText = _m
		}

	default:
		panic(antlr.NewNoViableAltException(p, nil, nil, nil, nil, nil))
	}

	return localctx
}

// IArgListContext is an interface to support dynamic dispatch.
type IArgListContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// Get_comparable returns the _comparable rule contexts.
	Get_comparable() IComparableContext

	// Set_comparable sets the _comparable rule contexts.
	Set_comparable(IComparableContext)

	// GetArgs returns the args rule context list.
	GetArgs() []IComparableContext

	// SetArgs sets the args rule context list.
	SetArgs([]IComparableContext)

	// IsArgListContext differentiates from other interfaces.
	IsArgListContext()
}

type ArgListContext struct {
	*antlr.BaseParserRuleContext
	parser      antlr.Parser
	_comparable IComparableContext
	args        []IComparableContext
}

func NewEmptyArgListContext() *ArgListContext {
	var p = new(ArgListContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = FilterExpressionRULE_argList
	return p
}

func (*ArgListContext) IsArgListContext() {}

func NewArgListContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *ArgListContext {
	var p = new(ArgListContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = FilterExpressionRULE_argList

	return p
}

func (s *ArgListContext) GetParser() antlr.Parser { return s.parser }

func (s *ArgListContext) Get_comparable() IComparableContext { return s._comparable }

func (s *ArgListContext) Set_comparable(v IComparableContext) { s._comparable = v }

func (s *ArgListContext) GetArgs() []IComparableContext { return s.args }

func (s *ArgListContext) SetArgs(v []IComparableContext) { s.args = v }

func (s *ArgListContext) AllComparable() []IComparableContext {
	var ts = s.GetTypedRuleContexts(reflect.TypeOf((*IComparableContext)(nil)).Elem())
	var tst = make([]IComparableContext, len(ts))

	for i, t := range ts {
		if t != nil {
			tst[i] = t.(IComparableContext)
		}
	}

	return tst
}

func (s *ArgListContext) Comparable(i int) IComparableContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IComparableContext)(nil)).Elem(), i)

	if t == nil {
		return nil
	}

	return t.(IComparableContext)
}

func (s *ArgListContext) AllWS() []antlr.TerminalNode {
	return s.GetTokens(FilterExpressionWS)
}

func (s *ArgListContext) WS(i int) antlr.TerminalNode {
	return s.GetToken(FilterExpressionWS, i)
}

func (s *ArgListContext) AllSep() []ISepContext {
	var ts = s.GetTypedRuleContexts(reflect.TypeOf((*ISepContext)(nil)).Elem())
	var tst = make([]ISepContext, len(ts))

	for i, t := range ts {
		if t != nil {
			tst[i] = t.(ISepContext)
		}
	}

	return tst
}

func (s *ArgListContext) Sep(i int) ISepContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*ISepContext)(nil)).Elem(), i)

	if t == nil {
		return nil
	}

	return t.(ISepContext)
}

func (s *ArgListContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ArgListContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *ArgListContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case FilterExpressionVisitor:
		return t.VisitArgList(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *FilterExpression) ArgList() (localctx IArgListContext) {
	localctx = NewArgListContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 20, FilterExpressionRULE_argList)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	var _alt int

	p.EnterOuterAlt(localctx, 1)
	p.SetState(164)
	p.GetErrorHandler().Sync(p)
	_la = p.GetTokenStream().LA(1)

	for _la == FilterExpressionWS {
		{
			p.SetState(161)
			p.Match(FilterExpressionWS)
		}

		p.SetState(166)
		p.GetErrorHandler().Sync(p)
		_la = p.GetTokenStream().LA(1)
	}
	{
		p.SetState(167)

		var _x = p.Comparable()

		localctx.(*ArgListContext)._comparable = _x
	}
	localctx.(*ArgListContext).args = append(localctx.(*ArgListContext).args, localctx.(*ArgListContext)._comparable)
	p.SetState(173)
	p.GetErrorHandler().Sync(p)
	_alt = p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 21, p.GetParserRuleContext())

	for _alt != 2 && _alt != antlr.ATNInvalidAltNumber {
		if _alt == 1 {
			{
				p.SetState(168)
				p.Sep()
			}
			{
				p.SetState(169)

				var _x = p.Comparable()

				localctx.(*ArgListContext)._comparable = _x
			}
			localctx.(*ArgListContext).args = append(localctx.(*ArgListContext).args, localctx.(*ArgListContext)._comparable)

		}
		p.SetState(175)
		p.GetErrorHandler().Sync(p)
		_alt = p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 21, p.GetParserRuleContext())
	}
	p.SetState(179)
	p.GetErrorHandler().Sync(p)
	_la = p.GetTokenStream().LA(1)

	for _la == FilterExpressionWS {
		{
			p.SetState(176)
			p.Match(FilterExpressionWS)
		}

		p.SetState(181)
		p.GetErrorHandler().Sync(p)
		_la = p.GetTokenStream().LA(1)
	}

	return localctx
}

// ICompositeContext is an interface to support dynamic dispatch.
type ICompositeContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsCompositeContext differentiates from other interfaces.
	IsCompositeContext()
}

type CompositeContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyCompositeContext() *CompositeContext {
	var p = new(CompositeContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = FilterExpressionRULE_composite
	return p
}

func (*CompositeContext) IsCompositeContext() {}

func NewCompositeContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *CompositeContext {
	var p = new(CompositeContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = FilterExpressionRULE_composite

	return p
}

func (s *CompositeContext) GetParser() antlr.Parser { return s.parser }

func (s *CompositeContext) LPAREN() antlr.TerminalNode {
	return s.GetToken(FilterExpressionLPAREN, 0)
}

func (s *CompositeContext) Expression() IExpressionContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IExpressionContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(IExpressionContext)
}

func (s *CompositeContext) RPAREN() antlr.TerminalNode {
	return s.GetToken(FilterExpressionRPAREN, 0)
}

func (s *CompositeContext) AllWS() []antlr.TerminalNode {
	return s.GetTokens(FilterExpressionWS)
}

func (s *CompositeContext) WS(i int) antlr.TerminalNode {
	return s.GetToken(FilterExpressionWS, i)
}

func (s *CompositeContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *CompositeContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *CompositeContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case FilterExpressionVisitor:
		return t.VisitComposite(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *FilterExpression) Composite() (localctx ICompositeContext) {
	localctx = NewCompositeContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 22, FilterExpressionRULE_composite)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(182)
		p.Match(FilterExpressionLPAREN)
	}
	p.SetState(186)
	p.GetErrorHandler().Sync(p)
	_la = p.GetTokenStream().LA(1)

	for _la == FilterExpressionWS {
		{
			p.SetState(183)
			p.Match(FilterExpressionWS)
		}

		p.SetState(188)
		p.GetErrorHandler().Sync(p)
		_la = p.GetTokenStream().LA(1)
	}
	{
		p.SetState(189)
		p.Expression()
	}
	p.SetState(193)
	p.GetErrorHandler().Sync(p)
	_la = p.GetTokenStream().LA(1)

	for _la == FilterExpressionWS {
		{
			p.SetState(190)
			p.Match(FilterExpressionWS)
		}

		p.SetState(195)
		p.GetErrorHandler().Sync(p)
		_la = p.GetTokenStream().LA(1)
	}
	{
		p.SetState(196)
		p.Match(FilterExpressionRPAREN)
	}

	return localctx
}

// ITextContext is an interface to support dynamic dispatch.
type ITextContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsTextContext differentiates from other interfaces.
	IsTextContext()
}

type TextContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyTextContext() *TextContext {
	var p = new(TextContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = FilterExpressionRULE_text
	return p
}

func (*TextContext) IsTextContext() {}

func NewTextContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *TextContext {
	var p = new(TextContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = FilterExpressionRULE_text

	return p
}

func (s *TextContext) GetParser() antlr.Parser { return s.parser }

func (s *TextContext) AllTEXT() []antlr.TerminalNode {
	return s.GetTokens(FilterExpressionTEXT)
}

func (s *TextContext) TEXT(i int) antlr.TerminalNode {
	return s.GetToken(FilterExpressionTEXT, i)
}

func (s *TextContext) AllEXCLAIM() []antlr.TerminalNode {
	return s.GetTokens(FilterExpressionEXCLAIM)
}

func (s *TextContext) EXCLAIM(i int) antlr.TerminalNode {
	return s.GetToken(FilterExpressionEXCLAIM, i)
}

func (s *TextContext) AllDIGIT() []antlr.TerminalNode {
	return s.GetTokens(FilterExpressionDIGIT)
}

func (s *TextContext) DIGIT(i int) antlr.TerminalNode {
	return s.GetToken(FilterExpressionDIGIT, i)
}

func (s *TextContext) AllMINUS() []antlr.TerminalNode {
	return s.GetTokens(FilterExpressionMINUS)
}

func (s *TextContext) MINUS(i int) antlr.TerminalNode {
	return s.GetToken(FilterExpressionMINUS, i)
}

func (s *TextContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *TextContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *TextContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case FilterExpressionVisitor:
		return t.VisitText(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *FilterExpression) Text() (localctx ITextContext) {
	localctx = NewTextContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 24, FilterExpressionRULE_text)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	var _alt int

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(198)
		_la = p.GetTokenStream().LA(1)

		if !(((_la)&-(0x1f+1)) == 0 && ((1<<uint(_la))&((1<<FilterExpressionEXCLAIM)|(1<<FilterExpressionDIGIT)|(1<<FilterExpressionTEXT))) != 0) {
			p.GetErrorHandler().RecoverInline(p)
		} else {
			p.GetErrorHandler().ReportMatch(p)
			p.Consume()
		}
	}
	p.SetState(202)
	p.GetErrorHandler().Sync(p)
	_alt = p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 25, p.GetParserRuleContext())

	for _alt != 2 && _alt != antlr.ATNInvalidAltNumber {
		if _alt == 1 {
			{
				p.SetState(199)
				_la = p.GetTokenStream().LA(1)

				if !(((_la)&-(0x1f+1)) == 0 && ((1<<uint(_la))&((1<<FilterExpressionEXCLAIM)|(1<<FilterExpressionMINUS)|(1<<FilterExpressionDIGIT)|(1<<FilterExpressionTEXT))) != 0) {
					p.GetErrorHandler().RecoverInline(p)
				} else {
					p.GetErrorHandler().ReportMatch(p)
					p.Consume()
				}
			}

		}
		p.SetState(204)
		p.GetErrorHandler().Sync(p)
		_alt = p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 25, p.GetParserRuleContext())
	}

	return localctx
}

// IFieldContext is an interface to support dynamic dispatch.
type IFieldContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// GetQuotedText returns the quotedText token.
	GetQuotedText() antlr.Token

	// SetQuotedText sets the quotedText token.
	SetQuotedText(antlr.Token)

	// GetId returns the id rule contexts.
	GetId() ITextContext

	// SetId sets the id rule contexts.
	SetId(ITextContext)

	// IsFieldContext differentiates from other interfaces.
	IsFieldContext()
}

type FieldContext struct {
	*antlr.BaseParserRuleContext
	parser     antlr.Parser
	id         ITextContext
	quotedText antlr.Token
}

func NewEmptyFieldContext() *FieldContext {
	var p = new(FieldContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = FilterExpressionRULE_field
	return p
}

func (*FieldContext) IsFieldContext() {}

func NewFieldContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *FieldContext {
	var p = new(FieldContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = FilterExpressionRULE_field

	return p
}

func (s *FieldContext) GetParser() antlr.Parser { return s.parser }

func (s *FieldContext) GetQuotedText() antlr.Token { return s.quotedText }

func (s *FieldContext) SetQuotedText(v antlr.Token) { s.quotedText = v }

func (s *FieldContext) GetId() ITextContext { return s.id }

func (s *FieldContext) SetId(v ITextContext) { s.id = v }

func (s *FieldContext) Text() ITextContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*ITextContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(ITextContext)
}

func (s *FieldContext) STRING() antlr.TerminalNode {
	return s.GetToken(FilterExpressionSTRING, 0)
}

func (s *FieldContext) Keyword() IKeywordContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IKeywordContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(IKeywordContext)
}

func (s *FieldContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *FieldContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *FieldContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case FilterExpressionVisitor:
		return t.VisitField(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *FilterExpression) Field() (localctx IFieldContext) {
	localctx = NewFieldContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 26, FilterExpressionRULE_field)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.SetState(208)
	p.GetErrorHandler().Sync(p)

	switch p.GetTokenStream().LA(1) {
	case FilterExpressionEXCLAIM, FilterExpressionDIGIT, FilterExpressionTEXT:
		p.EnterOuterAlt(localctx, 1)
		{
			p.SetState(205)

			var _x = p.Text()

			localctx.(*FieldContext).id = _x
		}

	case FilterExpressionSTRING:
		p.EnterOuterAlt(localctx, 2)
		{
			p.SetState(206)

			var _m = p.Match(FilterExpressionSTRING)

			localctx.(*FieldContext).quotedText = _m
		}

	case FilterExpressionOR, FilterExpressionAND, FilterExpressionNOT:
		p.EnterOuterAlt(localctx, 3)
		{
			p.SetState(207)
			p.Keyword()
		}

	default:
		panic(antlr.NewNoViableAltException(p, nil, nil, nil, nil, nil))
	}

	return localctx
}

// INumberContext is an interface to support dynamic dispatch.
type INumberContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsNumberContext differentiates from other interfaces.
	IsNumberContext()
}

type NumberContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyNumberContext() *NumberContext {
	var p = new(NumberContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = FilterExpressionRULE_number
	return p
}

func (*NumberContext) IsNumberContext() {}

func NewNumberContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *NumberContext {
	var p = new(NumberContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = FilterExpressionRULE_number

	return p
}

func (s *NumberContext) GetParser() antlr.Parser { return s.parser }

func (s *NumberContext) FloatVal() IFloatValContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IFloatValContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(IFloatValContext)
}

func (s *NumberContext) IntVal() IIntValContext {
	var t = s.GetTypedRuleContext(reflect.TypeOf((*IIntValContext)(nil)).Elem(), 0)

	if t == nil {
		return nil
	}

	return t.(IIntValContext)
}

func (s *NumberContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *NumberContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *NumberContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case FilterExpressionVisitor:
		return t.VisitNumber(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *FilterExpression) Number() (localctx INumberContext) {
	localctx = NewNumberContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 28, FilterExpressionRULE_number)

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.SetState(212)
	p.GetErrorHandler().Sync(p)
	switch p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 27, p.GetParserRuleContext()) {
	case 1:
		p.EnterOuterAlt(localctx, 1)
		{
			p.SetState(210)
			p.FloatVal()
		}

	case 2:
		p.EnterOuterAlt(localctx, 2)
		{
			p.SetState(211)
			p.IntVal()
		}

	}

	return localctx
}

// IIntValContext is an interface to support dynamic dispatch.
type IIntValContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsIntValContext differentiates from other interfaces.
	IsIntValContext()
}

type IntValContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyIntValContext() *IntValContext {
	var p = new(IntValContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = FilterExpressionRULE_intVal
	return p
}

func (*IntValContext) IsIntValContext() {}

func NewIntValContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *IntValContext {
	var p = new(IntValContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = FilterExpressionRULE_intVal

	return p
}

func (s *IntValContext) GetParser() antlr.Parser { return s.parser }

func (s *IntValContext) MINUS() antlr.TerminalNode {
	return s.GetToken(FilterExpressionMINUS, 0)
}

func (s *IntValContext) AllDIGIT() []antlr.TerminalNode {
	return s.GetTokens(FilterExpressionDIGIT)
}

func (s *IntValContext) DIGIT(i int) antlr.TerminalNode {
	return s.GetToken(FilterExpressionDIGIT, i)
}

func (s *IntValContext) HEX_DIGIT() antlr.TerminalNode {
	return s.GetToken(FilterExpressionHEX_DIGIT, 0)
}

func (s *IntValContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *IntValContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *IntValContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case FilterExpressionVisitor:
		return t.VisitIntVal(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *FilterExpression) IntVal() (localctx IIntValContext) {
	localctx = NewIntValContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 30, FilterExpressionRULE_intVal)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.SetState(226)
	p.GetErrorHandler().Sync(p)
	switch p.GetInterpreter().AdaptivePredict(p.GetTokenStream(), 31, p.GetParserRuleContext()) {
	case 1:
		p.EnterOuterAlt(localctx, 1)
		p.SetState(215)
		p.GetErrorHandler().Sync(p)
		_la = p.GetTokenStream().LA(1)

		if _la == FilterExpressionMINUS {
			{
				p.SetState(214)
				p.Match(FilterExpressionMINUS)
			}

		}
		p.SetState(218)
		p.GetErrorHandler().Sync(p)
		_la = p.GetTokenStream().LA(1)

		for ok := true; ok; ok = _la == FilterExpressionDIGIT {
			{
				p.SetState(217)
				p.Match(FilterExpressionDIGIT)
			}

			p.SetState(220)
			p.GetErrorHandler().Sync(p)
			_la = p.GetTokenStream().LA(1)
		}

	case 2:
		p.EnterOuterAlt(localctx, 2)
		p.SetState(223)
		p.GetErrorHandler().Sync(p)
		_la = p.GetTokenStream().LA(1)

		if _la == FilterExpressionMINUS {
			{
				p.SetState(222)
				p.Match(FilterExpressionMINUS)
			}

		}
		{
			p.SetState(225)
			p.Match(FilterExpressionHEX_DIGIT)
		}

	}

	return localctx
}

// IFloatValContext is an interface to support dynamic dispatch.
type IFloatValContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsFloatValContext differentiates from other interfaces.
	IsFloatValContext()
}

type FloatValContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyFloatValContext() *FloatValContext {
	var p = new(FloatValContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = FilterExpressionRULE_floatVal
	return p
}

func (*FloatValContext) IsFloatValContext() {}

func NewFloatValContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *FloatValContext {
	var p = new(FloatValContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = FilterExpressionRULE_floatVal

	return p
}

func (s *FloatValContext) GetParser() antlr.Parser { return s.parser }

func (s *FloatValContext) DOT() antlr.TerminalNode {
	return s.GetToken(FilterExpressionDOT, 0)
}

func (s *FloatValContext) MINUS() antlr.TerminalNode {
	return s.GetToken(FilterExpressionMINUS, 0)
}

func (s *FloatValContext) EXPONENT() antlr.TerminalNode {
	return s.GetToken(FilterExpressionEXPONENT, 0)
}

func (s *FloatValContext) AllDIGIT() []antlr.TerminalNode {
	return s.GetTokens(FilterExpressionDIGIT)
}

func (s *FloatValContext) DIGIT(i int) antlr.TerminalNode {
	return s.GetToken(FilterExpressionDIGIT, i)
}

func (s *FloatValContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *FloatValContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *FloatValContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case FilterExpressionVisitor:
		return t.VisitFloatVal(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *FilterExpression) FloatVal() (localctx IFloatValContext) {
	localctx = NewFloatValContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 32, FilterExpressionRULE_floatVal)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	p.SetState(229)
	p.GetErrorHandler().Sync(p)
	_la = p.GetTokenStream().LA(1)

	if _la == FilterExpressionMINUS {
		{
			p.SetState(228)
			p.Match(FilterExpressionMINUS)
		}

	}
	p.SetState(249)
	p.GetErrorHandler().Sync(p)

	switch p.GetTokenStream().LA(1) {
	case FilterExpressionDIGIT:
		p.SetState(232)
		p.GetErrorHandler().Sync(p)
		_la = p.GetTokenStream().LA(1)

		for ok := true; ok; ok = _la == FilterExpressionDIGIT {
			{
				p.SetState(231)
				p.Match(FilterExpressionDIGIT)
			}

			p.SetState(234)
			p.GetErrorHandler().Sync(p)
			_la = p.GetTokenStream().LA(1)
		}
		{
			p.SetState(236)
			p.Match(FilterExpressionDOT)
		}
		p.SetState(240)
		p.GetErrorHandler().Sync(p)
		_la = p.GetTokenStream().LA(1)

		for _la == FilterExpressionDIGIT {
			{
				p.SetState(237)
				p.Match(FilterExpressionDIGIT)
			}

			p.SetState(242)
			p.GetErrorHandler().Sync(p)
			_la = p.GetTokenStream().LA(1)
		}

	case FilterExpressionDOT:
		{
			p.SetState(243)
			p.Match(FilterExpressionDOT)
		}
		p.SetState(245)
		p.GetErrorHandler().Sync(p)
		_la = p.GetTokenStream().LA(1)

		for ok := true; ok; ok = _la == FilterExpressionDIGIT {
			{
				p.SetState(244)
				p.Match(FilterExpressionDIGIT)
			}

			p.SetState(247)
			p.GetErrorHandler().Sync(p)
			_la = p.GetTokenStream().LA(1)
		}

	default:
		panic(antlr.NewNoViableAltException(p, nil, nil, nil, nil, nil))
	}
	p.SetState(252)
	p.GetErrorHandler().Sync(p)
	_la = p.GetTokenStream().LA(1)

	if _la == FilterExpressionEXPONENT {
		{
			p.SetState(251)
			p.Match(FilterExpressionEXPONENT)
		}

	}

	return localctx
}

// IKeywordContext is an interface to support dynamic dispatch.
type IKeywordContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsKeywordContext differentiates from other interfaces.
	IsKeywordContext()
}

type KeywordContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyKeywordContext() *KeywordContext {
	var p = new(KeywordContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = FilterExpressionRULE_keyword
	return p
}

func (*KeywordContext) IsKeywordContext() {}

func NewKeywordContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *KeywordContext {
	var p = new(KeywordContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = FilterExpressionRULE_keyword

	return p
}

func (s *KeywordContext) GetParser() antlr.Parser { return s.parser }

func (s *KeywordContext) OR() antlr.TerminalNode {
	return s.GetToken(FilterExpressionOR, 0)
}

func (s *KeywordContext) AND() antlr.TerminalNode {
	return s.GetToken(FilterExpressionAND, 0)
}

func (s *KeywordContext) NOT() antlr.TerminalNode {
	return s.GetToken(FilterExpressionNOT, 0)
}

func (s *KeywordContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *KeywordContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *KeywordContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case FilterExpressionVisitor:
		return t.VisitKeyword(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *FilterExpression) Keyword() (localctx IKeywordContext) {
	localctx = NewKeywordContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 34, FilterExpressionRULE_keyword)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(254)
		_la = p.GetTokenStream().LA(1)

		if !(((_la)&-(0x1f+1)) == 0 && ((1<<uint(_la))&((1<<FilterExpressionOR)|(1<<FilterExpressionAND)|(1<<FilterExpressionNOT))) != 0) {
			p.GetErrorHandler().RecoverInline(p)
		} else {
			p.GetErrorHandler().ReportMatch(p)
			p.Consume()
		}
	}

	return localctx
}

// INotOpContext is an interface to support dynamic dispatch.
type INotOpContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsNotOpContext differentiates from other interfaces.
	IsNotOpContext()
}

type NotOpContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyNotOpContext() *NotOpContext {
	var p = new(NotOpContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = FilterExpressionRULE_notOp
	return p
}

func (*NotOpContext) IsNotOpContext() {}

func NewNotOpContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *NotOpContext {
	var p = new(NotOpContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = FilterExpressionRULE_notOp

	return p
}

func (s *NotOpContext) GetParser() antlr.Parser { return s.parser }

func (s *NotOpContext) MINUS() antlr.TerminalNode {
	return s.GetToken(FilterExpressionMINUS, 0)
}

func (s *NotOpContext) NOT() antlr.TerminalNode {
	return s.GetToken(FilterExpressionNOT, 0)
}

func (s *NotOpContext) AllWS() []antlr.TerminalNode {
	return s.GetTokens(FilterExpressionWS)
}

func (s *NotOpContext) WS(i int) antlr.TerminalNode {
	return s.GetToken(FilterExpressionWS, i)
}

func (s *NotOpContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *NotOpContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *NotOpContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case FilterExpressionVisitor:
		return t.VisitNotOp(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *FilterExpression) NotOp() (localctx INotOpContext) {
	localctx = NewNotOpContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 36, FilterExpressionRULE_notOp)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.SetState(263)
	p.GetErrorHandler().Sync(p)

	switch p.GetTokenStream().LA(1) {
	case FilterExpressionMINUS:
		p.EnterOuterAlt(localctx, 1)
		{
			p.SetState(256)
			p.Match(FilterExpressionMINUS)
		}

	case FilterExpressionNOT:
		p.EnterOuterAlt(localctx, 2)
		{
			p.SetState(257)
			p.Match(FilterExpressionNOT)
		}
		p.SetState(259)
		p.GetErrorHandler().Sync(p)
		_la = p.GetTokenStream().LA(1)

		for ok := true; ok; ok = _la == FilterExpressionWS {
			{
				p.SetState(258)
				p.Match(FilterExpressionWS)
			}

			p.SetState(261)
			p.GetErrorHandler().Sync(p)
			_la = p.GetTokenStream().LA(1)
		}

	default:
		panic(antlr.NewNoViableAltException(p, nil, nil, nil, nil, nil))
	}

	return localctx
}

// IAndOpContext is an interface to support dynamic dispatch.
type IAndOpContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsAndOpContext differentiates from other interfaces.
	IsAndOpContext()
}

type AndOpContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyAndOpContext() *AndOpContext {
	var p = new(AndOpContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = FilterExpressionRULE_andOp
	return p
}

func (*AndOpContext) IsAndOpContext() {}

func NewAndOpContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *AndOpContext {
	var p = new(AndOpContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = FilterExpressionRULE_andOp

	return p
}

func (s *AndOpContext) GetParser() antlr.Parser { return s.parser }

func (s *AndOpContext) AND() antlr.TerminalNode {
	return s.GetToken(FilterExpressionAND, 0)
}

func (s *AndOpContext) AllWS() []antlr.TerminalNode {
	return s.GetTokens(FilterExpressionWS)
}

func (s *AndOpContext) WS(i int) antlr.TerminalNode {
	return s.GetToken(FilterExpressionWS, i)
}

func (s *AndOpContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *AndOpContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *AndOpContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case FilterExpressionVisitor:
		return t.VisitAndOp(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *FilterExpression) AndOp() (localctx IAndOpContext) {
	localctx = NewAndOpContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 38, FilterExpressionRULE_andOp)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	p.SetState(266)
	p.GetErrorHandler().Sync(p)
	_la = p.GetTokenStream().LA(1)

	for ok := true; ok; ok = _la == FilterExpressionWS {
		{
			p.SetState(265)
			p.Match(FilterExpressionWS)
		}

		p.SetState(268)
		p.GetErrorHandler().Sync(p)
		_la = p.GetTokenStream().LA(1)
	}
	{
		p.SetState(270)
		p.Match(FilterExpressionAND)
	}
	p.SetState(272)
	p.GetErrorHandler().Sync(p)
	_la = p.GetTokenStream().LA(1)

	for ok := true; ok; ok = _la == FilterExpressionWS {
		{
			p.SetState(271)
			p.Match(FilterExpressionWS)
		}

		p.SetState(274)
		p.GetErrorHandler().Sync(p)
		_la = p.GetTokenStream().LA(1)
	}

	return localctx
}

// IOrOpContext is an interface to support dynamic dispatch.
type IOrOpContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsOrOpContext differentiates from other interfaces.
	IsOrOpContext()
}

type OrOpContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyOrOpContext() *OrOpContext {
	var p = new(OrOpContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = FilterExpressionRULE_orOp
	return p
}

func (*OrOpContext) IsOrOpContext() {}

func NewOrOpContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *OrOpContext {
	var p = new(OrOpContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = FilterExpressionRULE_orOp

	return p
}

func (s *OrOpContext) GetParser() antlr.Parser { return s.parser }

func (s *OrOpContext) OR() antlr.TerminalNode {
	return s.GetToken(FilterExpressionOR, 0)
}

func (s *OrOpContext) AllWS() []antlr.TerminalNode {
	return s.GetTokens(FilterExpressionWS)
}

func (s *OrOpContext) WS(i int) antlr.TerminalNode {
	return s.GetToken(FilterExpressionWS, i)
}

func (s *OrOpContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *OrOpContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *OrOpContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case FilterExpressionVisitor:
		return t.VisitOrOp(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *FilterExpression) OrOp() (localctx IOrOpContext) {
	localctx = NewOrOpContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 40, FilterExpressionRULE_orOp)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	p.SetState(277)
	p.GetErrorHandler().Sync(p)
	_la = p.GetTokenStream().LA(1)

	for ok := true; ok; ok = _la == FilterExpressionWS {
		{
			p.SetState(276)
			p.Match(FilterExpressionWS)
		}

		p.SetState(279)
		p.GetErrorHandler().Sync(p)
		_la = p.GetTokenStream().LA(1)
	}
	{
		p.SetState(281)
		p.Match(FilterExpressionOR)
	}
	p.SetState(283)
	p.GetErrorHandler().Sync(p)
	_la = p.GetTokenStream().LA(1)

	for ok := true; ok; ok = _la == FilterExpressionWS {
		{
			p.SetState(282)
			p.Match(FilterExpressionWS)
		}

		p.SetState(285)
		p.GetErrorHandler().Sync(p)
		_la = p.GetTokenStream().LA(1)
	}

	return localctx
}

// ISepContext is an interface to support dynamic dispatch.
type ISepContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// IsSepContext differentiates from other interfaces.
	IsSepContext()
}

type SepContext struct {
	*antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptySepContext() *SepContext {
	var p = new(SepContext)
	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(nil, -1)
	p.RuleIndex = FilterExpressionRULE_sep
	return p
}

func (*SepContext) IsSepContext() {}

func NewSepContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *SepContext {
	var p = new(SepContext)

	p.BaseParserRuleContext = antlr.NewBaseParserRuleContext(parent, invokingState)

	p.parser = parser
	p.RuleIndex = FilterExpressionRULE_sep

	return p
}

func (s *SepContext) GetParser() antlr.Parser { return s.parser }

func (s *SepContext) COMMA() antlr.TerminalNode {
	return s.GetToken(FilterExpressionCOMMA, 0)
}

func (s *SepContext) AllWS() []antlr.TerminalNode {
	return s.GetTokens(FilterExpressionWS)
}

func (s *SepContext) WS(i int) antlr.TerminalNode {
	return s.GetToken(FilterExpressionWS, i)
}

func (s *SepContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *SepContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *SepContext) Accept(visitor antlr.ParseTreeVisitor) interface{} {
	switch t := visitor.(type) {
	case FilterExpressionVisitor:
		return t.VisitSep(s)

	default:
		return t.VisitChildren(s)
	}
}

func (p *FilterExpression) Sep() (localctx ISepContext) {
	localctx = NewSepContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 42, FilterExpressionRULE_sep)
	var _la int

	defer func() {
		p.ExitRule()
	}()

	defer func() {
		if err := recover(); err != nil {
			if v, ok := err.(antlr.RecognitionException); ok {
				localctx.SetException(v)
				p.GetErrorHandler().ReportError(p, v)
				p.GetErrorHandler().Recover(p, v)
			} else {
				panic(err)
			}
		}
	}()

	p.EnterOuterAlt(localctx, 1)
	p.SetState(290)
	p.GetErrorHandler().Sync(p)
	_la = p.GetTokenStream().LA(1)

	for _la == FilterExpressionWS {
		{
			p.SetState(287)
			p.Match(FilterExpressionWS)
		}

		p.SetState(292)
		p.GetErrorHandler().Sync(p)
		_la = p.GetTokenStream().LA(1)
	}
	{
		p.SetState(293)
		p.Match(FilterExpressionCOMMA)
	}
	p.SetState(297)
	p.GetErrorHandler().Sync(p)
	_la = p.GetTokenStream().LA(1)

	for _la == FilterExpressionWS {
		{
			p.SetState(294)
			p.Match(FilterExpressionWS)
		}

		p.SetState(299)
		p.GetErrorHandler().Sync(p)
		_la = p.GetTokenStream().LA(1)
	}

	return localctx
}

func (p *FilterExpression) Sempred(localctx antlr.RuleContext, ruleIndex, predIndex int) bool {
	switch ruleIndex {
	case 8:
		var t *ValueContext = nil
		if localctx != nil {
			t = localctx.(*ValueContext)
		}
		return p.Value_Sempred(t, predIndex)

	default:
		panic("No predicate with index: " + fmt.Sprint(ruleIndex))
	}
}

func (p *FilterExpression) Value_Sempred(localctx antlr.RuleContext, predIndex int) bool {
	switch predIndex {
	case 0:
		return p.Precpred(p.GetParserRuleContext(), 2)

	case 1:
		return p.Precpred(p.GetParserRuleContext(), 1)

	default:
		panic("No predicate with index: " + fmt.Sprint(predIndex))
	}
}
