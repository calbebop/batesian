package mcp

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"strconv"
	"strings"
)

const maxSafeHeaderInteger = 1<<53 - 1

type toolHeaderBinding struct {
	path []string
	name string
	kind string
}

func toolParamHeaders(schema, args map[string]interface{}) (map[string]string, error) {
	var bindings []toolHeaderBinding
	if err := collectToolHeaderBindings(schema, nil, true, map[string]bool{}, &bindings); err != nil {
		return nil, err
	}
	headers := make(map[string]string, len(bindings))
	for _, binding := range bindings {
		value, present := toolArgumentAt(args, binding.path)
		if !present || value == nil {
			continue
		}
		plain, err := toolHeaderString(binding.kind, value)
		if err != nil {
			return nil, fmt.Errorf("Mcp-Param-%s: %w", binding.name, err)
		}
		headers["Mcp-Param-"+binding.name] = encodeMCPHeaderValue(plain)
	}
	return headers, nil
}

func collectToolHeaderBindings(node interface{}, path []string, reachable bool, seen map[string]bool, out *[]toolHeaderBinding) error {
	switch schema := node.(type) {
	case map[string]interface{}:
		if raw, exists := schema["x-mcp-header"]; exists {
			name, ok := raw.(string)
			kind, kindOK := schema["type"].(string)
			if !reachable || len(path) == 0 || !ok || !validMCPHeaderToken(name) ||
				!kindOK || (kind != "string" && kind != "integer" && kind != "boolean") {
				return fmt.Errorf("invalid x-mcp-header annotation at %q", strings.Join(path, "."))
			}
			lower := strings.ToLower(name)
			if seen[lower] {
				return fmt.Errorf("duplicate x-mcp-header %q", name)
			}
			seen[lower] = true
			*out = append(*out, toolHeaderBinding{path: path, name: name, kind: kind})
		}
		for key, child := range schema {
			if key == "x-mcp-header" {
				continue
			}
			switch key {
			case "default", "const", "enum", "examples", "example":
				continue
			}
			if key == "properties" && reachable {
				if props, ok := child.(map[string]interface{}); ok {
					for name, prop := range props {
						childPath := append(append([]string(nil), path...), name)
						if err := collectToolHeaderBindings(prop, childPath, true, seen, out); err != nil {
							return err
						}
					}
				}
				continue
			}
			if err := collectToolHeaderBindings(child, nil, false, seen, out); err != nil {
				return err
			}
		}
	case []interface{}:
		for _, child := range schema {
			if err := collectToolHeaderBindings(child, nil, false, seen, out); err != nil {
				return err
			}
		}
	}
	return nil
}

func validMCPHeaderToken(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		b := value[i]
		if (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') ||
			strings.ContainsRune("!#$%&'*+-.^_`|~", rune(b)) {
			continue
		}
		return false
	}
	return true
}

func toolArgumentAt(args map[string]interface{}, path []string) (interface{}, bool) {
	var node interface{} = args
	for _, part := range path {
		object, ok := node.(map[string]interface{})
		if !ok {
			return nil, false
		}
		value, exists := object[part]
		if !exists {
			return nil, false
		}
		node = value
	}
	return node, true
}

func toolHeaderString(kind string, value interface{}) (string, error) {
	switch kind {
	case "string":
		if s, ok := value.(string); ok {
			return s, nil
		}
	case "boolean":
		if b, ok := value.(bool); ok {
			return strconv.FormatBool(b), nil
		}
	case "integer":
		if number, ok := value.(json.Number); ok {
			rat, parsed := new(big.Rat).SetString(string(number))
			limit := big.NewInt(maxSafeHeaderInteger)
			if parsed && rat.IsInt() && rat.Num().Cmp(limit) <= 0 && rat.Num().Cmp(new(big.Int).Neg(limit)) >= 0 {
				return rat.Num().String(), nil
			}
			return "", fmt.Errorf("integer header value is outside the safe range")
		}
		v := reflect.ValueOf(value)
		switch v.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			n := v.Int()
			if n >= -maxSafeHeaderInteger && n <= maxSafeHeaderInteger {
				return strconv.FormatInt(n, 10), nil
			}
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			n := v.Uint()
			if n <= maxSafeHeaderInteger {
				return strconv.FormatUint(n, 10), nil
			}
		case reflect.Float32, reflect.Float64:
			return safeIntegerHeader(v.Float())
		}
	}
	return "", fmt.Errorf("value %T does not match %s header type", value, kind)
}

func safeIntegerHeader(value float64) (string, error) {
	if math.IsNaN(value) || math.IsInf(value, 0) || math.Trunc(value) != value ||
		value < -maxSafeHeaderInteger || value > maxSafeHeaderInteger {
		return "", fmt.Errorf("integer header value is outside the safe range")
	}
	return strconv.FormatFloat(value, 'f', 0, 64), nil
}
