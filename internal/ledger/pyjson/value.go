// Package pyjson holds JSON documents as the reference (Python) implementation sees them, so that the Go ledger
// reads and writes the same bytes: objects keep their key order (Python dicts do), integers and floats stay
// distinct (14 and 14.0 are different documents), and output follows json.dumps (indent, sort_keys,
// ensure_ascii, float repr). It also provides the few Python semantics the ledger rules depend on: truthiness,
// str/repr, membership and arithmetic on mixed int/float numbers.
//
// A Value is one of: nil, bool, string, int64, float64, BigInt (an integer outside int64), []Value, *Object.
package pyjson

import "sort"

// Value is a JSON value; see the package documentation for the concrete types.
type Value = any

// BigInt is an integer literal that does not fit in int64, kept as its decimal text.
type BigInt string

// Object is a JSON object with insertion order (a Python dict). The zero value is not usable; use NewObject.
type Object struct {
	keys []string
	vals map[string]Value
}

// NewObject returns an empty object.
func NewObject() *Object {
	return &Object{vals: map[string]Value{}}
}

// Len is the number of keys.
func (o *Object) Len() int {
	return len(o.keys)
}

// Keys returns the keys in insertion order (a copy).
func (o *Object) Keys() []string {
	return append([]string(nil), o.keys...)
}

// SortedKeys returns the keys in code point order (Python sorted()).
func (o *Object) SortedKeys() []string {
	k := o.Keys()
	sort.Strings(k)
	return k
}

// Get returns the value of key and whether it is present.
func (o *Object) Get(key string) (Value, bool) {
	v, ok := o.vals[key]
	return v, ok
}

// Has reports whether key is present.
func (o *Object) Has(key string) bool {
	_, ok := o.vals[key]
	return ok
}

// Set sets key; a new key goes last, an existing one keeps its position (as in a Python dict).
func (o *Object) Set(key string, v Value) {
	if _, ok := o.vals[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.vals[key] = v
}

// Delete removes key if present.
func (o *Object) Delete(key string) {
	if _, ok := o.vals[key]; !ok {
		return
	}
	delete(o.vals, key)
	for i, k := range o.keys {
		if k == key {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			return
		}
	}
}

// Str returns the value of key when it is a string, else "".
func (o *Object) Str(key string) string {
	s, _ := o.vals[key].(string) // a missing or non-string field reads as ""
	return s
}

// Obj returns the value of key when it is an object, else nil.
func (o *Object) Obj(key string) *Object {
	v, _ := o.vals[key].(*Object) // a missing or non-object field reads as nil
	return v
}

// List returns the value of key when it is an array, else nil.
func (o *Object) List(key string) []Value {
	v, _ := o.vals[key].([]Value) // a missing or non-array field reads as nil
	return v
}

// GetOrCreateObj returns the object at key, creating (or replacing a non-object) with an empty one: Python's
// d.setdefault(key, {}).
func (o *Object) GetOrCreateObj(key string) *Object {
	if v := o.Obj(key); v != nil {
		return v
	}
	v := NewObject()
	o.Set(key, v)
	return v
}

// Truthy reports whether key is present with a true value (Python truthiness of d.get(key)).
func (o *Object) Truthy(key string) bool {
	return Truthy(o.vals[key])
}

// ObjectOf builds an object from alternating key, value pairs (keys must be strings).
func ObjectOf(kv ...Value) *Object {
	o := NewObject()
	for i := 0; i+1 < len(kv); i += 2 {
		k, _ := kv[i].(string) // callers pass literal string keys
		o.Set(k, kv[i+1])
	}
	return o
}
