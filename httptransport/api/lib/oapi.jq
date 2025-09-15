# vim: set expandtab ts=2 sw=2:
module {
  name: "openapi",
};

# Some helper functions:

def ref($ref): # Construct a JSON Schema reference object.
  { "$ref": "\($ref)" }
;

def lref($kind; $id): # Construct a ref object to an OpenAPI component.
  ref("#/components/\($kind)/\($id)")
;

def param_ref($id): # Construct a ref object to an OpenAPI parameter component.
  lref("parameters"; $id)
;

def response_ref($id): # Construct a ref object to an OpenAPI response component.
  lref("responses"; $id)
;

def header_ref($id): # Construct a ref object to an OpenAPI header component.
  lref("headers"; $id)
;

def schema_ref($id): # Construct a ref object to an OpenAPI schema component.
  lref("schemas"; $id)
;

def mediatype($t; $v): # Return the local vendor mediatype for $t, version $v.
  "application/vnd.clair.\($t).\($v)+json"
;

def mediatype($t): # As mediatype/2, but with the default of "v1".
  mediatype($t; "v1")
;

def contenttype($t; $v): # Construct an OpenAPI content type object for $t, version $v.
  { (mediatype($t; $v)): { "schema": schema_ref($t) } }
;

def contenttype($t): # As contenttype/2, but with the default version.
  { (mediatype($t)): { "schema": schema_ref($t) } }
;

def cli_hints: # Add some hints that CLI tools can pick up on to ignore our internal paths.
  (.paths[][] | select(objects and (.tags|contains(["internal"]))) ) |= . + {"x-cli-ignore": true}
;

def sort_paths: # Sort the paths object.
  .paths |= (. | to_entries | sort_by(.key) | from_entries)
;

def content_defaults: # All responses that don't have a "default" type, pick the first one.
  "application/json" as $t |
  [["example"], ["examples"]] as $rm |
  ( .paths[][] | select(objects) | .responses[].content | select(objects and (has($t)|not)) ) |= (. + { $t: (to_entries[0].value | delpaths($rm)) })
  |
  ( .paths[][] | select(objects) | .requestBody.content | select(objects and (has($t)|not)) ) |= (. + { $t: (to_entries[0].value | delpaths($rm)) })
  |
  ( .components.responses[].content | select(has($t)|not) ) |= (. + { $t: (to_entries[0].value | delpaths($rm)) })
;
