// A module outside devproof, used to prove the public resolver contract can
// be implemented from outside it. Under testdata, so the parent module
// ignores it entirely.
module example.com/external-resolver

go 1.27.1

require github.com/thingzio/devproof v0.0.0

require gopkg.in/yaml.v3 v3.0.1 // indirect

replace github.com/thingzio/devproof => ../../../..
