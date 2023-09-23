# Journey Planner #

Journey Planner can calculate the fastest route between two systems in Eve Online using data from Tripwire (wormhole connections) and Eve Scout (Thera connections).

### Compiling

```
GOOS=js GOARCH=wasm go build -o journey.wasm
```

### Deploying

Place the following files in the root web directory of Tripwire:

* journey.htm
* journey.wasm
* wasm_exec.js
